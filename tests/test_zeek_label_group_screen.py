"""Synthetic-only label/host confounding preflight regression; no VMware."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.features import LAB_FEATURE_COLUMNS
from blue_team_ai.labeled_dataset import LabeledLabDataset
from blue_team_ai.label_group_screen import summarize_train_validation_label_group_confounding
from evaluate_zeek_lab import main


def _dataset():
    def provenance(host, session):
        return {"host_group": host, "session_id": session}
    return LabeledLabDataset(
        feature_schema_version=1, feature_columns=LAB_FEATURE_COLUMNS,
        features={"train": [{"untrusted": object()}],
                  "validation": [{"untrusted": object()}],
                  "test": [{"secret": object()}]},
        labels={"train": [0, 0, 1, 1], "validation": [0, 1, 0, 1],
                "test": ["untrusted"]},
        provenance={
            "train": [provenance("host-A", "s-A")] * 2
                     + [provenance("host-B", "s-B")] * 2,
            "validation": [provenance("host-C", "s-C")] * 2
                          + [provenance("host-D", "s-D")] * 2,
            "test": None,
        },
    )


def test_detects_perfect_host_label_separation_without_private_values():
    report = summarize_train_validation_label_group_confounding(_dataset())
    train = report["partitions"]["train"]
    validation = report["partitions"]["validation"]
    assert train["host_groups_with_both_classes"] == 0
    assert train["host_groups_normal_only"] == 1
    assert train["host_groups_attack_only"] == 1
    assert train["labels_fully_separated_by_host_group"] is True
    assert validation["host_groups_with_both_classes"] == 2
    assert validation["labels_fully_separated_by_host_group"] is False
    assert "train:labels_fully_separated_by_host_group" in report["warnings"]
    assert "validation:labels_fully_separated_by_host_group" not in report["warnings"]
    assert report["test_labels_used_in_diagnostic"] is False
    assert report["test_features_used_in_diagnostic"] is False
    assert report["feature_values_used"] is False
    assert report["model_fitted"] is False
    serialized = json.dumps(report, allow_nan=False)
    for private in ("host-A", "host-B", "s-A", "s-C", "secret", "untrusted"):
        assert private not in serialized


def test_test_and_feature_mutation_cannot_change_diagnostic():
    dataset = _dataset()
    baseline = summarize_train_validation_label_group_confounding(dataset)
    dataset.features["train"] = None
    dataset.features["validation"] = None
    dataset.features["test"] = None
    dataset.labels["test"] = None
    dataset.provenance["test"] = None
    assert summarize_train_validation_label_group_confounding(dataset) == baseline


@pytest.mark.parametrize("mutation", [
    lambda d: d.labels["train"].__setitem__(0, True),
    lambda d: d.labels["train"].pop(),
    lambda d: d.provenance["validation"][0].update(host_group="host-A"),
    lambda d: d.provenance["validation"][0].update(session_id="s-A"),
    lambda d: d.provenance["train"][0].update(host_group=" "),
])
def test_invalid_or_cross_split_group_contract_fails_closed(mutation):
    dataset = _dataset()
    mutation(dataset)
    with pytest.raises(ValueError):
        summarize_train_validation_label_group_confounding(dataset)


def _manifest(folder: Path) -> Path:
    folder.mkdir()
    captures = []
    for i, split in enumerate(("train", "validation", "test")):
        raw = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            f"{100 + i * 10}.0\tN{i}\t192.168.56.10\t1234\t192.168.56.20\t80\ttcp\n"
            f"{101 + i * 10}.0\tA{i}\t192.168.56.11\t1235\t192.168.56.21\t53\tudp\n"
        ).encode("utf-8")
        (folder / f"{i}.log").write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        (folder / f"{i}.json").write_text(json.dumps({
            "source_sha256": digest, "labels_by_uid": {f"N{i}": 0, f"A{i}": 1},
        }), encoding="utf-8")
        captures.append({
            "log_path": f"{i}.log", "labels_path": f"{i}.json",
            "source_sha256": digest, "session_id": f"session-{i}",
            "host_group": f"host-{i}", "split": split,
            "label_method": "manual_analyst_review",
            "label_reference": f"private-evidence-{i}",
        })
    path = folder / "manifest.json"
    path.write_text(json.dumps({"manifest_version": 1, "captures": captures}), encoding="utf-8")
    return path


def test_cli_opt_in_read_only_and_preflight_only(tmp_path, capsys):
    manifest = _manifest(tmp_path / "private")
    before = {p.name: p.read_bytes() for p in manifest.parent.iterdir()}
    assert main(["--manifest", str(manifest), "--preflight", "--label-group-screen"]) == 0
    report = json.loads(capsys.readouterr().out)
    screen = report["label_group_diagnostics"]
    assert screen["partitions"]["train"]["host_groups_with_both_classes"] == 1
    assert screen["test_labels_used_in_diagnostic"] is False
    assert "private-evidence" not in json.dumps(report)
    assert "192.168.56" not in json.dumps(report)
    assert main(["--manifest", str(manifest), "--preflight"]) == 0
    assert "label_group_diagnostics" not in json.loads(capsys.readouterr().out)
    output = manifest.parent / "must-not-write.json"
    assert main(["--manifest", str(manifest), "--output", str(output),
                 "--label-group-screen"]) == 1
    assert capsys.readouterr().out == ""
    assert not output.exists()
    assert {p.name: p.read_bytes() for p in manifest.parent.iterdir()} == before


def test_session_separation_detected_even_when_host_has_both_labels():
    dataset = _dataset()
    dataset.provenance["train"] = [
        {"host_group": "host-A", "session_id": "normal-session"},
        {"host_group": "host-A", "session_id": "normal-session"},
        {"host_group": "host-A", "session_id": "attack-session"},
        {"host_group": "host-A", "session_id": "attack-session"},
    ]
    report = summarize_train_validation_label_group_confounding(dataset)
    train = report["partitions"]["train"]
    assert train["host_groups_with_both_classes"] == 1
    assert train["labels_fully_separated_by_host_group"] is False
    assert train["labels_fully_separated_by_session"] is True
    assert train["normal_session_coverage"] == 1
    assert train["attack_session_coverage"] == 1
    assert train["host_groups_with_multiple_sessions"] == 1
    assert "train:labels_fully_separated_by_session" in report["warnings"]
    assert "train:attack_labels_in_one_session" in report["warnings"]
    assert "train:normal_labels_in_one_session" in report["warnings"]
    assert "train:labels_fully_separated_by_host_group" not in report["warnings"]
    assert "train:host_and_session_one_to_one" not in report["warnings"]
    assert "normal-session" not in json.dumps(report)
    assert "attack-session" not in json.dumps(report)


def test_one_to_one_host_session_nesting_warning_is_not_detection_claim():
    report = summarize_train_validation_label_group_confounding(_dataset())
    assert "train:host_and_session_one_to_one" in report["warnings"]
    assert "validation:host_and_session_one_to_one" in report["warnings"]
    assert report["partitions"]["train"]["host_groups_with_multiple_sessions"] == 0
    assert report["partitions"]["validation"]["labels_fully_separated_by_session"] is False
    assert "validation:labels_fully_separated_by_session" not in report["warnings"]
    assert report["label_truth_verified"] is False
    assert report["host_only_isolation_verified"] is False


def test_single_mixed_session_is_distinct_from_perfect_session_separation():
    dataset = _dataset()
    dataset.provenance["train"] = [
        {"host_group": "host-A", "session_id": "single-session"}
        for _ in dataset.labels["train"]
    ]
    report = summarize_train_validation_label_group_confounding(dataset)
    train = report["partitions"]["train"]
    assert train["sessions"] == 1
    assert train["sessions_with_both_classes"] == 1
    assert train["labels_fully_separated_by_session"] is False
    assert "train:only_one_declared_session" in report["warnings"]
    assert "train:labels_fully_separated_by_session" not in report["warnings"]
    assert "train:host_and_session_one_to_one" not in report["warnings"]
