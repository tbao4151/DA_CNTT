"""Synthetic-only TRAIN/VALIDATION Zeek shift diagnostics; no VMware or attack."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.feature_shift import summarize_train_validation_feature_shift
from blue_team_ai.features import LAB_FEATURE_COLUMNS
from blue_team_ai.labeled_dataset import LabeledLabDataset
from evaluate_zeek_lab import main


def _row(*, proto="tcp", service=None, duration=1.0, orig_bytes=10):
    return {
        "proto": proto, "service": service, "src_port": 1234, "dst_port": 80,
        "duration_s": duration, "orig_bytes": orig_bytes, "resp_bytes": 2,
        "orig_pkts": 1, "resp_pkts": 1,
    }


def _dataset():
    return LabeledLabDataset(
        feature_schema_version=1, feature_columns=LAB_FEATURE_COLUMNS,
        features={
            "train": [_row(service="http"), _row(proto="udp", duration=2.0)],
            "validation": [
                _row(proto="icmp", service="dns", duration=20.0, orig_bytes=None),
                _row(proto="tcp", service=None, duration=1.5),
            ],
            "test": [{"secret": object()}],  # Must never be inspected.
        },
        labels={"train": [0, 1], "validation": [0, 1], "test": [0, 1]},
        provenance={"train": [], "validation": [], "test": []},
    )


def test_train_reference_reports_shift_without_private_values_or_test_inspection():
    report = summarize_train_validation_feature_shift(_dataset())
    assert report["mode"] == "offline_zeek_train_validation_feature_shift_only"
    assert report["test_features_used_in_shift"] is False
    assert report["test_labels_used_in_shift"] is False
    assert report["model_fitted"] is False
    assert report["partitions"]["train"]["flows"] == 2
    assert report["partitions"]["validation"]["flows"] == 2
    assert report["partitions"]["validation"]["missing_counts"]["orig_bytes"] == 1
    assert report["partitions"]["validation"]["unseen_train_category_counts"] == {
        "proto": 1, "service": 1,
    }
    assert report["partitions"]["validation"]["outside_train_numeric_range_counts"]["duration_s"] == 1
    assert "validation_contains_unseen_train_categories" in report["warnings"]
    assert "validation_contains_values_outside_train_numeric_ranges" in report["warnings"]
    serialized = json.dumps(report, allow_nan=False)
    for forbidden in ("http", "dns", "icmp", "secret", "1234", "192.168."):
        assert forbidden not in serialized


def test_test_mutation_cannot_change_shift_diagnostic():
    dataset = _dataset()
    baseline = summarize_train_validation_feature_shift(dataset)
    dataset.features["test"] = None
    dataset.labels["test"] = ["untrusted"]
    assert summarize_train_validation_feature_shift(dataset) == baseline


@pytest.mark.parametrize("mutation", [
    lambda d: d.features["train"].clear(),
    lambda d: d.features["validation"][0].update(label=1),
    lambda d: object.__setattr__(d, "feature_schema_version", 999),
])
def test_invalid_train_or_validation_contract_is_rejected(mutation):
    dataset = _dataset()
    mutation(dataset)
    with pytest.raises(ValueError):
        summarize_train_validation_feature_shift(dataset)


def _manifest(root: Path) -> Path:
    root.mkdir()
    captures = []
    for i, split in enumerate(("train", "validation", "test")):
        raw = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            f"100.0\tN{i}\t192.168.56.10\t1234\t192.168.56.20\t80\ttcp\n"
            f"101.0\tA{i}\t192.168.56.11\t1235\t192.168.56.21\t53\tudp\n"
        ).encode()
        (root / f"{i}.log").write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        (root / f"{i}.json").write_text(json.dumps({
            "source_sha256": digest, "labels_by_uid": {f"N{i}": 0, f"A{i}": 1},
        }), encoding="utf-8")
        captures.append({
            "log_path": f"{i}.log", "labels_path": f"{i}.json",
            "source_sha256": digest, "session_id": f"session-{i}",
            "host_group": f"host-{i}", "split": split,
            "label_method": "manual_analyst_review",
            "label_reference": f"private-{i}",
        })
    path = root / "manifest.json"
    path.write_text(json.dumps({"manifest_version": 1, "captures": captures}), encoding="utf-8")
    return path


def test_cli_feature_shift_is_opt_in_preflight_only(tmp_path, capsys):
    manifest = _manifest(tmp_path / "private")
    assert main(["--manifest", str(manifest), "--preflight", "--feature-shift"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["model_fitted"] is False
    assert result["test_scored"] is False
    assert result["feature_shift_diagnostics"]["test_features_used_in_shift"] is False
    assert result["feature_shift_diagnostics"]["partitions"]["validation"]["flows"] == 2
    assert "192.168.56." not in json.dumps(result)
    assert "private-0" not in json.dumps(result)
    assert main(["--manifest", str(manifest), "--preflight"]) == 0
    assert "feature_shift_diagnostics" not in json.loads(capsys.readouterr().out)
    output = manifest.parent / "should-not-exist.json"
    assert main([
        "--manifest", str(manifest), "--output", str(output), "--feature-shift",
    ]) == 1
    assert not output.exists()
    assert capsys.readouterr().out == ""
