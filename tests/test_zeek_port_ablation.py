"""Synthetic-only port ablation tests: NOT measured VMware attack detection."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.offline_baseline import evaluate_offline_zeek_baseline
from blue_team_ai.port_ablation import evaluate_zeek_port_ablation, _portless_pipeline
from test_zeek_offline_baseline import _dataset
from test_zeek_lab_cli import _lab_files


def test_portless_excludes_both_ports_and_full_matches_existing_baseline():
    dataset = _dataset()
    original = copy.deepcopy(dataset)
    report = evaluate_zeek_port_ablation(dataset)
    assert dataset == original
    assert report["mode"] == "offline_zeek_port_feature_ablation_research_only"
    assert report["variants"]["full"]["test_metrics"] == evaluate_offline_zeek_baseline(dataset)["test_metrics"]
    assert report["variants"]["full"]["selected_validation_threshold"] == evaluate_offline_zeek_baseline(dataset)["selected_threshold"]
    assert report["excluded_port_features"] == ["dst_port", "src_port"]
    assert len(report["variants"]["full"]["used_feature_columns"]) == 9
    assert len(report["variants"]["without_ports"]["used_feature_columns"]) == 7
    assert not {"src_port", "dst_port"} & set(report["variants"]["without_ports"]["used_feature_columns"])
    assert report["test_metrics_used_for_model_selection"] is False
    assert report["causal_feature_effect_established"] is False
    assert report["automated_alerts"] is False
    assert report["live_capture"] is False
    assert report["independent_ground_truth_verified"] is False
    assert sum(report["variants"]["without_ports"]["test_metrics"][key] for key in ("tp", "fp", "tn", "fn")) == 2
    assert "192.168.56." not in json.dumps(report)
    assert "operator-note" not in json.dumps(report)
    assert "N0" not in json.dumps(report)


def test_portless_is_invariant_to_port_values_across_all_splits():
    dataset = _dataset()
    baseline = evaluate_zeek_port_ablation(dataset)["variants"]["without_ports"]
    changed = copy.deepcopy(dataset)
    for split in ("train", "validation", "test"):
        for row in changed.features[split]:
            row["src_port"] = 65535
            row["dst_port"] = 1
    assert evaluate_zeek_port_ablation(changed)["variants"]["without_ports"] == baseline
    # Inspect the actual fitted transformer's column list, not merely report metadata.
    transformer = _portless_pipeline().named_steps["preprocessing"]
    used = [column for _, _, columns in transformer.transformers for column in columns]
    assert "src_port" not in used and "dst_port" not in used


def test_heldout_test_labels_cannot_change_validation_thresholds():
    dataset = _dataset()
    reference = evaluate_zeek_port_ablation(dataset)
    altered = copy.deepcopy(dataset)
    altered.labels["test"] = [1, 0]
    changed = evaluate_zeek_port_ablation(altered)
    for variant in ("full", "without_ports"):
        assert reference["variants"][variant]["selected_validation_threshold"] == changed["variants"][variant]["selected_validation_threshold"]
        assert reference["variants"][variant]["validation_metrics"] == changed["variants"][variant]["validation_metrics"]
    assert reference["variants"]["full"]["test_metrics"] != changed["variants"]["full"]["test_metrics"]


@pytest.mark.parametrize("mutation", [
    lambda d: d.features["train"][0].update(label=1),
    lambda d: d.labels["train"].__setitem__(0, True),
    lambda d: d.provenance["test"][0].update(host_group="host-train"),
])
def test_ablation_refuses_invalid_research_inputs(mutation):
    dataset = _dataset()
    mutation(dataset)
    with pytest.raises(ValueError):
        evaluate_zeek_port_ablation(dataset)


def _pinned_manifest(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    # The generic CLI fixture deliberately repeats identical flow tuples
    # across splits; strict ablation input gates must reject those. Give each
    # synthetic session distinct source ports and repin BOTH log and labels.
    for index, entry in enumerate(spec["captures"]):
        log = manifest.parent / entry["log_path"]
        raw = log.read_bytes().replace(
            b"\t52344\t", f"\t{52344 + 10 * index}\t".encode(),
        ).replace(
            b"\t52345\t", f"\t{52345 + 10 * index}\t".encode(),
        )
        log.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        entry["source_sha256"] = digest
        labels = manifest.parent / entry["labels_path"]
        annotation = json.loads(labels.read_text(encoding="utf-8"))
        annotation["source_sha256"] = digest
        labels.write_text(json.dumps(annotation), encoding="utf-8")
        entry["labels_sha256"] = hashlib.sha256(labels.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    return manifest


def test_cli_private_strict_pinned_ablation_and_refusals(tmp_path):
    manifest = _pinned_manifest(tmp_path)
    pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
    output = manifest.parent / "port-ablation.json"
    base = [
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--cidr", "192.168.56.0/24",
        "--strict-input-gates", "--expected-manifest-sha256", pin,
        "--port-ablation-output", str(output),
    ]
    accepted = subprocess.run(base, capture_output=True, text=True)
    assert accepted.returncode == 0, accepted.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["input_manifest_sha256"] == pin
    assert report["manifest_sha256_pin_verified"] is True
    assert report["all_annotation_sha256_pins_required"] is True
    assert report["mode"] == "offline_zeek_port_feature_ablation_research_only"
    assert "192.168.56." not in json.dumps(report)
    original = output.read_bytes()
    assert subprocess.run(base, capture_output=True).returncode == 1
    assert output.read_bytes() == original

    for removed in ("--strict-input-gates", "--expected-manifest-sha256", "--cidr"):
        rejected_output = manifest.parent / ("rejected-" + removed[2:] + ".json")
        command = base.copy()
        if removed == "--strict-input-gates":
            command.remove(removed)
        else:
            at = command.index(removed)
            del command[at:at + 2]
        command[command.index("--port-ablation-output") + 1] = str(rejected_output)
        rejected = subprocess.run(command, capture_output=True, text=True)
        assert rejected.returncode == 1
        assert not rejected_output.exists()
        assert str(manifest) not in rejected.stderr.decode("utf-8", errors="replace")
    bad_output = manifest.parent / "rejected-bad-pin.json"
    altered = base.copy()
    altered[altered.index("--expected-manifest-sha256") + 1] = "0" * 64
    altered[altered.index("--port-ablation-output") + 1] = str(bad_output)
    assert subprocess.run(altered, capture_output=True).returncode == 1
    assert not bad_output.exists()
