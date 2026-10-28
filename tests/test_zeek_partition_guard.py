"""Synthetic-only regressions: no genuine VMware or attack evidence."""
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

from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.model_artifact import build_zeek_research_artifact
from blue_team_ai.partition_guard import verify_declared_partition_exclusion
from evaluate_zeek_lab import load_experiment_manifest
from test_zeek_lab_cli import _lab_files
from test_zeek_new_log_inference import _log
from test_zeek_offline_baseline import _dataset


def _inputs(tmp_path):
    private = tmp_path / "private"
    manifest = _lab_files(private)
    captures, digest = load_experiment_manifest(manifest, lab_cidrs=["192.168.56.0/24"])
    dataset = build_labeled_lab_dataset(captures)
    model = build_zeek_research_artifact(_dataset(), input_manifest_sha256=digest)
    for split in ("train", "validation"):
        model[f"{split}_source_sha256"] = sorted({
            row["source_sha256"] for row in dataset.provenance[split]
        })
    new = private / "new-conn.log"
    new.write_bytes(_log())
    return manifest, dataset, model, new


def _check(manifest, dataset, model, new):
    return verify_declared_partition_exclusion(
        model, dataset,
        manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        new_capture_sha256=hashlib.sha256(new.read_bytes()).hexdigest(),
    )


def test_exact_partition_nonreuse_and_limitations(tmp_path):
    manifest, dataset, model, new = _inputs(tmp_path)
    result = _check(manifest, dataset, model, new)
    assert result["new_capture_not_in_declared_train_validation_test"] is True
    assert result["declared_capture_counts"] == {"train": 1, "validation": 1, "test": 1}
    for key in (
        "independent_partition_history_verified", "semantic_flow_nonreuse_verified",
        "host_only_isolation_verified", "label_truth_verified",
        "operational_attack_detection_verified",
    ):
        assert result[key] is False
    output = json.dumps(result)
    assert "192.168.56" not in output and "private-operator-note" not in output
    assert "N0" not in output and "A0" not in output


def test_rejects_reserved_test_reuse_and_model_mismatch(tmp_path):
    manifest, dataset, model, new = _inputs(tmp_path)
    new.write_bytes((manifest.parent / "host-2.log").read_bytes())
    with pytest.raises(ValueError, match="exact-byte reuse"):
        _check(manifest, dataset, model, new)
    new.write_bytes(_log())
    changed = copy.deepcopy(model)
    changed["input_manifest_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="different experiment manifest"):
        _check(manifest, dataset, changed, new)
    changed = copy.deepcopy(model)
    changed["train_source_sha256"] = ["f" * 64]
    with pytest.raises(ValueError, match="TRAIN sources"):
        _check(manifest, dataset, changed, new)
    changed = copy.deepcopy(model)
    changed["validation_source_sha256"] = ["f" * 64]
    with pytest.raises(ValueError, match="VALIDATION sources"):
        _check(manifest, dataset, changed, new)


def test_rejects_bad_hash_and_wrong_dataset_type(tmp_path):
    manifest, dataset, model, new = _inputs(tmp_path)
    with pytest.raises(ValueError, match="lowercase"):
        verify_declared_partition_exclusion(model, dataset, manifest_sha256="A" * 64,
                                            new_capture_sha256="b" * 64)
    with pytest.raises(ValueError, match="labeled dataset"):
        verify_declared_partition_exclusion(model, object(),
                                            manifest_sha256=model["input_manifest_sha256"],
                                            new_capture_sha256="b" * 64)


def test_cli_pinned_sources_scope_and_no_file_writes(tmp_path):
    manifest, dataset, model, new = _inputs(tmp_path)
    model_path = manifest.parent / "zeek-model.json"
    model_path.write_text(json.dumps(model), encoding="utf-8")
    base = [
        sys.executable, str(ROOT / "scripts" / "check_zeek_partition_exclusion.py"),
        "--model", str(model_path),
        "--expected-model-sha256", hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "--manifest", str(manifest),
        "--expected-manifest-sha256", hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "--log", str(new),
        "--expected-log-sha256", hashlib.sha256(new.read_bytes()).hexdigest(),
        "--cidr", "192.168.56.0/24",
    ]
    before = {p.name: p.read_bytes() for p in manifest.parent.iterdir() if p.is_file()}
    ok = subprocess.run(base, capture_output=True, text=True, check=False)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["new_capture_not_in_declared_train_validation_test"] is True
    for flag, bad in (
        ("--expected-model-sha256", "0" * 64),
        ("--expected-manifest-sha256", "0" * 64),
        ("--expected-log-sha256", "0" * 64),
        ("--cidr", "10.42.0.0/16"),
    ):
        cmd = base.copy()
        cmd[cmd.index(flag) + 1] = bad
        refused = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert refused.returncode == 1
        assert str(manifest) not in refused.stderr
        assert "192.168.56" not in refused.stderr
    assert before == {p.name: p.read_bytes() for p in manifest.parent.iterdir() if p.is_file()}


def test_cli_rejects_test_reuse_even_with_matching_new_log_pin(tmp_path):
    manifest, _, model, new = _inputs(tmp_path)
    new.write_bytes((manifest.parent / "host-2.log").read_bytes())
    model_path = manifest.parent / "model.json"
    model_path.write_text(json.dumps(model), encoding="utf-8")
    cmd = [
        sys.executable, str(ROOT / "scripts" / "check_zeek_partition_exclusion.py"),
        "--model", str(model_path),
        "--expected-model-sha256", hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "--manifest", str(manifest),
        "--expected-manifest-sha256", hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "--log", str(new),
        "--expected-log-sha256", hashlib.sha256(new.read_bytes()).hexdigest(),
        "--cidr", "192.168.56.0/24",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "new_capture_not_in_declared" not in result.stdout
