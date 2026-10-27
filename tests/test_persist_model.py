"""Regression tests for safe local model/metrics artifact persistence.

Uses tiny trusted synthetic objects, not official UNSW training or SOC data.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import joblib
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.model import persist_model


def test_persist_model_writes_both_artifacts_and_cleans_stage(tmp_path):
    persist_model({"synthetic": True}, {"train_size": 3}, tmp_path)
    assert joblib.load(tmp_path / "unsw_binary_rf.joblib") == {"synthetic": True}
    manifest = json.loads((tmp_path / "artifact_manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["sha256"] == {
        name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        for name in ("unsw_binary_rf.joblib", "metrics.json")
    }
    assert json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8")) == {"train_size": 3}
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "artifact_manifest.json", "metrics.json", "unsw_binary_rf.joblib",
    ]


def test_persist_model_does_not_overwrite_previous_pair_when_dump_fails(tmp_path, monkeypatch):
    model_file = tmp_path / "unsw_binary_rf.joblib"
    metrics_file = tmp_path / "metrics.json"
    model_file.write_bytes(b"prior model")
    metrics_file.write_bytes(b"prior metrics")

    def interrupted_dump(model, filename, **kwargs):
        Path(filename).write_bytes(b"incomplete staging data")
        raise OSError("simulated disk error")

    monkeypatch.setattr("siem_ai.model.joblib.dump", interrupted_dump)
    with pytest.raises(OSError, match="simulated disk error"):
        persist_model({"new": True}, {"new": True}, tmp_path)

    assert model_file.read_bytes() == b"prior model"
    assert metrics_file.read_bytes() == b"prior metrics"
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "metrics.json", "unsw_binary_rf.joblib",
    ]


def test_persist_model_does_not_overwrite_previous_pair_when_metrics_invalid(tmp_path):
    model_file = tmp_path / "unsw_binary_rf.joblib"
    metrics_file = tmp_path / "metrics.json"
    model_file.write_bytes(b"prior model")
    metrics_file.write_bytes(b"prior metrics")

    with pytest.raises(TypeError, match="JSON serializable"):
        persist_model({"new": True}, {"not_json": object()}, tmp_path)

    assert model_file.read_bytes() == b"prior model"
    assert metrics_file.read_bytes() == b"prior metrics"
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "metrics.json", "unsw_binary_rf.joblib",
    ]


def test_interrupted_second_replace_keeps_old_manifest(tmp_path, monkeypatch):
    persist_model({"generation": 1}, {"generation": 1}, tmp_path)
    manifest_path = tmp_path / "artifact_manifest.json"
    previous_manifest = manifest_path.read_bytes()
    real_replace = os.replace
    count = 0

    def fail_second_replace(source, target):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("simulated metrics replacement failure")
        return real_replace(source, target)

    monkeypatch.setattr("siem_ai.model.os.replace", fail_second_replace)
    with pytest.raises(OSError, match="simulated metrics replacement failure"):
        persist_model({"generation": 2}, {"generation": 2}, tmp_path)

    # The first file may have changed, but a stale manifest cannot certify it.
    assert manifest_path.read_bytes() == previous_manifest
    assert hashlib.sha256((tmp_path / "unsw_binary_rf.joblib").read_bytes()).hexdigest() != (
        json.loads(previous_manifest)["sha256"]["unsw_binary_rf.joblib"]
    )
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "artifact_manifest.json", "metrics.json", "unsw_binary_rf.joblib",
    ]
