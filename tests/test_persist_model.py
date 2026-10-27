"""Regression tests for safe local model/metrics artifact persistence.

Uses tiny trusted synthetic objects, not official UNSW training or SOC data.
"""
import json
import sys
from pathlib import Path

import joblib
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.model import persist_model


def test_persist_model_writes_both_artifacts_and_cleans_stage(tmp_path):
    persist_model({"synthetic": True}, {"train_size": 3}, tmp_path)
    assert joblib.load(tmp_path / "unsw_binary_rf.joblib") == {"synthetic": True}
    assert json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8")) == {"train_size": 3}
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "metrics.json", "unsw_binary_rf.joblib",
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
