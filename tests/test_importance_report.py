"""Regression tests for an explainability report made from a fitted model."""
import sys
from pathlib import Path

import pytest
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.importance_report import build_importance_report
from siem_ai.model import fit_and_evaluate


def fitted():
    rows = []
    for i in range(30):
        rows.append({
            "id": i + 1, "proto": ["tcp", "udp", "icmp"][i % 3],
            "service": ["http", "dns", "ssl_tls"][i % 3],
            "state": ["FIN", "CON", "INT"][i % 3],
            "dur": i / 10, "sbytes": i * 14, "dbytes": i * 2,
            "spkts": i % 5 + 1, "dpkts": i % 4 + 1,
            "label": i % 2, "attack_cat": "Exploits" if i % 2 else "Normal",
        })
    frame = pd.DataFrame(rows)
    return fit_and_evaluate(frame.iloc[:22], frame.iloc[22:])


def report(model, metrics):
    return build_importance_report(model, metrics,
                                   training_sha256="a" * 64, model_sha256="b" * 64)


def test_report_covers_features_and_preserves_importance():
    model, metrics = fitted()
    result = report(model, metrics)
    assert result["training_rows"] == 22
    assert result["uses_test_labels"] is False
    assert result["importance_sum"] == pytest.approx(1)
    assert result["feature_count"] == len(metrics["features"])
    assert {row["feature"] for row in result["features"]} == set(metrics["features"])
    assert sum(row["mdi_importance"] for row in result["features"]) == pytest.approx(1)
    assert sum(row["encoded_dimensions"] for row in result["features"]) == result["encoded_feature_count"]
    assert [r["rank"] for r in result["features"]] == list(range(1, result["feature_count"] + 1))
    assert not {"id", "label", "attack_cat"} & {r["feature"] for r in result["features"]}


def test_rejects_metrics_different_from_fitted_model():
    model, metrics = fitted()
    altered = {**metrics, "features": list(reversed(metrics["features"]))}
    with pytest.raises(ValueError, match="differ"):
        report(model, altered)


def test_rejects_fake_hash_or_model_type():
    model, metrics = fitted()
    with pytest.raises(ValueError, match="SHA-256"):
        build_importance_report(model, metrics, training_sha256="bad", model_sha256="b" * 64)
    with pytest.raises(ValueError, match="RandomForest"):
        report(model, {**metrics, "model": "FakeAI"})
