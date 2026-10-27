"""Synthetic-only regression tests for the opt-in local evidence checker."""
import hashlib
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.verify_local_run import verify_local_run


def make_synthetic_run(tmp_path):
    data = tmp_path / "data/raw/unsw_nb15"
    data.mkdir(parents=True)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    train = pd.DataFrame({"id": range(1, 17), "dur": range(16), "sbytes": [x * 3 for x in range(16)],
                          "label": [x % 2 for x in range(16)], "attack_cat": ["Normal" if x % 2 == 0 else "Exploits" for x in range(16)]})
    test = pd.DataFrame({"id": range(17, 25), "dur": range(16, 24), "sbytes": [x * 3 for x in range(16, 24)],
                         "label": [x % 2 for x in range(16, 24)], "attack_cat": ["Normal" if x % 2 == 0 else "Exploits" for x in range(16, 24)]})
    expected = {}
    for name, frame in [("UNSW_NB15_training-set.csv", train), ("UNSW_NB15_testing-set.csv", test)]:
        path = data / name
        frame.to_csv(path, index=False)
        expected[name] = (len(frame), hashlib.sha256(path.read_bytes()).hexdigest())
    model = RandomForestClassifier(n_estimators=15, random_state=42).fit(train[["dur", "sbytes"]], train["label"])
    joblib.dump(model, artifacts / "unsw_binary_rf.joblib")
    predictions = model.predict(test[["dur", "sbytes"]])
    metrics = {"train_size": len(train), "test_size": len(test), "features": ["dur", "sbytes"],
               "classification_report": classification_report(test["label"], predictions, labels=[0, 1], output_dict=True, zero_division=0),
               "confusion_matrix_0_1": confusion_matrix(test["label"], predictions, labels=[0, 1]).tolist(),
               "average_precision_attack": float(average_precision_score(test["label"], model.predict_proba(test[["dur", "sbytes"]])[:, 1]))}
    (artifacts / "metrics.json").write_text(json.dumps(metrics), encoding="utf-8")
    return expected


def test_synthetic_run_creates_truthful_verification_report(tmp_path):
    expected = make_synthetic_run(tmp_path)
    report = verify_local_run(tmp_path, expected_files=expected)
    assert report["verification_status"] == "passed"
    assert report["train_rows"] == 16 and report["test_rows"] == 8
    assert report["feature_count"] == 2
    assert len(report["model_sha256"]) == 64
    assert report["dataset_sha256"] == {k: value[1] for k, value in expected.items()}
    assert "live capture" in report["scope_note"]


def test_synthetic_run_rejects_modified_test_data(tmp_path):
    expected = make_synthetic_run(tmp_path)
    test_path = tmp_path / "data/raw/unsw_nb15/UNSW_NB15_testing-set.csv"
    test_path.write_bytes(test_path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_local_run(tmp_path, expected_files=expected)


def test_synthetic_run_rejects_tampered_metrics(tmp_path):
    expected = make_synthetic_run(tmp_path)
    path = tmp_path / "artifacts/metrics.json"
    metrics = json.loads(path.read_text())
    metrics["confusion_matrix_0_1"][0][0] += 1
    path.write_text(json.dumps(metrics))
    with pytest.raises(ValueError, match="confusion matrix differs"):
        verify_local_run(tmp_path, expected_files=expected)


def test_synthetic_run_rejects_ground_truth_as_feature(tmp_path):
    expected = make_synthetic_run(tmp_path)
    path = tmp_path / "artifacts/metrics.json"
    metrics = json.loads(path.read_text())
    metrics["features"].append("label")
    path.write_text(json.dumps(metrics))
    with pytest.raises(ValueError, match="ground-truth features"):
        verify_local_run(tmp_path, expected_files=expected)
