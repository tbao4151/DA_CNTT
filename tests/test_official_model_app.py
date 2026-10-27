"""Opt-in official UNSW model -> Streamlit -> SOC case integration smoke.

This test is run only after training the official model in a dedicated workflow.
It uses the official test CSV for inference, never for fitting or tuning. All
application writes are confined to a temporary directory. This is headless
integration on CI runners, not a browser end-to-end certification.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import joblib
import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from siem_ai.case_report import export_case_report
from siem_ai.core import list_cases
from siem_ai.model import predict_batch

MODEL = ROOT / "artifacts" / "unsw_binary_rf.joblib"
METRICS = ROOT / "artifacts" / "metrics.json"
TEST_CSV = ROOT / "data" / "raw" / "unsw_nb15" / "UNSW_NB15_testing-set.csv"


@pytest.mark.skipif(
    os.environ.get("DA005_OFFICIAL_MODEL_SMOKE") != "1",
    reason="Requires a trusted freshly trained official UNSW model (opt-in workflow)",
)
def test_official_model_dashboard_creates_exportable_case(tmp_path):
    assert MODEL.is_file() and METRICS.is_file() and TEST_CSV.is_file()
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    assert (metrics["train_size"], metrics["test_size"]) == (175341, 82332)

    # Same default sample and alert threshold as the Streamlit UI.
    sample = pd.read_csv(TEST_CSV, nrows=2500)
    assert len(sample) == 2500
    trained_model = joblib.load(MODEL)  # Trusted artifact trained in this workflow.
    predictions = predict_batch(trained_model, sample)
    expected_alerts = int((predictions["attack_probability"] >= 0.8).sum())
    assert expected_alerts > 0, "Official model produced no alerts on this sample"
    del trained_model

    sandbox = tmp_path / "isolated_official_app"
    sandbox.mkdir()
    shutil.copy2(ROOT / "app.py", sandbox / "app.py")
    shutil.copytree(ROOT / "src", sandbox / "src")
    data_dir = sandbox / "data" / "raw" / "unsw_nb15"
    data_dir.mkdir(parents=True)
    sample.to_csv(data_dir / TEST_CSV.name, index=False)
    artifacts = sandbox / "artifacts"
    artifacts.mkdir()
    shutil.copy2(MODEL, artifacts / MODEL.name)
    shutil.copy2(METRICS, artifacts / METRICS.name)

    app = AppTest.from_file(str(sandbox / "app.py"), default_timeout=120).run()
    assert not app.exception, [str(exc.message) for exc in app.exception]
    assert any(
        metric.label == "AI dự đoán Attack"
        and metric.value != "Chưa huấn luyện"
        for metric in app.metric
    )
    assert any(
        metric.label == "Cảnh báo ở ngưỡng hiện tại"
        and int(str(metric.value).replace(",", "")) == expected_alerts
        for metric in app.metric
    )
    create_buttons = [
        button for button in app.button
        if button.label == "Tạo SOC case từ flow đã chọn"
    ]
    assert len(create_buttons) == 1

    app = create_buttons[0].click().run()
    assert not app.exception, [str(exc.message) for exc in app.exception]
    db = sandbox / "runtime" / "soc_cases.sqlite3"
    cases = list_cases(db)
    assert len(cases) == 1
    case = cases.iloc[0]
    assert case["verdict"] == "Attack"
    assert 0.8 <= float(case["confidence"]) <= 1.0
    report = json.loads(export_case_report(db, int(case["case_id"])))
    assert report["case"]["state"] == "New"
    assert report["flow_evidence"]
    assert not {
        "id", "label", "attack_cat", "AI_verdict",
        "AI_attack_probability", "flow_ref",
    } & set(report["flow_evidence"])
    assert [event["new_state"] for event in report["case_events"]] == ["New"]
