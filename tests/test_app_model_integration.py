"""Headless Streamlit integration: real fitted synthetic model -> alert -> SOC export.

All input flows and labels are synthetic test fixtures. The temporary app copy
prevents writes to the repository's actual runtime/ and artifacts/ directories.
This does not validate the official UNSW benchmark or Windows browser behavior.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import joblib
import pandas as pd
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from siem_ai.case_report import export_case_report
from siem_ai.core import list_cases
from siem_ai.model import fit_and_evaluate


def test_fitted_model_alert_creates_exportable_soc_case(tmp_path):
    # Copy only the app and its code: the test cannot alter the real SOC DB.
    sandbox = tmp_path / "isolated_app"
    sandbox.mkdir()
    shutil.copy2(ROOT / "app.py", sandbox / "app.py")
    shutil.copytree(ROOT / "src", sandbox / "src")
    data_dir = sandbox / "data" / "raw" / "unsw_nb15"
    data_dir.mkdir(parents=True)
    artifacts_dir = sandbox / "artifacts"
    artifacts_dir.mkdir()

    rows = []
    for i in range(128):
        attack = i % 2
        rows.append({
            "id": i + 1, "proto": "tcp" if attack else "udp",
            "service": "http" if attack else "dns",
            "state": "FIN" if attack else "CON",
            "dur": 1.5 if attack else 0.2,
            "sbytes": 1000 if attack else 100,
            "dbytes": 500 if attack else 50,
            "spkts": 10 if attack else 1,
            "dpkts": 5 if attack else 1,
            "rate": 1000 if attack else 10,
            "ct_srv_src": 16 if attack else 1,
            "label": attack,
            "attack_cat": "Exploits" if attack else "Normal",
        })
    flows = pd.DataFrame(rows)
    flows.to_csv(data_dir / "UNSW_NB15_testing-set.csv", index=False)
    model, _ = fit_and_evaluate(flows.iloc[:96], flows.iloc[96:])
    joblib.dump(model, artifacts_dir / "unsw_binary_rf.joblib")

    app = AppTest.from_file(str(sandbox / "app.py"), default_timeout=90).run()
    assert not app.exception, [str(exc.message) for exc in app.exception]
    assert any(
        metric.label == "AI dự đoán Attack" and metric.value != "Chưa huấn luyện"
        for metric in app.metric
    )
    create_buttons = [
        button for button in app.button
        if button.label == "Tạo SOC case từ flow đã chọn"
    ]
    assert len(create_buttons) == 1, "Expected a real model-generated alert"

    app = create_buttons[0].click().run()
    assert not app.exception, [str(exc.message) for exc in app.exception]
    db = sandbox / "runtime" / "soc_cases.sqlite3"
    cases = list_cases(db)
    assert len(cases) == 1
    case = cases.iloc[0]
    assert case["verdict"] == "Attack"
    assert 0.8 <= case["confidence"] <= 1.0
    report = json.loads(export_case_report(db, int(case["case_id"])))
    assert report["case"]["state"] == "New"
    assert report["flow_evidence"]["proto"] == "tcp"
    assert not {"id", "label", "attack_cat", "AI_verdict", "flow_ref"} & set(report["flow_evidence"])
    assert [event["new_state"] for event in report["case_events"]] == ["New"]
