"""Regression tests for read-only, self-contained SOC case JSON exports."""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.case_report import export_case_report
from siem_ai.core import create_case, update_case, case_history, list_cases


def test_export_contains_evidence_and_chronological_history_without_labels(tmp_path):
    db = tmp_path / "soc.sqlite3"
    row = {
        "proto": "tcp", "service": "http", "state": "FIN", "dur": 1,
        "sbytes": 120, "dbytes": 45, "label": 1,
        "attack_cat": "Exploits", "id": 7,
        "AI_verdict": "Attack", "AI_attack_probability": 0.91,
        "flow_ref": "view-only",
    }
    case_id = create_case(db, row=row, verdict="Attack", confidence=0.91)
    update_case(db, case_id, "Investigating", "Đang kiểm tra kết nối")
    before_cases = list_cases(db).to_dict("records")
    before_events = case_history(db, case_id).to_dict("records")

    raw = export_case_report(db, case_id)
    report = json.loads(raw.decode("utf-8"))
    assert report["schema_version"] == 1
    assert report["case"]["case_id"] == case_id
    assert report["case"]["state"] == "Investigating"
    assert report["flow_evidence"]["proto"] == "tcp"
    assert not {"label", "attack_cat", "id", "AI_verdict", "AI_attack_probability", "flow_ref"} & set(report["flow_evidence"])
    assert [event["new_state"] for event in report["case_events"]] == ["New", "Investigating"]
    assert report["case_events"][-1]["note"] == "Đang kiểm tra kết nối"
    assert "not signed" in report["integrity_notice"]
    assert raw == export_case_report(db, case_id)
    assert before_cases == list_cases(db).to_dict("records")
    assert before_events == case_history(db, case_id).to_dict("records")


def test_export_legacy_case_without_events(tmp_path):
    db = tmp_path / "legacy.sqlite3"
    case_id = create_case(db, row={"proto": "udp"}, verdict="Normal", confidence=0.1)
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM case_events WHERE case_id=?", (case_id,))
    report = json.loads(export_case_report(db, case_id))
    assert report["case_events"] == []


@pytest.mark.parametrize("invalid", [0, -1, True, 1.5, "1"])
def test_export_rejects_invalid_case_id(tmp_path, invalid):
    with pytest.raises(ValueError, match="Case ID"):
        export_case_report(tmp_path / "cases.sqlite3", invalid)


def test_export_rejects_unknown_case_and_corrupt_evidence(tmp_path):
    db = tmp_path / "cases.sqlite3"
    case_id = create_case(db, row={"proto": "tcp"}, verdict="Attack", confidence=0.8)
    with pytest.raises(ValueError, match="not found"):
        export_case_report(db, case_id + 1)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE cases SET evidence_json='[]' WHERE case_id=?", (case_id,))
    with pytest.raises(ValueError, match="object"):
        export_case_report(db, case_id)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE cases SET evidence_json='broken' WHERE case_id=?", (case_id,))
    with pytest.raises(ValueError, match="valid JSON"):
        export_case_report(db, case_id)
