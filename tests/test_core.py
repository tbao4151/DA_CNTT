import sys
from pathlib import Path
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.core import validate_flows, flow_id, assess_signal, create_case, list_cases, update_case

def record():
    return {"proto":"tcp","service":"http","state":"FIN","dur":1,
            "sbytes":123,"dbytes":456,"spkts":2,"dpkts":4,"rate":500}

def test_schema_accepts_flow():
    df = pd.DataFrame([record()])
    assert len(validate_flows(df)) == 1

def test_schema_rejects_missing_required():
    with pytest.raises(ValueError, match="Missing"):
        validate_flows(pd.DataFrame([{"proto":"tcp"}]))

def test_id_ignores_target_leakage():
    first = record() | {"label":1,"attack_cat":"Exploits","id":3}
    second = record() | {"label":0,"attack_cat":"Normal","id":4}
    assert flow_id(first) == flow_id(second)

def test_rules_describe_signals_not_attack_truth():
    score, why = assess_signal(record() | {"ct_srv_src":20})
    assert score == 30 and len(why) == 1

def test_case_lifecycle(tmp_path):
    path = tmp_path / "db" / "cases.sqlite3"
    key = create_case(path,row=record(),verdict="Attack",confidence=.93)
    cases = list_cases(path)
    assert len(cases) == 1 and cases.loc[0,"case_id"] == key
    update_case(path,key,"Investigating","Review flow features.")
    assert list_cases(path).loc[0,"state"] == "Investigating"
    with pytest.raises(ValueError, match="Invalid case"):
        update_case(path,key,"Made Up","note")
    with pytest.raises(ValueError, match="note"):
        update_case(path,key,"Resolved","")

def test_id_ignores_ai_outputs_and_view_metadata():
    base = record() | {"id": 7, "label": 1, "attack_cat": "DoS"}
    with_predictions = base | {
        "AI_verdict": "Attack", "AI_attack_probability": 0.987,
        "flow_ref": "unrelated-ui-value",
    }
    assert flow_id(base) == flow_id(with_predictions)


@pytest.mark.parametrize("confidence", [float("nan"), float("inf"), float("-inf"), -0.1, 1.1])
def test_case_rejects_invalid_confidence(tmp_path, confidence):
    with pytest.raises(ValueError, match="Confidence"):
        create_case(tmp_path / "cases.sqlite3", row=record(), verdict="Attack", confidence=confidence)


@pytest.mark.parametrize("note", [" ", "\\n  \\t", "x" * 2001])
def test_case_rejects_empty_or_oversized_notes(tmp_path, note):
    db = tmp_path / "cases.sqlite3"
    case_id = create_case(db, row=record(), verdict="Attack", confidence=0.7)
    with pytest.raises(ValueError, match="note"):
        update_case(db, case_id, "Resolved", note)
