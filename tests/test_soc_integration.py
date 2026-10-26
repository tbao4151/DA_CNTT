"""Integration regression: trained ML scores -> SOC case -> audit trail.

Synthetic labeled flows are used ONLY as deterministic test fixtures.
This test is not an UNSW-NB15 performance benchmark and does not load a
production model artifact or write to the application's runtime database.
"""
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.core import (
    case_evidence, case_history, create_case, flow_id, list_cases, update_case,
)
from siem_ai.model import fit_and_evaluate, predict_batch


def synthetic_flows(n=64):
    rows = []
    for i in range(n):
        attack = i % 2
        rows.append({
            "id": i + 1,
            "proto": "tcp" if attack else "udp",
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
    return pd.DataFrame(rows)


def test_model_alert_to_soc_case_lifecycle(tmp_path):
    flows = synthetic_flows()
    train, test = flows.iloc[:48], flows.iloc[48:]
    model, report = fit_and_evaluate(train, test)
    assert report["test_size"] == len(test)

    # Inference must work without the original labels and dataset row ID.
    features_only = test.drop(columns=["id", "label", "attack_cat"])
    predictions = predict_batch(model, features_only)
    assert len(predictions) == len(test)
    assert predictions["attack_probability"].between(0, 1).all()

    # Choose an actual high-confidence attack prediction; no mock scores.
    candidates = predictions.index[predictions["attack_probability"] >= 0.8]
    assert len(candidates) > 0, "Synthetic model produced no demo alert"
    idx = candidates[0]
    score = float(predictions.loc[idx, "attack_probability"])
    assert predictions.loc[idx, "verdict"] == "Attack"

    original = test.loc[idx].to_dict()
    enriched = original | {
        "AI_verdict": "Attack",
        "AI_attack_probability": score,
        "flow_ref": "UI-generated-reference",
    }
    db = tmp_path / "soc" / "cases.sqlite3"
    case_id = create_case(db, row=enriched, verdict="Attack", confidence=score)

    saved = list_cases(db).iloc[0]
    assert saved["case_id"] == case_id
    assert saved["flow_id"] == flow_id(original)
    assert saved["confidence"] == score
    evidence = case_evidence(db, case_id)
    assert set(features_only.columns).issubset(evidence)
    assert not {"label", "attack_cat", "id", "AI_verdict",
                "AI_attack_probability", "flow_ref"}.intersection(evidence)
    assert flow_id(evidence) == saved["flow_id"]

    update_case(db, case_id, "Investigating", "Review protocol and traffic volume")
    update_case(db, case_id, "Resolved", "Synthetic test case closed")
    assert list_cases(db).iloc[0]["state"] == "Resolved"
    history = case_history(db, case_id)
    assert history["new_state"].tolist() == ["New", "Investigating", "Resolved"]
    assert history["old_state"].tolist() == [None, "New", "Investigating"]
    assert len(history) == 3
