"""Offline synthetic-only research-candidate to manual SOC case regression."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from blue_team_ai.research_triage import create_research_candidate_case
from blue_team_ai.triage import create_offline_review_case
from siem_ai.core import case_evidence, case_history, list_cases


def _inputs():
    raw = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "1630000000.25\tN1\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp\n"
        "1630000001.0\tA1\t192.168.56.11\t52345\t192.168.56.21\t53\tudp\n"
    ).encode()
    digest = hashlib.sha256(raw).hexdigest()
    flows = [
        {
            "source_sha256": digest, "uid": uid,
            "attack_probability": probability, "predicted_attack": predicted,
            "operator_supplied_label": label,
            "outcome_against_supplied_label": outcome,
        }
        for uid, probability, predicted, label, outcome in (
            ("N1", 0.2, False, 0, "true_negative"),
            ("A1", 0.8, True, 1, "true_positive"),
        )
    ]
    report = {
        "report_version": 4,
        "mode": "offline_labeled_zeek_research_only",
        "input_manifest_sha256": "a" * 64,
        "selected_threshold": 0.5,
        "test_metrics": {"tp": 1, "fp": 0, "tn": 1, "fn": 0, "support": 2},
        "live_capture": False, "automated_alerts": False,
        "private_test_trace": {
            "trace_version": 1,
            "mode": "offline_zeek_heldout_test_predictions_only",
            "feature_schema_version": 1,
            "selected_threshold": 0.5,
            "label_authenticity": "operator_supplied_not_verified",
            "live_capture": False, "automated_alerts": False,
            "flows": flows,
        },
    }
    return raw, json.dumps(report).encode()


def test_explicit_candidate_creates_unclassified_case_and_atomic_research_audit(tmp_path):
    raw, trace = _inputs()
    db = tmp_path / "cyber.sqlite3"
    dataset_db = tmp_path / "soc_cases.sqlite3"
    assert not db.exists()
    case_id = create_research_candidate_case(
        db, source_data=raw, trace_data=trace, record_index=1, analyst_confirmed=True,
    )
    cases = list_cases(db)
    assert len(cases) == 1
    case = cases.iloc[0]
    assert case["case_id"] == case_id
    assert case["verdict"] == "Unclassified"
    assert case["state"] == "New"
    assert case["confidence"] is None or str(case["confidence"]) == "nan"
    note = case["analyst_note"]
    assert "NOT a live AI alert" in note
    assert hashlib.sha256(trace).hexdigest() in note
    assert hashlib.sha256(raw).hexdigest() in note
    assert "research_attack_probability=0.80000000" in note
    assert "validation_threshold=0.50000000" in note
    assert "operator_supplied_label" not in note
    assert "true_positive" not in note
    history = case_history(db, case_id)
    assert len(history) == 1
    assert history.iloc[0]["old_state"] is None
    assert history.iloc[0]["new_state"] == "New"
    assert history.iloc[0]["note"] == note
    evidence = case_evidence(db, case_id)
    assert evidence["uid"] == "A1"
    assert evidence["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert "AI_verdict" not in evidence
    assert "AI_attack_probability" not in evidence
    assert not dataset_db.exists()


@pytest.mark.parametrize("index,consent", [
    (0, True), (1, False), (1, None), (1, 1),
    (-1, True), (2, True), (500, True), (True, True), (1.0, True),
])
def test_unconfirmed_non_candidate_or_invalid_index_never_writes(tmp_path, index, consent):
    raw, trace = _inputs()
    db = tmp_path / "cyber.sqlite3"
    with pytest.raises(ValueError):
        create_research_candidate_case(
            db, source_data=raw, trace_data=trace,
            record_index=index, analyst_confirmed=consent,
        )
    assert not db.exists()


def test_tampered_original_or_trace_fails_closed_without_case(tmp_path):
    raw, trace = _inputs()
    db = tmp_path / "cyber.sqlite3"
    for source, report in (
        (raw.replace(b"192.168.56.11", b"192.168.56.12"), trace),
        (raw, trace.replace(b'"attack_probability": 0.8', b'"attack_probability": 0.1')),
        (raw, trace.replace(b'"uid": "A1"', b'"uid": "DIFFERENT"')),
        (raw, b"{}"),
    ):
        with pytest.raises(ValueError):
            create_research_candidate_case(
                db, source_data=source, trace_data=report,
                record_index=1, analyst_confirmed=True,
            )
        assert not db.exists()


def test_legacy_manual_case_keeps_default_note_and_unclassified_semantics(tmp_path):
    raw, _ = _inputs()
    db = tmp_path / "cyber.sqlite3"
    case_id = create_offline_review_case(db, source_data=raw, record_index=0)
    case = list_cases(db).iloc[0]
    assert case["case_id"] == case_id
    assert case["analyst_note"] == ""
    assert case["verdict"] == "Unclassified"
    assert case_history(db, case_id).iloc[0]["note"] == "Case created from selected flow"


def test_invalid_research_note_rejected_before_creating_database(tmp_path):
    raw, _ = _inputs()
    db = tmp_path / "cyber.sqlite3"
    with pytest.raises(ValueError, match="Creation note"):
        create_offline_review_case(
            db, source_data=raw, record_index=1, research_note="x" * 2001,
        )
    assert not db.exists()
