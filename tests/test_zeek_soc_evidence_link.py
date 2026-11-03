"""Synthetic-only regression: verify original Zeek -> research score -> SOC case."""
from __future__ import annotations

import json
import sqlite3

import pytest

from blue_team_ai.new_log_triage import create_new_log_candidate_case
from blue_team_ai.soc_evidence_link import verify_new_log_soc_case_link
from siem_ai.core import update_case
from test_zeek_new_log_triage import evidence, _args


def _verify(db, evidence, **overrides):
    args = _args(evidence)
    values = dict(
        source_data=args["source_data"],
        model=args["model"],
        report_data=args["report_data"],
        expected_log_sha256=args["expected_log_sha256"],
        model_sha256=args["model_sha256"],
        lab_cidrs=args["lab_cidrs"],
        record_index=args["record_index"],
    )
    values.update(overrides)
    return verify_new_log_soc_case_link(db, **values)


def test_original_research_case_link_and_read_only_recheck(tmp_path, evidence):
    db = tmp_path / "research.sqlite3"
    case_id = create_new_log_candidate_case(db, **_args(evidence))
    before = db.read_bytes()
    result = _verify(db, evidence, case_id=case_id)
    assert result["stored_flow_snapshot_matches_original"] is True
    assert result["initial_audit_matches_recomputed_inference"] is True
    assert result["soc_audit_history_consistent"] is True
    assert result["soc_audit_event_count"] == 1
    assert result["sqlite_read_only"] is True
    assert result["operational_alert_verified"] is False
    assert result["detection_latency_measured"] is False
    assert "192.168.56." not in json.dumps(result)
    assert "NEW1" not in json.dumps(result)
    assert db.read_bytes() == before
    # Analyst investigation must not erase the immutable creation evidence.
    update_case(db, case_id, "Investigating", "Review pending independent labels")
    updated = _verify(db, evidence, case_id=case_id)
    assert updated["initial_audit_matches_recomputed_inference"]
    assert updated["soc_audit_history_consistent"] is True
    assert updated["soc_audit_event_count"] == 2


@pytest.mark.parametrize("tamper", ["snapshot", "flow_id", "verdict", "initial_note"])
def test_tampered_sqlite_link_is_refused(tmp_path, evidence, tamper):
    db = tmp_path / "research.sqlite3"
    case_id = create_new_log_candidate_case(db, **_args(evidence))
    with sqlite3.connect(db) as conn:
        if tamper == "snapshot":
            conn.execute("UPDATE cases SET evidence_json=? WHERE case_id=?",
                         ('{"uid":"forged"}', case_id))
        elif tamper == "flow_id":
            conn.execute("UPDATE cases SET flow_id=? WHERE case_id=?",
                         ("0" * 16, case_id))
        elif tamper == "verdict":
            conn.execute("UPDATE cases SET verdict=? WHERE case_id=?",
                         ("Attack", case_id))
        else:
            conn.execute("UPDATE case_events SET note=? WHERE case_id=?",
                         ("forged audit", case_id))
    with pytest.raises(ValueError):
        _verify(db, evidence, case_id=case_id)


def test_wrong_pinned_inputs_or_missing_case_refuse_without_db_writes(tmp_path, evidence):
    db = tmp_path / "research.sqlite3"
    case_id = create_new_log_candidate_case(db, **_args(evidence))
    before = db.read_bytes()
    for kwargs in (
        {"case_id": case_id + 100},
        {"case_id": True},
        {"case_id": case_id, "record_index": True},
        {"case_id": case_id, "expected_log_sha256": "0" * 64},
        {"case_id": case_id, "model_sha256": "0" * 64},
        {"case_id": case_id, "report_data": b'{"forged":true}'},
    ):
        with pytest.raises(ValueError):
            _verify(db, evidence, **kwargs)
    assert db.read_bytes() == before
    with pytest.raises(ValueError, match="Existing regular SQLite"):
        _verify(tmp_path / "missing.sqlite3", evidence, case_id=case_id)
    assert not (tmp_path / "missing.sqlite3").exists()


@pytest.mark.parametrize("mutation", [
    "append_claim", "prepend_claim", "insert_claim", "alter_canonical_phrase",
])
def test_creation_audit_rejects_extra_or_reworded_claims(tmp_path, evidence, mutation):
    """A note containing all the old required substrings is not sufficient."""
    db = tmp_path / "research.sqlite3"
    case_id = create_new_log_candidate_case(db, **_args(evidence))
    with sqlite3.connect(db) as conn:
        note = conn.execute(
            "SELECT note FROM case_events WHERE case_id=? ORDER BY event_id LIMIT 1",
            (case_id,),
        ).fetchone()[0]
        if mutation == "append_claim":
            altered = note + " Attack independently confirmed."
        elif mutation == "prepend_claim":
            altered = "Verified attack. " + note
        elif mutation == "insert_claim":
            altered = note.replace(
                "Authorization, Host-only isolation",
                "Verified attack. Authorization, Host-only isolation",
            )
        else:
            altered = note.replace(
                "NOT a verified attack", "NOT a verified attack (yet)",
            )
        assert altered != note
        conn.execute(
            "UPDATE case_events SET note=? WHERE case_id=?",
            (altered, case_id),
        )
    with pytest.raises(ValueError):
        _verify(db, evidence, case_id=case_id)


def test_legacy_soc_case_cannot_claim_queue_pin_retroactively(tmp_path, evidence):
    db = tmp_path / "legacy.sqlite3"
    case_id = create_new_log_candidate_case(db, **_args(evidence))
    original = db.read_bytes()
    assert _verify(db, evidence, case_id=case_id)[
        "pinned_research_queue_creation_audit_verified"
    ] is False
    with pytest.raises(ValueError, match="lacks matching pinned research queue"):
        _verify(
            db, evidence, case_id=case_id,
            expected_research_bundle_sha256="a" * 64,
            expected_research_alert_ref="b" * 64,
        )
    assert db.read_bytes() == original


@pytest.mark.parametrize("mutation", [
    "case_state", "case_updated_at", "case_created_at", "old_state",
    "event_new_state", "backdated_event", "non_utc_event", "second_creation",
    "case_analyst_note", "last_event_note",
])
def test_existing_soc_case_audit_chain_tampering_is_refused_read_only(
    tmp_path, evidence, mutation
):
    db = tmp_path / "audit-chain.sqlite3"
    case_id = create_new_log_candidate_case(db, **_args(evidence))
    update_case(db, case_id, "Investigating", "Independent analyst review")
    with sqlite3.connect(db) as conn:
        last_id, last_time = conn.execute(
            "SELECT event_id, created_at FROM case_events "
            "WHERE case_id=? ORDER BY event_id DESC LIMIT 1", (case_id,),
        ).fetchone()
        if mutation == "case_state":
            conn.execute("UPDATE cases SET state='Resolved' WHERE case_id=?", (case_id,))
        elif mutation == "case_updated_at":
            conn.execute(
                "UPDATE cases SET updated_at='2000-01-01T00:00:00+00:00' "
                "WHERE case_id=?", (case_id,),
            )
        elif mutation == "case_created_at":
            conn.execute(
                "UPDATE cases SET created_at='2000-01-01T00:00:00+00:00' "
                "WHERE case_id=?", (case_id,),
            )
        elif mutation == "old_state":
            conn.execute(
                "UPDATE case_events SET old_state='Resolved' WHERE event_id=?",
                (last_id,),
            )
        elif mutation == "event_new_state":
            conn.execute(
                "UPDATE case_events SET new_state='Escalated' WHERE event_id=?",
                (last_id,),
            )
        elif mutation == "backdated_event":
            conn.execute(
                "UPDATE case_events SET created_at='2000-01-01T00:00:00+00:00' "
                "WHERE event_id=?", (last_id,),
            )
        elif mutation == "non_utc_event":
            conn.execute(
                "UPDATE case_events SET created_at='2026-11-03T12:00:00+07:00' "
                "WHERE event_id=?", (last_id,),
            )
        elif mutation == "case_analyst_note":
            conn.execute(
                "UPDATE cases SET analyst_note='Forged analyst finding' "
                "WHERE case_id=?", (case_id,),
            )
        elif mutation == "last_event_note":
            conn.execute(
                "UPDATE case_events SET note='Forged analyst finding' "
                "WHERE event_id=?", (last_id,),
            )
        else:
            conn.execute(
                "INSERT INTO case_events(case_id,old_state,new_state,note,created_at) "
                "VALUES (?,NULL,'New','Forged second creation',?)",
                (case_id, last_time),
            )
    before = db.read_bytes()
    with pytest.raises(ValueError, match="SOC audit|SOC case|SOC analyst note"):
        _verify(db, evidence, case_id=case_id)
    assert db.read_bytes() == before


def test_initial_soc_case_analyst_note_must_match_creation_event(tmp_path, evidence):
    """Even a New case cannot carry a claim absent from its creation audit."""
    db = tmp_path / "initial-note.sqlite3"
    case_id = create_new_log_candidate_case(db, **_args(evidence))
    with sqlite3.connect(db) as conn:
        conn.execute(
            "UPDATE cases SET analyst_note='Attack independently verified' "
            "WHERE case_id=?", (case_id,),
        )
    before = db.read_bytes()
    with pytest.raises(ValueError, match="SOC analyst note"):
        _verify(db, evidence, case_id=case_id)
    assert db.read_bytes() == before
