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
    assert result["sqlite_read_only"] is True
    assert result["operational_alert_verified"] is False
    assert result["detection_latency_measured"] is False
    assert "192.168.56." not in json.dumps(result)
    assert "NEW1" not in json.dumps(result)
    assert db.read_bytes() == before
    # Analyst investigation must not erase the immutable creation evidence.
    update_case(db, case_id, "Investigating", "Review pending independent labels")
    assert _verify(db, evidence, case_id=case_id)["initial_audit_matches_recomputed_inference"]


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
