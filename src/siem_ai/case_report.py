"""Read-only, portable SOC case report for the local educational dashboard.

This is a snapshot of a mutable SQLite database, NOT signed forensic evidence.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .core import NON_FEATURE_FIELDS, ensure_case_db


def export_case_report(path: str | Path, case_id: int) -> bytes:
    """Export one case and its chronological audit trail as UTF-8 JSON.

    A single SQLite read transaction keeps case details and events consistent.
    The export never writes case state or includes original ground-truth labels.
    """
    if isinstance(case_id, bool) or not isinstance(case_id, int) or case_id <= 0:
        raise ValueError("Case ID must be a positive integer")

    ensure_case_db(path)
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN")
        row = conn.execute(
            """SELECT case_id,flow_id,verdict,confidence,state,analyst_note,
                      evidence_json,created_at,updated_at
               FROM cases WHERE case_id=?""",
            (case_id,),
        ).fetchone()
        if row is None:
            raise ValueError("Case not found")
        events = conn.execute(
            """SELECT event_id,old_state,new_state,note,created_at
               FROM case_events WHERE case_id=? ORDER BY event_id""",
            (case_id,),
        ).fetchall()

    try:
        evidence = json.loads(row["evidence_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Case evidence is not valid JSON") from exc
    if not isinstance(evidence, dict):
        raise ValueError("Case evidence must be an object")

    report = {
        "schema_version": 1,
        "report_type": "DA005 educational SOC case",
        "integrity_notice": (
            "Local SQLite snapshot; editable by database users; "
            "not signed, immutable, or production forensic evidence."
        ),
        "case": {
            key: row[key]
            for key in (
                "case_id", "flow_id", "verdict", "confidence", "state",
                "analyst_note", "created_at", "updated_at",
            )
        },
        "flow_evidence": {
            str(key): value for key, value in evidence.items()
            if key not in NON_FEATURE_FIELDS
        },
        "case_events": [dict(event) for event in events],
    }
    return (json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
