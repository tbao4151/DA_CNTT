"""Bounded read-only viewer for private offline Zeek SOC research cases.

A local SQLite snapshot is editable by its owner and is not forensic proof.
No schema creation, case state mutation, network access, or alert emission.
"""
from __future__ import annotations

import json
from contextlib import closing
import sqlite3
import stat
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MAX_DB_BYTES = 128 * 1024 * 1024
MAX_INDEX_SCAN = 500
MAX_VISIBLE_CASES = 100
MAX_EVENTS = 200
MAX_EVIDENCE_CHARS = 65536


def _private_existing_db(path: str | Path) -> Path:
    if not isinstance(path, (str, Path)) or not str(path).strip():
        raise ValueError("Private SQLite path required")
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.suffix.lower() != ".sqlite3":
        raise ValueError("Use an absolute private .sqlite3 path")
    if candidate.is_symlink():
        raise ValueError("Database symlinks are not allowed")
    resolved = candidate.resolve(strict=True)
    if resolved.is_relative_to(REPOSITORY_ROOT):
        raise ValueError("Private database must remain outside Git")
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_DB_BYTES:
        raise ValueError("Private database is missing, empty or exceeds size limit")
    with resolved.open("rb") as stream:
        if stream.read(16) != b"SQLite format 3\x00":
            raise ValueError("Not a SQLite database")
    return resolved


def _open_read_only(path: str | Path) -> sqlite3.Connection:
    resolved = _private_existing_db(path)
    connection = sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True, timeout=2)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _zeek_evidence(raw: str) -> dict | None:
    if not isinstance(raw, str) or len(raw) > MAX_EVIDENCE_CHARS:
        return None
    try:
        evidence = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(evidence, dict) or evidence.get("origin") != "offline_zeek_log":
        return None
    return evidence


def list_private_zeek_cases(path: str | Path) -> dict:
    """Return at most 100 recent Zeek Unclassified cases; never create a DB."""
    with closing(_open_read_only(path)) as connection:
        rows = connection.execute(
            "SELECT case_id, state, created_at, updated_at, evidence_json "
            "FROM cases WHERE verdict='Unclassified' ORDER BY case_id DESC LIMIT ?",
            (MAX_INDEX_SCAN + 1,),
        ).fetchall()
    cases = []
    for row in rows[:MAX_INDEX_SCAN]:
        evidence = _zeek_evidence(row["evidence_json"])
        if evidence is None:
            continue
        cases.append({
            "case_id": row["case_id"],
            "state": row["state"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "zeek_uid": evidence.get("uid"),
            "source_sha256": evidence.get("source_sha256"),
        })
        if len(cases) >= MAX_VISIBLE_CASES:
            break
    return {
        "cases": cases,
        "limited": len(rows) > MAX_INDEX_SCAN or len(cases) >= MAX_VISIBLE_CASES,
        "scan_limit": MAX_INDEX_SCAN,
    }


def read_private_zeek_case(path: str | Path, case_id: int) -> dict:
    """Consistent read-only case/evidence/audit snapshot with bounded history."""
    if type(case_id) is not int or case_id <= 0:
        raise ValueError("Case ID must be a positive integer")
    with closing(_open_read_only(path)) as connection:
        connection.execute("BEGIN")
        case = connection.execute(
            "SELECT case_id, flow_id, verdict, confidence, state, analyst_note, "
            "evidence_json, created_at, updated_at FROM cases WHERE case_id=?",
            (case_id,),
        ).fetchone()
        if case is None or case["verdict"] != "Unclassified":
            raise ValueError("Unclassified research case not found")
        evidence = _zeek_evidence(case["evidence_json"])
        if evidence is None:
            raise ValueError("Case is not a valid offline Zeek research record")
        events = connection.execute(
            "SELECT event_id, old_state, new_state, note, created_at "
            "FROM case_events WHERE case_id=? ORDER BY event_id DESC LIMIT ?",
            (case_id, MAX_EVENTS + 1),
        ).fetchall()
    return {
        "schema_version": 1,
        "report_type": "DA005 offline Zeek SOC research review",
        "integrity_notice": (
            "Local editable SQLite snapshot, not signed or tamper-proof evidence. "
            "History may be truncated to the most recent 200 events."
        ),
        "case": {key: case[key] for key in (
            "case_id", "flow_id", "verdict", "confidence", "state",
            "analyst_note", "created_at", "updated_at",
        )},
        "flow_evidence": evidence,
        "case_events": [dict(event) for event in reversed(events[:MAX_EVENTS])],
        "history_truncated": len(events) > MAX_EVENTS,
    }
