"""Schema validation, deterministic alert identifiers and local SOC case store.

UNSW-NB15 train/test split has 45 columns, no timestamps/IPs.
ATTACK_LABELS ARE GROUND TRUTH — never pass them as model features.
"""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

LABEL_FIELDS = frozenset({"id", "label", "attack_cat"})
# Predictions and UI-generated columns must never alter a flow content digest.
DERIVED_FIELDS = frozenset({"AI_verdict", "AI_attack_probability", "flow_ref"})
NON_FEATURE_FIELDS = LABEL_FIELDS | DERIVED_FIELDS
REQUIRED_FEATURES = frozenset({"dur", "proto", "service", "state", "sbytes", "dbytes", "spkts", "dpkts"})
CASE_STATES = ("New", "Investigating", "Escalated", "Resolved", "False Positive")
MAX_UPLOAD_ROWS = 30000


def validate_flows(frame: pd.DataFrame, *, max_rows: int = MAX_UPLOAD_ROWS) -> pd.DataFrame:
    if not isinstance(frame, pd.DataFrame):
        raise TypeError("Input must be a pandas DataFrame")
    if not 0 < len(frame) <= max_rows:
        raise ValueError(f"Flow count must be 1..{max_rows:,}")
    if frame.columns.duplicated().any():
        raise ValueError("Duplicate column names are not allowed")
    missing = sorted(REQUIRED_FEATURES.difference(frame.columns))
    if missing:
        raise ValueError("Missing UNSW-NB15 columns: " + ", ".join(missing))
    return frame.copy()


def flow_id(row: dict) -> str:
    """Stable digest of flow features, independent of ground truth and row ID."""
    features = {str(k): str(v)[:256] for k, v in row.items() if k not in NON_FEATURE_FIELDS}
    raw = json.dumps(features, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def assess_signal(row: dict) -> tuple[int, list[str]]:
    """Transparent demonstration heuristics, NOT proof of malicious traffic."""
    reasons = []
    try:
        if float(row.get("ct_srv_src", 0) or 0) >= 15:
            reasons.append("Many same-service connections from source (ct_srv_src)")
        if float(row.get("ct_dst_sport_ltm", 0) or 0) >= 15:
            reasons.append("Repeated destination/source-port combination")
        if float(row.get("rate", 0) or 0) > 100000:
            reasons.append("High flow packet rate")
    except (ValueError, TypeError):
        return 0, ["Rule fields were not numeric"]
    return min(100, len(reasons) * 30), reasons


def ensure_case_db(path: str | Path) -> None:
    db = Path(path)
    db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS cases (
            case_id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id TEXT NOT NULL,
            verdict TEXT NOT NULL,
            confidence REAL,
            state TEXT NOT NULL DEFAULT 'New',
            analyst_note TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS case_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            old_state TEXT,
            new_state TEXT NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )""")


def create_case(
    path: str | Path, *, row: dict, verdict: str, confidence: float | None,
    creation_note: str | None = None,
) -> int:
    # Existing callers retain the original empty analyst_note and default event.
    # Explicit research triage may atomically attach a bounded initial audit note.
    if creation_note is not None and (
        not isinstance(creation_note, str) or not 0 < len(creation_note.strip()) <= 2000
    ):
        raise ValueError("Creation note must be 1..2000 non-whitespace characters")
    ensure_case_db(path)
    if verdict not in ("Attack", "Normal", "Unclassified"):
        raise ValueError("Invalid verdict")
    if confidence is not None and (not math.isfinite(confidence) or not 0 <= confidence <= 1):
        raise ValueError("Confidence must be in [0,1]")
    # Capture the same feature set used by flow_id for traceable SOC evidence.
    # Ground-truth labels, row IDs and AI/UI-derived columns are stored separately
    # (or omitted), never mixed into the original network-flow feature snapshot.
    # String values are capped like flow_id; this is a human-readable snapshot,
    # not a lossless typed serialization for re-running model inference.
    evidence = {
        str(k): str(v)[:256]
        for k, v in row.items()
        if k not in NON_FEATURE_FIELDS
    }
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(path) as conn:
        cursor = conn.execute(
            """INSERT INTO cases (flow_id,verdict,confidence,analyst_note,evidence_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (flow_id(row), verdict, confidence, creation_note.strip() if creation_note else "", json.dumps(evidence), now, now),
        )
        case_id = int(cursor.lastrowid)
        conn.execute(
            """INSERT INTO case_events (case_id,old_state,new_state,note,created_at)
               VALUES (?,?,?,?,?)""",
            (case_id, None, "New", creation_note.strip() if creation_note else "Case created from selected flow", now),
        )
        return case_id


def case_evidence(path: str | Path, case_id: int) -> dict:
    """Read the immutable feature snapshot captured when a case was opened."""
    ensure_case_db(path)
    with sqlite3.connect(path) as conn:
        result = conn.execute(
            "SELECT evidence_json FROM cases WHERE case_id=?", (int(case_id),)
        ).fetchone()
    if result is None:
        raise ValueError("Case not found")
    return json.loads(result[0])


def case_history(path: str | Path, case_id: int) -> pd.DataFrame:
    """Return chronological SOC state transitions; legacy cases may have none."""
    ensure_case_db(path)
    with sqlite3.connect(path) as conn:
        return pd.read_sql_query(
            "SELECT event_id,old_state,new_state,note,created_at "
            "FROM case_events WHERE case_id=? ORDER BY event_id",
            conn, params=(int(case_id),)
        )


def list_cases(path: str | Path) -> pd.DataFrame:
    ensure_case_db(path)
    with sqlite3.connect(path) as conn:
        return pd.read_sql_query(
            "SELECT case_id,flow_id,verdict,confidence,state,analyst_note,created_at,updated_at "
            "FROM cases ORDER BY case_id DESC", conn
        )


def update_case(path: str | Path, case_id: int, state: str, note: str) -> None:
    if state not in CASE_STATES:
        raise ValueError("Invalid case state")
    if not isinstance(note, str) or not 0 < len(note.strip()) <= 2000:
        raise ValueError("Analyst note must be 1..2000 non-whitespace characters")
    ensure_case_db(path)
    with sqlite3.connect(path) as conn:
        existing = conn.execute(
            "SELECT state FROM cases WHERE case_id=?", (int(case_id),)
        ).fetchone()
        if existing is None:
            raise ValueError("Case not found")
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE cases SET state=?, analyst_note=?, updated_at=? WHERE case_id=?",
            (state, note.strip(), now, int(case_id)),
        )
        conn.execute(
            """INSERT INTO case_events (case_id,old_state,new_state,note,created_at)
               VALUES (?,?,?,?,?)""",
            (int(case_id), existing[0], state, note.strip(), now),
        )
