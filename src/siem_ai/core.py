"""Schema validation, deterministic alert identifiers and local SOC case store.

UNSW-NB15 train/test split has 45 columns, no timestamps/IPs.
ATTACK_LABELS ARE GROUND TRUTH — never pass them as model features.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

LABEL_FIELDS = frozenset({"id", "label", "attack_cat"})
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
    features = {str(k): str(v)[:256] for k, v in row.items() if k not in LABEL_FIELDS}
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


def create_case(path: str | Path, *, row: dict, verdict: str, confidence: float | None) -> int:
    ensure_case_db(path)
    if verdict not in ("Attack", "Normal", "Unclassified"):
        raise ValueError("Invalid verdict")
    if confidence is not None and not (0 <= confidence <= 1):
        raise ValueError("Confidence must be in [0,1]")
    evidence = {
        k: str(row[k])[:256] for k in ("proto", "service", "state", "dur", "sbytes", "dbytes", "rate")
        if k in row
    }
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(path) as conn:
        cursor = conn.execute(
            """INSERT INTO cases (flow_id,verdict,confidence,evidence_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?)""",
            (flow_id(row), verdict, confidence, json.dumps(evidence), now, now),
        )
        return int(cursor.lastrowid)


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
    if not 0 < len(note) <= 2000:
        raise ValueError("Analyst note must be 1..2000 characters")
    with sqlite3.connect(path) as conn:
        cursor = conn.execute(
            "UPDATE cases SET state=?, analyst_note=?, updated_at=? WHERE case_id=?",
            (state, note.strip(), datetime.now(timezone.utc).isoformat(), int(case_id)),
        )
        if cursor.rowcount != 1:
            raise ValueError("Case not found")
