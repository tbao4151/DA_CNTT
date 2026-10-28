"""Synthetic SQLite-only tests; no genuine VMware/SOC detection evidence."""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from blue_team_ai.case_workspace import (
    list_private_zeek_cases, read_private_zeek_case,
)


def _make_db(path):
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE cases (case_id INTEGER PRIMARY KEY, flow_id TEXT,
                verdict TEXT, confidence REAL, state TEXT, analyst_note TEXT,
                evidence_json TEXT, created_at TEXT, updated_at TEXT);
            CREATE TABLE case_events (event_id INTEGER PRIMARY KEY,
                case_id INTEGER, old_state TEXT, new_state TEXT,
                note TEXT, created_at TEXT);
        """)
        for n, (verdict, evidence) in enumerate([
            ("Unclassified", {"origin": "offline_zeek_log", "uid": "C123", "source_sha256": "a" * 64}),
            ("Attack", {"origin": "offline_zeek_log", "uid": "C999"}),
            ("Unclassified", {"origin": "dataset", "uid": "other"}),
        ], 1):
            db.execute("INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?)", (
                n, "flow", verdict, None, "New", "Private note", json.dumps(evidence), "t0", "t0",
            ))
        db.execute("INSERT INTO case_events VALUES (1,1,NULL,'New','Created','t0')")
    return path


def test_read_only_index_and_snapshot_do_not_mutate_database(tmp_path):
    path = _make_db(tmp_path / "cases.sqlite3")
    before = path.read_bytes()
    listing = list_private_zeek_cases(path)
    assert [item["case_id"] for item in listing["cases"]] == [1]
    report = read_private_zeek_case(path, 1)
    assert report["case"]["verdict"] == "Unclassified"
    assert report["flow_evidence"]["uid"] == "C123"
    assert [e["new_state"] for e in report["case_events"]] == ["New"]
    assert report["history_truncated"] is False
    assert path.read_bytes() == before
    assert not (tmp_path / "cases.sqlite3-wal").exists()


def test_refuse_missing_invalid_and_non_zeek(tmp_path):
    path = tmp_path / "missing.sqlite3"
    with pytest.raises((ValueError, OSError)):
        list_private_zeek_cases(path)
    assert not path.exists()
    path.write_text("not sqlite", encoding="utf-8")
    with pytest.raises(ValueError, match="SQLite"):
        list_private_zeek_cases(path)
    path.unlink()
    _make_db(path)
    for case_id in (2, 3, 999, 0, True, "1"):
        with pytest.raises(ValueError):
            read_private_zeek_case(path, case_id)
    alias = tmp_path / "alias.sqlite3"
    alias.symlink_to(path)
    with pytest.raises(ValueError, match="symlink"):
        list_private_zeek_cases(alias)


def test_history_is_bounded_and_chronological(tmp_path):
    path = _make_db(tmp_path / "cases.sqlite3")
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT INTO case_events VALUES (?,?,?,?,?,?)",
            [(i, 1, "New", "Investigating", f"note-{i}", "t1") for i in range(2, 214)],
        )
    report = read_private_zeek_case(path, 1)
    assert report["history_truncated"] is True
    assert len(report["case_events"]) == 200
    assert report["case_events"][0]["event_id"] == 14
    assert report["case_events"][-1]["event_id"] == 213


def test_index_is_bounded(tmp_path):
    path = _make_db(tmp_path / "cases.sqlite3")
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?)",
            [(i, "flow", "Unclassified", None, "New", "",
              json.dumps({"origin": "offline_zeek_log", "uid": str(i)}), "t0", "t0")
             for i in range(4, 160)],
        )
    listing = list_private_zeek_cases(path)
    assert len(listing["cases"]) == 100
    assert listing["limited"] is True
