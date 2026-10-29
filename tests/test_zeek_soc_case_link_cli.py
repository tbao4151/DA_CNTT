"""Synthetic-only end-to-end CLI regressions for pinned NEW-log SOC evidence links."""
from __future__ import annotations

import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from siem_ai.core import update_case
from test_zeek_new_log_partition_triage import _setup

ROOT = Path(__file__).resolve().parents[1]


def _run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


def _case_and_command(tmp_path):
    manifest, _, _, _, _, index, base, pinned = _setup(tmp_path)
    db = manifest.parent / "cases.sqlite3"
    created = _run(base + pinned + [
        "--record-index", str(index), "--db", str(db),
        "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture",
    ])
    assert created.returncode == 0, created.stderr
    with sqlite3.connect(db) as conn:
        case_id = conn.execute("SELECT case_id FROM cases").fetchone()[0]
    verify = [
        sys.executable, str(ROOT / "scripts" / "verify_zeek_soc_case_link.py"),
        *base[2:], *pinned,
        "--db", str(db), "--case-id", str(case_id),
        "--record-index", str(index),
    ]
    return manifest, db, case_id, verify


def test_pinned_case_cli_rechecks_without_modifying_database(tmp_path):
    _, db, case_id, verify = _case_and_command(tmp_path)
    before = db.read_bytes()
    checked = _run(verify)
    assert checked.returncode == 0, checked.stderr
    assert "offline_soc_evidence_link_verified=true" in checked.stdout
    assert "pinned_declared_partitions_screened=true" in checked.stdout
    assert "sqlite_read_only=true" in checked.stdout
    assert "192.168.56" not in checked.stdout
    assert "NEW1" not in checked.stdout
    assert db.read_bytes() == before
    update_case(db, case_id, "Investigating", "Independent review pending")
    assert _run(verify).returncode == 0


@pytest.mark.parametrize("change", [
    "case", "audit", "annotation", "manifest", "report", "missing_db",
    "wrong_model_pin", "wrong_log_pin", "partial_pcap", "invalid_case_id",
    "audit_extra_claim", "audit_manifest_pin",
])
def test_pinned_case_cli_fails_closed_without_private_details(tmp_path, change):
    manifest, db, case_id, verify = _case_and_command(tmp_path)
    if change in ("case", "audit"):
        with sqlite3.connect(db) as conn:
            if change == "case":
                conn.execute("UPDATE cases SET evidence_json=? WHERE case_id=?",
                             ('{"uid":"tampered"}', case_id))
            else:
                conn.execute("UPDATE case_events SET note=? WHERE case_id=?",
                             ("tampered", case_id))
    elif change in ("audit_extra_claim", "audit_manifest_pin"):
        with sqlite3.connect(db) as conn:
            note = conn.execute(
                "SELECT note FROM case_events WHERE case_id=? ORDER BY event_id LIMIT 1",
                (case_id,),
            ).fetchone()[0]
            if change == "audit_extra_claim":
                altered = note.replace(
                    "Authorization, Host-only isolation",
                    "Independently verified attack. Authorization, Host-only isolation",
                )
            else:
                altered = re.sub(
                    r"manifest_sha256=[0-9a-f]{64}",
                    "manifest_sha256=" + "0" * 64,
                    note,
                    count=1,
                )
            assert altered != note
            conn.execute(
                "UPDATE case_events SET note=? WHERE case_id=?",
                (altered, case_id),
            )
    elif change == "annotation":
        labels = manifest.parent / "host-0-labels.json"
        labels.write_bytes(labels.read_bytes() + b"\n")
    elif change == "manifest":
        manifest.write_bytes(manifest.read_bytes() + b"\n")
    elif change == "report":
        report = Path(verify[verify.index("--report") + 1])
        report.write_bytes(report.read_bytes() + b"\n")
    elif change == "missing_db":
        verify[verify.index("--db") + 1] = str(tmp_path / "missing.sqlite3")
    elif change == "wrong_model_pin":
        verify[verify.index("--expected-model-sha256") + 1] = "0" * 64
    elif change == "wrong_log_pin":
        verify[verify.index("--expected-log-sha256") + 1] = "0" * 64
    elif change == "partial_pcap":
        verify += ["--offline-import-report", str(manifest)]
    elif change == "invalid_case_id":
        verify[verify.index("--case-id") + 1] = "0"
    before = db.read_bytes()
    refused = _run(verify)
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert "verification refused" in refused.stderr
    assert str(tmp_path) not in refused.stderr
    assert "192.168.56" not in refused.stderr
    assert "NEW1" not in refused.stderr
    assert db.read_bytes() == before
    assert not (tmp_path / "missing.sqlite3").exists()
