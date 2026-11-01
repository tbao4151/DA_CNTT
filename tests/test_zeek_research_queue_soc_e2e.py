"""Synthetic-only end-to-end CLI regression: Zeek score -> queue -> SOC -> read-only link.

No VMware traffic, independent attack labels, or live detection is asserted.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from test_zeek_research_alert_bundle import _pinned_manual_handoff, _run


def _verification(tmp_path):
    triage, bundle, db, selected = _pinned_manual_handoff(tmp_path)
    created = _run(triage)
    assert created.returncode == 0, created.stderr
    with sqlite3.connect(db) as conn:
        case_id = conn.execute("SELECT case_id FROM cases").fetchone()[0]
    # Reuse exactly the original private paths/pins selected for manual triage.
    names = (
        "--model", "--expected-model-sha256", "--log",
        "--expected-log-sha256", "--report", "--manifest",
        "--expected-manifest-sha256", "--cidr", "--record-index",
        "--db",
    )
    args = []
    for name in names:
        args.extend((name, triage[triage.index(name) + 1]))
    base = [
        sys.executable, str(ROOT / "scripts" / "verify_zeek_soc_case_link.py"),
        *args, "--case-id", str(case_id),
    ]
    pinned = [
        "--research-alert-bundle", str(bundle),
        "--expected-research-alert-bundle-sha256",
        hashlib.sha256(bundle.read_bytes()).hexdigest(),
        "--research-alert-ref", selected["research_alert_ref"],
    ]
    return base, pinned, bundle, db, selected


def test_pinned_queue_to_unclassified_soc_case_to_read_only_verification(tmp_path):
    base, pinned, bundle, db, selected = _verification(tmp_path)
    before = db.read_bytes()
    checked = _run(base + pinned)
    assert checked.returncode == 0, checked.stderr
    assert "pinned_research_queue_reverified=true" in checked.stdout
    assert "candidate selection and creation audit" in checked.stdout
    assert "offline_soc_evidence_link_verified=true" in checked.stdout
    assert "sqlite_read_only=true" in checked.stdout
    assert "192.168.56." not in checked.stdout
    assert "NEW1" not in checked.stdout
    assert str(tmp_path) not in checked.stdout
    assert db.read_bytes() == before
    with sqlite3.connect(db) as conn:
        case = conn.execute(
            "SELECT verdict, confidence FROM cases"
        ).fetchone()
        assert case == ("Unclassified", None)
        assert conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM case_events").fetchone()[0] == 1
        note = conn.execute("SELECT note FROM case_events ORDER BY event_id LIMIT 1").fetchone()[0]
        assert "bundle_sha256=" + pinned[
            pinned.index("--expected-research-alert-bundle-sha256") + 1
        ] in note
        assert "research_alert_ref=" + selected["research_alert_ref"] in note

    timed = _run(base + pinned + ["--timing-json"])
    assert timed.returncode == 0, timed.stderr
    report = json.loads(timed.stdout)
    assert report["pinned_research_queue_reverified"] is True
    assert report["pinned_research_queue_creation_audit_verified"] is True
    assert report["sqlite_read_only"] is True
    assert report["operational_alert_verified"] is False
    assert report["event_to_soc_case_latency_measured"] is False
    assert report["stage_duration_ms"]["optional_pinned_research_queue_reverification"] >= 0
    assert db.read_bytes() == before

    # Existing CLI remains compatible without the new optional queue check.
    legacy = _run(base + ["--timing-json"])
    assert legacy.returncode == 0, legacy.stderr
    legacy_report = json.loads(legacy.stdout)
    assert legacy_report["pinned_research_queue_reverified"] is False
    assert "optional_pinned_research_queue_reverification" not in legacy_report["stage_duration_ms"]
    assert legacy_report["pinned_research_queue_creation_audit_verified"] is False
    assert db.read_bytes() == before


@pytest.mark.parametrize("change", [
    "wrong_digest", "wrong_reference", "missing_digest",
    "tampered_repin", "duplicate_key_repin", "wrong_index", "queue_is_report",
])
def test_queue_case_link_refuses_unverified_handoff_without_db_writes(tmp_path, change):
    base, pinned, bundle, db, selected = _verification(tmp_path)
    if change == "wrong_digest":
        pinned[pinned.index("--expected-research-alert-bundle-sha256") + 1] = "0" * 64
    elif change == "wrong_reference":
        pinned[pinned.index("--research-alert-ref") + 1] = "0" * 64
    elif change == "missing_digest":
        idx = pinned.index("--expected-research-alert-bundle-sha256")
        del pinned[idx:idx + 2]
    elif change == "tampered_repin":
        saved = json.loads(bundle.read_text(encoding="utf-8"))
        saved["research_alerts"][0]["soc_case_id"] = 999
        bundle.write_text(json.dumps(saved), encoding="utf-8")
        pinned[pinned.index("--expected-research-alert-bundle-sha256") + 1] = hashlib.sha256(
            bundle.read_bytes()
        ).hexdigest()
    elif change == "duplicate_key_repin":
        raw = bundle.read_text(encoding="utf-8")
        assert '"bundle_version": 1,' in raw
        bundle.write_text(raw.replace('"bundle_version": 1,',
                                      '"bundle_version": 1, "bundle_version": 1,', 1),
                          encoding="utf-8")
        pinned[pinned.index("--expected-research-alert-bundle-sha256") + 1] = hashlib.sha256(
            bundle.read_bytes()
        ).hexdigest()
    elif change == "wrong_index":
        base[base.index("--record-index") + 1] = "499"
    else:
        pinned[pinned.index("--research-alert-bundle") + 1] = base[
            base.index("--report") + 1
        ]

    before = db.read_bytes()
    refused = _run(base + pinned)
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert "verification refused" in refused.stderr
    assert "192.168.56." not in refused.stderr
    assert "NEW1" not in refused.stderr
    assert str(tmp_path) not in refused.stderr
    assert db.read_bytes() == before


@pytest.mark.parametrize("mutation", ["bundle_digest", "alert_reference", "remove_binding"])
def test_queue_creation_audit_pin_tampering_refused_without_writes(tmp_path, mutation):
    base, pinned, bundle, db, selected = _verification(tmp_path)
    digest = pinned[pinned.index("--expected-research-alert-bundle-sha256") + 1]
    clause = (
        "Pinned research queue selection rechecked: "
        f"bundle_sha256={digest}; "
        f"research_alert_ref={selected['research_alert_ref']}. "
    )
    with sqlite3.connect(db) as conn:
        note = conn.execute(
            "SELECT note FROM case_events ORDER BY event_id LIMIT 1"
        ).fetchone()[0]
        assert clause in note
        if mutation == "bundle_digest":
            altered = note.replace(clause, clause.replace(digest, "0" * 64))
        elif mutation == "alert_reference":
            altered = note.replace(
                clause, clause.replace(selected["research_alert_ref"], "0" * 64)
            )
        else:
            altered = note.replace(clause, "")
        conn.execute("UPDATE case_events SET note=? WHERE event_id=1", (altered,))
    before = db.read_bytes()
    refused = _run(base + pinned)
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert "verification refused" in refused.stderr
    assert str(tmp_path) not in refused.stderr
    assert db.read_bytes() == before
