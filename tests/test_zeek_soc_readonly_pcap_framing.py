"""Synthetic-only read-only SOC PCAP framing recheck contract.

This is not an actual VMware capture, packet-to-Zeek match or attack detection.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
import sys
from pathlib import Path

from test_zeek_research_alert_bundle import _pinned_manual_handoff, _run

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.lab_scope import inspect_zeek_lab_scope


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _prepare(tmp_path: Path):
    triage, bundle, db, selected = _pinned_manual_handoff(tmp_path)
    log = Path(triage[triage.index("--log") + 1])
    log_bytes = log.read_bytes()
    scope = inspect_zeek_lab_scope(log_bytes, ["192.168.56.0/24"])

    # A structurally framed synthetic packet; intentionally NOT a Zeek tuple.
    pcap = tmp_path / "original.pcap"
    raw = (
        bytes.fromhex("d4c3b2a1")
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 100, 123, 4, 4) + b"test"
    )
    pcap.write_bytes(raw)
    import_report = log.parent / "offline_import_report.json"
    report = {
        "report_version": 1,
        "mode": "offline_classic_pcap_to_zeek_import",
        "source_kind": "operator_supplied_offline_pcap",
        "pcap_sha256": _sha(raw),
        "pcap_size_bytes": len(raw),
        "zeek_conn_sha256": _sha(log_bytes),
        "zeek_conn_size_bytes": len(log_bytes),
        "flow_count": scope["flow_count"],
        "declared_scope_sha256": scope["declared_scope_sha256"],
        "all_endpoints_within_declared_scope": True,
        "interpretation": "Synthetic-only import consistency; not a genuine capture.",
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "authorization_verified": False,
        "ground_truth_verified": False,
        "ai_inference_performed": False,
        "automated_alerts": False,
        "live_capture": False,
    }
    import_report.write_text(json.dumps(report), encoding="utf-8")
    provenance = [
        "--offline-import-report", str(import_report),
        "--expected-offline-import-report-sha256", _sha(import_report.read_bytes()),
        "--offline-import-pcap", str(pcap),
    ]
    created = _run(triage + provenance)
    assert created.returncode == 0, created.stderr
    with sqlite3.connect(db) as conn:
        case_id = conn.execute("SELECT case_id FROM cases").fetchone()[0]
    names = (
        "--model", "--expected-model-sha256", "--log",
        "--expected-log-sha256", "--report", "--manifest",
        "--expected-manifest-sha256", "--cidr", "--record-index", "--db",
    )
    verify = [sys.executable, str(ROOT / "scripts/verify_zeek_soc_case_link.py")]
    for name in names:
        verify.extend((name, triage[triage.index(name) + 1]))
    verify.extend(("--case-id", str(case_id)))
    return verify, provenance, db, pcap, import_report


def test_strict_soc_readonly_pcap_framing_recheck_and_legacy_mode(tmp_path):
    verify, provenance, db, pcap, import_report = _prepare(tmp_path)
    before = {p: p.read_bytes() for p in (db, pcap, import_report)}
    legacy = _run(verify + provenance + ["--timing-json"])
    assert legacy.returncode == 0, legacy.stderr
    old = json.loads(legacy.stdout)
    assert old["pcap_framing_required"] is False
    assert old["pcap_framing_verified"] is False
    assert old["pcap_packet_count"] is None

    strict = _run(verify + provenance + ["--require-pcap-framing", "--timing-json"])
    assert strict.returncode == 0, strict.stderr
    report = json.loads(strict.stdout)
    assert report["pcap_framing_required"] is True
    assert report["pcap_framing_verified"] is True
    assert report["pcap_packet_count"] == 1
    assert report["sqlite_read_only"] is True
    assert report["event_to_soc_case_latency_measured"] is False
    assert report["operational_alert_verified"] is False
    plain = _run(verify + provenance + ["--require-pcap-framing"])
    assert plain.returncode == 0, plain.stderr
    assert "offline_pcap_packet_framing_reverified=true" in plain.stdout
    assert "NOT packet-to-Zeek correlation" in plain.stdout
    assert all(p.read_bytes() == raw for p, raw in before.items())


def test_strict_soc_readonly_framing_requires_complete_pinned_provenance(tmp_path):
    verify, provenance, db, pcap, import_report = _prepare(tmp_path)
    before = db.read_bytes()
    for args in (
        ["--require-pcap-framing"],
        provenance[:-2] + ["--require-pcap-framing"],
    ):
        refused = _run(verify + args)
        assert refused.returncode == 1
        assert refused.stdout == ""
        assert "verification refused" in refused.stderr
        assert str(tmp_path) not in refused.stderr
    assert db.read_bytes() == before


def test_strict_soc_readonly_rejects_repinned_header_only_pcap(tmp_path):
    verify, provenance, db, pcap, import_report = _prepare(tmp_path)
    before = db.read_bytes()
    header_only = bytes.fromhex("d4c3b2a1") + struct.pack(
        "<HHIIII", 2, 4, 0, 0, 65535, 1,
    )
    pcap.write_bytes(header_only)
    payload = json.loads(import_report.read_text(encoding="utf-8"))
    payload["pcap_sha256"] = _sha(header_only)
    payload["pcap_size_bytes"] = len(header_only)
    import_report.write_text(json.dumps(payload), encoding="utf-8")
    provenance[provenance.index("--expected-offline-import-report-sha256") + 1] = (
        _sha(import_report.read_bytes())
    )
    refused = _run(verify + provenance + ["--require-pcap-framing"])
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert "verification refused" in refused.stderr
    assert str(tmp_path) not in refused.stderr
    assert db.read_bytes() == before
