"""Synthetic-only read-only SOC PCAP framing recheck contract.

This is not an actual VMware capture, packet-to-Zeek match or attack detection.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
import sys
from datetime import datetime
from pathlib import Path

from test_zeek_research_alert_bundle import _pinned_manual_handoff, _run
from test_pcap_zeek_tuple import pcap_packet

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.lab_scope import inspect_zeek_lab_scope
from blue_team_ai.zeek import parse_zeek_conn_log


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _prepare(tmp_path: Path, *, matching_pcap: bool = False, timestamp_offset: int = 0):
    triage, bundle, db, selected = _pinned_manual_handoff(tmp_path)
    log = Path(triage[triage.index("--log") + 1])
    log_bytes = log.read_bytes()
    # The research helper names this file new-conn.log; the original offline
    # PCAP import contract requires the exact basename conn.log. Make a
    # byte-identical synthetic-only copy and point triage at that copy.
    # The research queue and independent SHA pins remain byte-consistent.
    conn = log.with_name("conn.log")
    assert not conn.exists()
    conn.write_bytes(log_bytes)
    triage[triage.index("--log") + 1] = str(conn)
    log = conn
    scope = inspect_zeek_lab_scope(log_bytes, ["192.168.56.0/24"])

    # A structurally framed synthetic packet; intentionally NOT a Zeek tuple.
    pcap = tmp_path / "original.pcap"
    header = bytes.fromhex("d4c3b2a1") + struct.pack(
        "<HHIIII", 2, 4, 0, 0, 65535, 1,
    )
    if matching_pcap:
        # Construct packet headers from the two synthetic Zeek rows; the
        # bytes are fixtures, not a capture or evidence Zeek generated them.
        records = []
        for event in parse_zeek_conn_log(log_bytes):
            packet = pcap_packet(
                src=event["src_ip"], dst=event["dst_ip"],
                sport=event["src_port"], dport=event["dst_port"],
                proto=6 if event["proto"] == "tcp" else 17,
            )
            stamp = datetime.fromisoformat(event["event_time_utc"]).timestamp()
            seconds = int(stamp) + timestamp_offset
            micros = round((stamp - int(stamp)) * 1_000_000)
            records.append(
                struct.pack("<IIII", seconds, micros, len(packet), len(packet))
                + packet
            )
        raw = header + b"".join(records)
    else:
        # Valid framing, deliberately NOT an Ethernet/Zeek tuple match.
        raw = header + struct.pack("<IIII", 100, 123, 4, 4) + b"test"
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
        provenance[:4] + ["--require-pcap-framing"],
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


def test_soc_readonly_opt_in_tuple_and_timestamp_corroboration(tmp_path):
    verify, provenance, db, pcap, import_report = _prepare(
        tmp_path, matching_pcap=True,
    )
    before = {p: p.read_bytes() for p in (db, pcap, import_report)}
    legacy = _run(verify + provenance + ["--timing-json"])
    assert legacy.returncode == 0, legacy.stderr
    old = json.loads(legacy.stdout)
    assert old["pcap_zeek_tuples_required"] is False
    assert old["pcap_zeek_tuples_corroborated"] is False
    assert old["pcap_zeek_matched_flow_count"] is None

    strict = _run(verify + provenance + [
        "--require-pcap-zeek-tuples", "--require-pcap-zeek-timestamps", "--timing-json",
    ])
    assert strict.returncode == 0, strict.stderr
    report = json.loads(strict.stdout)
    assert report["pcap_framing_verified"] is True
    assert report["pcap_packet_count"] == 2
    assert report["pcap_zeek_tuples_corroborated"] is True
    assert report["pcap_zeek_timestamps_corroborated"] is True
    assert report["pcap_zeek_matched_flow_count"] == 2
    assert report["packet_to_flow_identity_verified"] is False
    assert report["attack_ground_truth_verified"] is False
    assert report["event_to_soc_case_latency_measured"] is False
    plain = _run(verify + provenance + [
        "--require-pcap-zeek-tuples", "--require-pcap-zeek-timestamps",
    ])
    assert plain.returncode == 0, plain.stderr
    assert "NOT packet-to-flow identity" in plain.stdout
    assert "within 1 second only" in plain.stdout
    assert all(path.read_bytes() == data for path, data in before.items())


def test_soc_readonly_tuple_gate_refuses_framed_but_unrelated_packet(tmp_path):
    verify, provenance, db, pcap, import_report = _prepare(tmp_path)
    before = db.read_bytes()
    framing = _run(verify + provenance + ["--require-pcap-framing"])
    assert framing.returncode == 0, framing.stderr
    refused = _run(verify + provenance + ["--require-pcap-zeek-tuples"])
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert "verification refused" in refused.stderr
    assert str(tmp_path) not in refused.stderr
    assert db.read_bytes() == before


def test_soc_readonly_timestamp_gate_rejects_distant_matching_tuples(tmp_path):
    verify, provenance, db, pcap, import_report = _prepare(
        tmp_path, matching_pcap=True, timestamp_offset=10,
    )
    before = db.read_bytes()
    tuples = _run(verify + provenance + ["--require-pcap-zeek-tuples"])
    assert tuples.returncode == 0, tuples.stderr
    refused = _run(verify + provenance + [
        "--require-pcap-zeek-tuples", "--require-pcap-zeek-timestamps",
    ])
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert "verification refused" in refused.stderr
    assert db.read_bytes() == before


def test_soc_readonly_tuple_flags_require_complete_provenance(tmp_path):
    verify, provenance, db, pcap, import_report = _prepare(
        tmp_path, matching_pcap=True,
    )
    before = db.read_bytes()
    for options in (
        ["--require-pcap-zeek-tuples"],
        provenance[:4] + ["--require-pcap-zeek-tuples"],
        provenance + ["--require-pcap-zeek-timestamps"],
    ):
        refused = _run(verify + options)
        assert refused.returncode == 1
        assert refused.stdout == ""
        assert "verification refused" in refused.stderr
        assert str(tmp_path) not in refused.stderr
    assert db.read_bytes() == before


def test_soc_readonly_opt_in_distinct_pcap_packet_records(tmp_path):
    verify, provenance, db, pcap, import_report = _prepare(
        tmp_path, matching_pcap=True,
    )
    before = {path: path.read_bytes() for path in (db, pcap, import_report)}
    strict = _run(verify + provenance + [
        "--require-pcap-zeek-tuples", "--require-pcap-zeek-timestamps",
        "--require-distinct-pcap-packets", "--timing-json",
    ])
    assert strict.returncode == 0, strict.stderr
    report = json.loads(strict.stdout)
    assert report["distinct_pcap_packets_required"] is True
    assert report["distinct_pcap_packets_corroborated"] is True
    assert report["pcap_zeek_matched_flow_count"] == 2
    assert report["distinct_pcap_assigned_offset_p95_ms"] is not None
    assert report["packet_to_flow_identity_verified"] is False
    legacy = _run(verify + provenance + ["--timing-json"])
    assert legacy.returncode == 0, legacy.stderr
    old = json.loads(legacy.stdout)
    assert old["distinct_pcap_packets_required"] is False
    assert old["distinct_pcap_packets_corroborated"] is False
    assert old["distinct_pcap_assigned_offset_p95_ms"] is None
    plain = _run(verify + provenance + [
        "--require-pcap-zeek-tuples", "--require-pcap-zeek-timestamps",
        "--require-distinct-pcap-packets",
    ])
    assert plain.returncode == 0, plain.stderr
    assert "offline_distinct_pcap_packet_records_corroborated=true" in plain.stdout
    assert all(path.read_bytes() == raw for path, raw in before.items())


def test_soc_readonly_distinct_packet_flag_fails_closed_without_dependencies(tmp_path):
    verify, provenance, db, pcap, import_report = _prepare(
        tmp_path, matching_pcap=True,
    )
    before = db.read_bytes()
    for flags in (
        ["--require-distinct-pcap-packets"],
        ["--require-pcap-zeek-tuples", "--require-distinct-pcap-packets"],
        ["--require-pcap-zeek-timestamps", "--require-distinct-pcap-packets"],
    ):
        refused = _run(verify + provenance + flags)
        assert refused.returncode == 1
        assert refused.stdout == ""
        assert "verification refused" in refused.stderr
        assert str(tmp_path) not in refused.stderr
    refused = _run(verify + [
        "--require-pcap-zeek-tuples", "--require-pcap-zeek-timestamps",
        "--require-distinct-pcap-packets",
    ])
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert db.read_bytes() == before
