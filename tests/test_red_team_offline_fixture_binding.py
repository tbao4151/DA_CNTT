"""Synthetic-only Red Team offline evidence binding tests; no traffic or Zeek execution."""
from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.lab_scope import inspect_zeek_lab_scope
from red_team_ai.offline_fixture_binding import bind_pending_offline_fixture
from red_team_ai.planning_audit import append_manual_feedback, append_proposal, export_planning_audit
from red_team_ai.scenario_policy import choose_scenario
from test_zeek_telemetry import VALUES, log

CIDR = ["192.168.56.0/24"]


@pytest.fixture
def evidence(tmp_path):
    audit_events = append_proposal(
        [], choose_scenario([]), seed=42, recorded_at_utc="2026-10-31T01:00:00+00:00",
    )
    audit = tmp_path / "red-team-audit.json"
    audit.write_text(json.dumps(export_planning_audit(audit_events)), encoding="utf-8")
    pcap = tmp_path / "original.pcap"
    raw_pcap = (
        bytes.fromhex("d4c3b2a1")
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 100, 123, 4, 4) + b"test"
    )
    pcap.write_bytes(raw_pcap)
    output = tmp_path / "zeek"
    output.mkdir()
    conn = output / "conn.log"
    raw_conn = log(VALUES)
    conn.write_bytes(raw_conn)
    scope = inspect_zeek_lab_scope(raw_conn, CIDR)
    report = output / "offline_import_report.json"
    record = {
        "report_version": 1,
        "mode": "offline_classic_pcap_to_zeek_import",
        "source_kind": "operator_supplied_offline_pcap",
        "pcap_sha256": hashlib.sha256(raw_pcap).hexdigest(),
        "pcap_size_bytes": len(raw_pcap),
        "zeek_conn_sha256": hashlib.sha256(raw_conn).hexdigest(),
        "zeek_conn_size_bytes": len(raw_conn),
        "flow_count": scope["flow_count"],
        "declared_scope_sha256": scope["declared_scope_sha256"],
        "all_endpoints_within_declared_scope": True,
        "interpretation": "Synthetic test import, not an authenticated capture.",
    }
    record.update({key: False for key in (
        "host_only_isolation_verified", "capture_authenticity_verified",
        "authorization_verified", "ground_truth_verified",
        "ai_inference_performed", "automated_alerts", "live_capture",
    )})
    report.write_text(json.dumps(record), encoding="utf-8")
    return {"audit": audit, "pcap": pcap, "log": conn, "report": report}


def bind(item, **changes):
    audit_data = item["audit"].read_bytes()
    params = {
        "audit_data": audit_data,
        "expected_audit_sha256": hashlib.sha256(audit_data).hexdigest(),
        "import_report_path": item["report"],
        "expected_import_report_sha256": hashlib.sha256(item["report"].read_bytes()).hexdigest(),
        "pcap_path": item["pcap"],
        "conn_log_path": item["log"],
        "lab_cidrs": CIDR,
        "operator_confirmed_authorized": True,
        "operator_confirmed_offline": True,
        "operator_confirmed_fixture_reviewed": True,
    }
    params.update(changes)
    return bind_pending_offline_fixture(**params)


def test_pending_policy_proposal_binds_to_pinned_offline_evidence(evidence):
    result = bind(evidence)
    assert result["scenario_id"] == "baseline_web"
    assert result["proposal_id"] == 1
    assert result["pcap_packet_count"] == 1
    assert result["zeek_flow_count"] == 1
    assert result["pcap_framing_verified"] is True
    for key in (
        "independent_authorization_verified", "physical_host_only_isolation_verified",
        "capture_authenticity_verified", "scenario_traffic_match_verified",
        "ground_truth_verified", "blue_team_detection_verified",
        "replay_executed", "execution_enabled", "network_access", "soc_cases_created",
    ):
        assert result[key] is False
    assert str(evidence["pcap"]) not in json.dumps(result)


@pytest.mark.parametrize("key", [
    "operator_confirmed_authorized", "operator_confirmed_offline",
    "operator_confirmed_fixture_reviewed",
])
def test_explicit_confirmations_required(evidence, key):
    with pytest.raises(ValueError, match="confirmations"):
        bind(evidence, **{key: False})


def test_changed_audit_rejected_before_reading_evidence(evidence):
    audit = json.loads(evidence["audit"].read_text())
    audit["events"][0]["scenario_id"] = "dns_variation"
    evidence["audit"].write_text(json.dumps(audit), encoding="utf-8")
    with pytest.raises(ValueError, match="policy"):
        bind(evidence)


def test_re_pinned_misleading_audit_summary_rejected(evidence):
    audit = json.loads(evidence["audit"].read_text())
    audit["network_access"] = True
    evidence["audit"].write_text(json.dumps(audit), encoding="utf-8")
    with pytest.raises(ValueError, match="differs"):
        bind(evidence)


def test_no_pending_proposal_rejected(evidence):
    audit = json.loads(evidence["audit"].read_text())
    events = append_manual_feedback(
        audit["events"], proposal_id=1, blue_flagged=False,
        recorded_at_utc="2026-10-31T01:01:00+00:00",
    )
    evidence["audit"].write_text(json.dumps(export_planning_audit(events)), encoding="utf-8")
    with pytest.raises(ValueError, match="outstanding"):
        bind(evidence)


@pytest.mark.parametrize("target", ["pcap", "log", "report"])
def test_tampered_original_refused(evidence, target):
    evidence[target].write_bytes(evidence[target].read_bytes() + b"tampered")
    with pytest.raises(ValueError):
        bind(evidence)


def test_wrong_declared_scope_refused(evidence):
    with pytest.raises(ValueError):
        bind(evidence, lab_cidrs=["192.168.57.0/24"])


def test_audit_sha_pin_required(evidence):
    with pytest.raises(ValueError, match="audit SHA"):
        bind(evidence, expected_audit_sha256="0" * 64)


def test_read_only_cli_and_fail_closed_without_confirmation(evidence):
    files = {key: evidence[key].read_bytes() for key in evidence}
    cmd = [
        sys.executable, str(ROOT / "scripts/bind_red_team_offline_fixture.py"),
        "--audit", str(evidence["audit"]),
        "--expected-audit-sha256", hashlib.sha256(files["audit"]).hexdigest(),
        "--report", str(evidence["report"]),
        "--expected-report-sha256", hashlib.sha256(files["report"]).hexdigest(),
        "--pcap", str(evidence["pcap"]), "--log", str(evidence["log"]),
        "--cidr", CIDR[0],
    ]
    failed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert failed.returncode == 1
    assert "Refused" in failed.stderr
    ok = subprocess.run(
        cmd + ["--confirm-authorized", "--confirm-offline-only", "--confirm-fixture-reviewed"],
        capture_output=True, text=True, check=False,
    )
    assert ok.returncode == 0, ok.stderr
    result = json.loads(ok.stdout)
    assert result["network_access"] is False
    assert result["scenario_traffic_match_verified"] is False
    assert all(evidence[key].read_bytes() == original for key, original in files.items())
