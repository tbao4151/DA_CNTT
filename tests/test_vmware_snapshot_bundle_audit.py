"""Network-free, synthetic-only tests for the independent VMware snapshot auditor."""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from blue_team_ai.lab_scope import inspect_zeek_lab_scope
from blue_team_ai.zeek import parse_zeek_conn_log
from verify_vmware_snapshot_bundle import verify_bundle, main

BASE = "zeek_conn_20261119T050000Z_abcdef123456"


def _fixture(tmp_path):
    stamp = datetime(2026, 11, 19, 5, tzinfo=timezone.utc).timestamp()
    rows = [
        f"{stamp:.3f}\tCa\t192.168.77.1\t45678\t192.168.77.20\t22\ttcp",
        f"{stamp+1:.3f}\tCb\t192.168.77.1\t45679\t192.168.77.20\t22\ttcp",
    ]
    raw = ("#separator \\x09\n"
           "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
           + "\n".join(rows) + "\n").encode("utf-8")
    scope = inspect_zeek_lab_scope(raw, ["192.168.77.0/24"])
    source = tmp_path / (BASE + ".log")
    source.write_bytes(raw)
    receipt = tmp_path / (BASE + ".receipt.json")
    receipt_obj = {
        "version": 1, "capture_kind": "read_only_vmware_scp_snapshot_unverified",
        "local_log_filename": source.name, "log_sha256": hashlib.sha256(raw).hexdigest(),
        "remote_host": "192.168.77.20",
        "remote_path": "/opt/zeek/logs/current/conn.log",
        "declared_cidr": "192.168.77.0/24", "scope_screen_passed": True,
        "bytes": len(raw), "flow_count": 2,
        "first_event_utc": scope["first_event_utc"], "last_event_utc": scope["last_event_utc"],
        "host_only_isolation_verified": False, "capture_authenticity_verified": False,
        "attack_detection_performed": False, "red_team_execution_performed": False,
    }
    receipt.write_text(json.dumps(receipt_obj), encoding="utf-8")
    predictions = []
    for i, event in enumerate(parse_zeek_conn_log(raw)):
        predictions.append({
            field: event[field] for field in
            ("uid", "event_time_utc", "src_ip", "src_port", "dst_ip", "dst_port")
        } | {"attack_probability": 0.6 if i == 0 else 0.1,
             "research_candidate": i == 0})
    report_obj = {
        "report_version": 1, "mode": "offline_new_zeek_research_inference_only",
        "origin": "offline_zeek_log", "source_sha256": hashlib.sha256(raw).hexdigest(),
        "declared_scope_sha256": scope["declared_scope_sha256"], "model_sha256": "a" * 64,
        "flow_count": 2, "research_candidate_count": 1,
        "predictions": predictions,
    }
    for field in ("labels_used", "test_partition_exclusion_verified",
                  "host_only_isolation_verified", "capture_authenticity_verified",
                  "model_authorship_verified", "operational_attack_detection_verified",
                  "automated_alerts", "soc_cases_created", "live_capture"):
        report_obj[field] = False
    report = tmp_path / (BASE + ".research.json")
    report.write_text(json.dumps(report_obj), encoding="utf-8")
    return source, receipt, receipt_obj, report, report_obj


def test_receipt_only_rechecks_original_zeek_without_network(tmp_path):
    _, receipt, _, _, _ = _fixture(tmp_path)
    result = verify_bundle(receipt)
    assert result["flow_count"] == 2
    assert result["research_rows_matched_to_original_flows"] is False
    assert result["physical_vmware_isolation_verified"] is False
    assert result["attack_detection_verified"] is False


def test_report_rows_matched_to_exact_original_uid_and_scope(tmp_path):
    _, receipt, _, report, _ = _fixture(tmp_path)
    result = verify_bundle(
        receipt, research_report_path=report,
        expected_receipt_sha256=hashlib.sha256(receipt.read_bytes()).hexdigest(),
        expected_research_sha256=hashlib.sha256(report.read_bytes()).hexdigest(),
    )
    assert result["research_candidate_count"] == 1
    assert result["research_rows_matched_to_original_flows"] is True
    assert result["independent_receipt_digest_supplied"] is True
    assert result["independent_research_digest_supplied"] is True


@pytest.mark.parametrize("field,value", [
    ("flow_count", 100), ("bytes", 1), ("log_sha256", "f" * 64),
    ("scope_screen_passed", False), ("capture_authenticity_verified", True),
    ("declared_cidr", "192.168.78.0/24"),
    ("remote_host", "8.8.8.8"),
    ("remote_path", "/etc/passwd"),
])
def test_tampered_receipt_fails_closed(tmp_path, field, value):
    _, receipt, data, _, _ = _fixture(tmp_path)
    data[field] = value
    receipt.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_bundle(receipt)


@pytest.mark.parametrize("field,value", [
    ("source_sha256", "0"*64), ("research_candidate_count", 2),
    ("mode", "operational_alert"), ("automated_alerts", True),
    ("test_partition_exclusion_verified", True),
    ("model_sha256", "not_sha256"),
])
def test_tampered_research_fails_closed(tmp_path, field, value):
    _, receipt, _, report, data = _fixture(tmp_path)
    data[field] = value
    report.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_bundle(receipt, research_report_path=report)


def test_modified_original_zeek_is_rejected(tmp_path):
    source, receipt, _, _, _ = _fixture(tmp_path)
    source.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        verify_bundle(receipt)


def test_per_row_uid_and_probability_forgery_rejected(tmp_path):
    _, receipt, _, report, data = _fixture(tmp_path)
    data["predictions"][0]["uid"] = "unknown-uid"
    report.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_bundle(receipt, research_report_path=report)
    data["predictions"][0]["uid"] = "Ca"
    data["predictions"][0]["attack_probability"] = float("nan")
    report.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_bundle(receipt, research_report_path=report)


def test_reject_wrong_digest_wrong_name_and_other_bundle(tmp_path):
    _, receipt, _, report, _ = _fixture(tmp_path)
    with pytest.raises(ValueError):
        verify_bundle(receipt, expected_receipt_sha256="0" * 64)
    with pytest.raises(ValueError):
        verify_bundle(receipt, expected_research_sha256="0" * 64)
    fake = tmp_path / "other.research.json"
    fake.write_bytes(report.read_bytes())
    with pytest.raises(ValueError):
        verify_bundle(receipt, research_report_path=fake)


def test_duplicate_json_property_rejected(tmp_path):
    _, receipt, _, _, _ = _fixture(tmp_path)
    receipt.write_bytes(receipt.read_bytes().replace(
        b'"version": 1,', b'"version": 1, "version": 1,',
    ))
    with pytest.raises(ValueError, match="Duplicate"):
        verify_bundle(receipt)


def test_cli_is_read_only_and_returns_nonzero_on_failure(tmp_path, capsys):
    _, receipt, _, report, _ = _fixture(tmp_path)
    assert main(["--receipt", str(receipt), "--research-report", str(report)]) == 0
    stdout = capsys.readouterr().out
    assert '"mode": "offline_vmware_snapshot_byte_consistency_audit"' in stdout
    assert main(["--receipt", str(receipt), "--expected-receipt-sha256", "0"*64]) == 1
    assert "refused" in capsys.readouterr().err
