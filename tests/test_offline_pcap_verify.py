"""Synthetic-only pinned verification tests; no real Zeek, PCAP capture or VMware."""
from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai import offline_pcap
from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import
from test_zeek_telemetry import VALUES, log

CIDR = ["192.168.56.0/24"]


@pytest.fixture
def imported(tmp_path, monkeypatch):
    pcap = tmp_path / "original.pcap"
    pcap.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 20)
    def fake_zeek(argv, **kwargs):
        assert argv == ["zeek", "-r", str(pcap)]
        (Path(kwargs["cwd"]) / "conn.log").write_bytes(log(VALUES))
        return SimpleNamespace(returncode=0)
    real_run = subprocess.run
    monkeypatch.setattr(offline_pcap.subprocess, "run", fake_zeek)
    destination = tmp_path / "zeek-output"
    try:
        offline_pcap.import_offline_pcap(
            pcap, destination, lab_cidrs=CIDR, operator_confirmed_offline=True,
        )
    finally:
        # offline_pcap.subprocess is the global subprocess module. Restore
        # run before exercising the real CLI in a child Python interpreter.
        monkeypatch.setattr(offline_pcap.subprocess, "run", real_run)
    report = destination / "offline_import_report.json"
    return {
        "pcap": pcap,
        "log": destination / "conn.log",
        "report": report,
        "pin": hashlib.sha256(report.read_bytes()).hexdigest(),
    }


def check(item, **overrides):
    params = {
        "report_path": item["report"],
        "expected_report_sha256": item["pin"],
        "pcap_path": item["pcap"],
        "log_path": item["log"],
        "lab_cidrs": CIDR,
    }
    params.update(overrides)
    return verify_offline_pcap_import(**params)


def repin(item, report):
    item["report"].write_text(json.dumps(report), encoding="utf-8")
    item["pin"] = hashlib.sha256(item["report"].read_bytes()).hexdigest()


def test_verified_originals_and_offline_flags(imported):
    result = check(imported)
    assert result["flow_count"] == 1
    assert result["original_files_verified"] == 2
    assert result["report_sha256"] == imported["pin"]
    assert all(result[key] is False for key in (
        "host_only_isolation_verified", "capture_authenticity_verified",
        "authorization_verified", "ground_truth_verified",
        "ai_inference_performed", "automated_alerts", "live_capture",
    ))


@pytest.mark.parametrize("changed", ["pcap", "log", "report"])
def test_changed_original_or_report_is_rejected(imported, changed):
    imported[changed].write_bytes(imported[changed].read_bytes() + b"tampered")
    with pytest.raises(ValueError):
        check(imported)


@pytest.mark.parametrize("field,value", [
    ("mode", "live_network_capture"),
    ("host_only_isolation_verified", True),
    ("ai_inference_performed", True),
    ("flow_count", 100),
    ("declared_scope_sha256", "0" * 64),
    ("pcap_size_bytes", True),
])
def test_re_pinned_misleading_report_is_rejected(imported, field, value):
    report = json.loads(imported["report"].read_text())
    report[field] = value
    repin(imported, report)
    with pytest.raises(ValueError):
        check(imported)


def test_re_pinned_pcap_magic_change_is_rejected(imported):
    raw = imported["pcap"].read_bytes()
    imported["pcap"].write_bytes(b"BAD!" + raw[4:])
    report = json.loads(imported["report"].read_text())
    report["pcap_sha256"] = hashlib.sha256(imported["pcap"].read_bytes()).hexdigest()
    repin(imported, report)
    with pytest.raises(ValueError, match="classic PCAP"):
        check(imported)


def test_report_duplicate_keys_rejected_even_if_re_pinned(imported):
    raw = imported["report"].read_bytes()
    imported["report"].write_bytes(b'{"report_version": 1,' + raw.lstrip()[1:])
    imported["pin"] = hashlib.sha256(imported["report"].read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="Duplicate"):
        check(imported)


@pytest.mark.parametrize("bad", ["bad_pin", "wrong_scope", "same_file", "missing_file"])
def test_refuse_untrusted_inputs(imported, bad):
    overrides = {}
    if bad == "bad_pin":
        overrides["expected_report_sha256"] = "0" * 64
    elif bad == "wrong_scope":
        overrides["lab_cidrs"] = ["192.168.57.0/24"]
    elif bad == "same_file":
        overrides["pcap_path"] = imported["log"]
    else:
        overrides["pcap_path"] = imported["pcap"].parent / "missing.pcap"
    with pytest.raises((ValueError, FileNotFoundError)):
        check(imported, **overrides)


def test_symlinked_report_refused(imported):
    alias_dir = imported["report"].parent.parent / "alias-dir"
    alias_dir.mkdir()
    alias = alias_dir / "offline_import_report.json"
    alias.symlink_to(imported["report"])
    with pytest.raises(ValueError, match="symlink"):
        check(imported, report_path=alias)


def test_cli_verifies_without_network_or_writes(imported):
    before = {key: imported[key].read_bytes() for key in ("pcap", "log", "report")}
    command = [
        sys.executable, str(ROOT / "scripts" / "verify_offline_pcap_import.py"),
        "--report", str(imported["report"]),
        "--expected-report-sha256", imported["pin"],
        "--pcap", str(imported["pcap"]),
        "--log", str(imported["log"]),
        "--cidr", CIDR[0],
    ]
    ok = subprocess.run(command, capture_output=True, text=True, check=False)
    assert ok.returncode == 0, ok.stderr
    assert "NOT verified" in ok.stdout
    failed = subprocess.run(
        command[:-1] + ["192.168.57.0/24"],
        capture_output=True, text=True, check=False,
    )
    assert failed.returncode == 1
    assert "refused" in failed.stderr
    assert str(imported["pcap"]) not in failed.stderr
    assert all(imported[key].read_bytes() == data for key, data in before.items())


def test_strict_framing_refuses_header_only_legacy_fixture(imported):
    # Legacy mock fixture has only a magic and 20 zero bytes; its report
    # can pass byte-consistency checks but not a structural packet check.
    assert check(imported)["pcap_framing_verified"] is False
    with pytest.raises(ValueError, match="no packet"):
        check(imported, require_pcap_framing=True)


def test_strict_framing_accepts_well_formed_pinned_packet_records(imported):
    # No packet-to-Zeek semantic match is asserted by this synthetic fixture.
    raw = (bytes.fromhex("d4c3b2a1")
           + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
           + struct.pack("<IIII", 100, 123, 4, 4) + b"test")
    imported["pcap"].write_bytes(raw)
    report = json.loads(imported["report"].read_text())
    report["pcap_sha256"] = hashlib.sha256(raw).hexdigest()
    report["pcap_size_bytes"] = len(raw)
    repin(imported, report)
    result = check(imported, require_pcap_framing=True)
    assert result["pcap_framing_required"] is True
    assert result["pcap_framing_verified"] is True
    assert result["pcap_packet_count"] == 1
    assert result["capture_authenticity_verified"] is False
    assert result["ai_inference_performed"] is False

    cmd = [
        sys.executable, str(ROOT / "scripts" / "verify_offline_pcap_import.py"),
        "--report", str(imported["report"]),
        "--expected-report-sha256", imported["pin"],
        "--pcap", str(imported["pcap"]),
        "--log", str(imported["log"]),
        "--cidr", CIDR[0], "--require-pcap-framing",
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    assert "1 packet records" in completed.stdout
    assert "NOT verified" in completed.stdout


def test_strict_framing_rejects_pinned_truncated_packet(imported):
    raw = (bytes.fromhex("d4c3b2a1")
           + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
           + struct.pack("<IIII", 100, 123, 5, 5) + b"abcd")
    imported["pcap"].write_bytes(raw)
    report = json.loads(imported["report"].read_text())
    report["pcap_sha256"] = hashlib.sha256(raw).hexdigest()
    report["pcap_size_bytes"] = len(raw)
    repin(imported, report)
    with pytest.raises(ValueError, match="packet"):
        check(imported, require_pcap_framing=True)
