"""Synthetic-only regression tests for read-only Zeek lab CIDR screening."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.lab_scope import inspect_zeek_lab_scope


def _log(*, destination="192.168.56.20", source="192.168.56.10"):
    return (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
        "\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
        f"1630000000.25\tTEST1\t{source}\t52344\t{destination}\t443\ttcp"
        "\t-\t1.25\t100\t-\t2\t-\n"
    ).encode()


def test_valid_private_lab_scope_produces_aggregate_only():
    raw = _log()
    result = inspect_zeek_lab_scope(raw, ["192.168.56.0/24"])
    assert result["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["flow_count"] == 1
    assert result["all_endpoints_within_declared_scope"] is True
    assert result["host_only_isolation_verified"] is False
    assert result["attack_detection_performed"] is False
    serialized = json.dumps(result)
    for forbidden in ("192.168.56", "TEST1", "52344", "tcp"):
        assert forbidden not in serialized


@pytest.mark.parametrize("destination", ["8.8.8.8", "192.168.57.2", "2001:db8::1"])
def test_out_of_scope_destination_fails_closed(destination):
    with pytest.raises(ValueError, match="outside"):
        inspect_zeek_lab_scope(_log(destination=destination), ["192.168.56.0/24"])


def test_out_of_scope_source_fails_closed():
    with pytest.raises(ValueError, match="outside"):
        inspect_zeek_lab_scope(_log(source="10.0.0.4"), ["192.168.56.0/24"])


@pytest.mark.parametrize("scope", [
    ["0.0.0.0/0"], ["10.0.0.0/8"], ["8.8.8.0/24"],
    ["192.168.56.1/24"], ["fc00::/7"], [],
    ["192.168.56.0/24"] * 2,
    ["192.168.56.0/24"] * 5,
])
def test_invalid_or_overbroad_scope_refused(scope):
    with pytest.raises(ValueError):
        inspect_zeek_lab_scope(_log(), scope)


def test_invalid_log_refused():
    with pytest.raises((ValueError, UnicodeError)):
        inspect_zeek_lab_scope(b"invalid", ["192.168.56.0/24"])


def test_cli_writes_private_report_exclusively(tmp_path):
    log_path = tmp_path / "conn.log"
    log_path.write_bytes(_log())
    output = tmp_path / "scope.json"
    command = [sys.executable, str(ROOT / "scripts" / "check_zeek_lab_scope.py"),
               "--log", str(log_path), "--cidr", "192.168.56.0/24", "--output", str(output)]
    first = subprocess.run(command, capture_output=True, text=True, check=False)
    assert first.returncode == 0, first.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["flow_count"] == 1
    second = subprocess.run(command, capture_output=True, text=True, check=False)
    assert second.returncode == 1
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_cli_rejects_public_report_and_no_file_written(tmp_path):
    log_path = tmp_path / "conn.log"
    log_path.write_bytes(_log())
    output = ROOT / "unsafe-scope-report.json"
    command = [sys.executable, str(ROOT / "scripts" / "check_zeek_lab_scope.py"),
               "--log", str(log_path), "--cidr", "192.168.56.0/24", "--output", str(output)]
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert not output.exists()


def test_cli_out_of_scope_does_not_write_report(tmp_path):
    log_path = tmp_path / "conn.log"
    log_path.write_bytes(_log(destination="8.8.8.8"))
    output = tmp_path / "scope.json"
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_zeek_lab_scope.py"),
                           "--log", str(log_path), "--cidr", "192.168.56.0/24", "--output", str(output)],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert not output.exists()
