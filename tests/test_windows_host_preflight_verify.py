"""Synthetic integrity tests only; no real Windows or VMware capture."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.host_preflight_verify import verify_host_preflight
from blue_team_ai.windows_host_preflight import (
    COMMANDS, REPORT_NAME, collect_windows_host_preflight,
)


def _snapshot(directory: Path) -> tuple[Path, str]:
    def fake_runner(argv, **kwargs):
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(
            argv, 0, stdout=b"SYNTHETIC PRIVATE HOST ROUTE\r\n", stderr=b""
        )
    collect_windows_host_preflight(
        directory, platform_name="win32", runner=fake_runner
    )
    report = directory / REPORT_NAME
    return report, hashlib.sha256(report.read_bytes()).hexdigest()


def _repin(report: Path) -> str:
    return hashlib.sha256(report.read_bytes()).hexdigest()


def test_verifies_all_originals_without_writes_or_raw_network_data(tmp_path):
    report, pin = _snapshot(tmp_path)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    result = verify_host_preflight(report, expected_report_sha256=pin)
    assert result["original_files_verified"] == 3
    assert result["host_only_isolation_verified"] is False
    assert result["guest_routes_verified"] is False
    assert result["attack_detection_performed"] is False
    assert "SYNTHETIC PRIVATE HOST" not in json.dumps(result)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_refuses_wrong_or_missing_independent_pin(tmp_path):
    report, pin = _snapshot(tmp_path)
    for wrong in ("", "X" * 64, "0" * 64):
        with pytest.raises(ValueError, match="SHA-256"):
            verify_host_preflight(report, expected_report_sha256=wrong)
    assert verify_host_preflight(report, expected_report_sha256=pin)


def test_refuses_changed_original_even_when_inventory_unchanged(tmp_path):
    report, pin = _snapshot(tmp_path)
    original = tmp_path / COMMANDS[0][2]
    original.write_bytes(original.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="integrity mismatch"):
        verify_host_preflight(report, expected_report_sha256=pin)


def test_refuses_missing_original(tmp_path):
    report, pin = _snapshot(tmp_path)
    (tmp_path / COMMANDS[1][2]).unlink()
    with pytest.raises(ValueError, match="regular file"):
        verify_host_preflight(report, expected_report_sha256=pin)


def test_refuses_report_tampering_before_json_parse(tmp_path):
    report, pin = _snapshot(tmp_path)
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_host_preflight(report, expected_report_sha256=pin)


@pytest.mark.parametrize("change", [
    lambda d: d.update({"schema_version": True}),
    lambda d: d.update({"host_only_isolation_verified": True}),
    lambda d: d["files"]["ipconfig"].update({"filename": "../unexpected.txt"}),
    lambda d: d["files"]["ipconfig"].update({"byte_size": True}),
    lambda d: d["files"].update({"unknown": {}}),
    lambda d: d.update({"captured_at_utc": "2026-10-28T12:00:00"}),
])
def test_refuses_invalid_re_pinned_report_schema(tmp_path, change):
    report, _ = _snapshot(tmp_path)
    document = json.loads(report.read_text(encoding="utf-8"))
    change(document)
    report.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_host_preflight(report, expected_report_sha256=_repin(report))


def test_refuses_duplicate_json_keys_even_if_re_pinned(tmp_path):
    report, _ = _snapshot(tmp_path)
    raw = report.read_text(encoding="utf-8").replace(
        '"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1
    )
    report.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        verify_host_preflight(report, expected_report_sha256=_repin(report))


def test_refuses_symlinked_original(tmp_path):
    report, pin = _snapshot(tmp_path)
    original = tmp_path / COMMANDS[0][2]
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_bytes(original.read_bytes())
    original.unlink()
    try:
        original.symlink_to(elsewhere)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValueError, match="regular file"):
        verify_host_preflight(report, expected_report_sha256=pin)


def test_cli_is_offline_and_refuses_tampered_evidence(tmp_path):
    report, pin = _snapshot(tmp_path)
    cmd = [
        sys.executable, str(ROOT / "scripts" / "verify_windows_host_network.py"),
        "--report", str(report), "--expected-report-sha256", pin,
    ]
    ok = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert ok.returncode == 0, ok.stderr
    assert "NOT verified" in ok.stdout
    (tmp_path / COMMANDS[2][2]).write_bytes(b"tampered")
    bad = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert bad.returncode == 1
    assert "SYNTHETIC" not in bad.stderr
