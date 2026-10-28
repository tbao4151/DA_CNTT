"""Synthetic command mocks only; no student Windows/VMware evidence."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.windows_host_preflight import (
    COMMANDS, REPORT_NAME, MAX_COMMAND_BYTES,
    collect_windows_host_preflight, validate_preflight_directory,
)


def fake_runner(calls, *, result_code=0, payload=b"PRIVATE HOST IP 192.168.56.1\n"):
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, result_code, stdout=payload, stderr=b"")
    return run


def test_read_only_allowlisted_commands_and_private_hashes(tmp_path):
    calls = []
    result = collect_windows_host_preflight(
        tmp_path, platform_name="win32", runner=fake_runner(calls),
    )
    assert len(calls) == len(COMMANDS)
    for (role, expected, filename), (argv, options) in zip(COMMANDS, calls):
        assert argv == list(expected)
        assert options["shell"] is False
        assert options["timeout"] == 20
        assert (tmp_path / filename).read_bytes() == b"PRIVATE HOST IP 192.168.56.1\n"
        assert result["files"][role]["sha256"] == hashlib.sha256(
            (tmp_path / filename).read_bytes()
        ).hexdigest()
    report = json.loads((tmp_path / REPORT_NAME).read_text(encoding="utf-8"))
    assert report["host_only_isolation_verified"] is False
    assert report["guest_adapters_verified"] is False
    assert report["network_traffic_generated"] is False
    assert report["attack_detection_performed"] is False
    assert "192.168.56.1" not in json.dumps(report)
    assert str(tmp_path) not in json.dumps(report)


def test_refuse_non_windows_without_commands_or_files(tmp_path):
    calls = []
    with pytest.raises(ValueError, match="Windows only"):
        collect_windows_host_preflight(
            tmp_path, platform_name="linux", runner=fake_runner(calls),
        )
    assert calls == []
    assert list(tmp_path.iterdir()) == []


def test_refuse_existing_output_before_commands(tmp_path):
    (tmp_path / REPORT_NAME).write_text("existing", encoding="utf-8")
    calls = []
    with pytest.raises(ValueError, match="overwrite"):
        collect_windows_host_preflight(
            tmp_path, platform_name="win32", runner=fake_runner(calls),
        )
    assert calls == []
    assert (tmp_path / REPORT_NAME).read_text(encoding="utf-8") == "existing"


def test_fail_closed_on_command_failure_or_oversize(tmp_path):
    for code, payload in ((1, b"failed"), (0, b"x" * (MAX_COMMAND_BYTES + 1)), (0, b"")):
        calls = []
        with pytest.raises(ValueError, match="output refused"):
            collect_windows_host_preflight(
                tmp_path, platform_name="win32",
                runner=fake_runner(calls, result_code=code, payload=payload),
            )
        assert len(calls) == 1
        assert list(tmp_path.iterdir()) == []


def test_refuse_repository_directory_and_relative_path(tmp_path):
    with pytest.raises(ValueError, match="outside"):
        validate_preflight_directory(ROOT)
    with pytest.raises(ValueError, match="absolute"):
        validate_preflight_directory(Path("relative"))


def test_refuse_symlink_directory_if_supported(tmp_path):
    alias = tmp_path.parent / (tmp_path.name + "-alias")
    try:
        alias.symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this platform")
    with pytest.raises(ValueError, match="symlink"):
        validate_preflight_directory(alias)


def test_timeout_does_not_write_partial_evidence(tmp_path):
    def timeout(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 20)
    with pytest.raises(ValueError, match="failed"):
        collect_windows_host_preflight(
            tmp_path, platform_name="win32", runner=timeout,
        )
    assert list(tmp_path.iterdir()) == []
