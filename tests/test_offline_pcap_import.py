"""Synthetic-only tests for offline classic PCAP import (no Zeek installed)."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai import offline_pcap
from test_zeek_telemetry import VALUES, log

CIDR = ["192.168.56.0/24"]


def _pcap(tmp_path):
    source = tmp_path / "capture.pcap"
    source.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 20)
    return source


def _fake_zeek(monkeypatch, *, data=None, returncode=0):
    seen = []
    def fake_run(argv, **kwargs):
        seen.append((argv, kwargs))
        (Path(kwargs["cwd"]) / "conn.log").write_bytes(log(VALUES) if data is None else data)
        return SimpleNamespace(returncode=returncode)
    monkeypatch.setattr(offline_pcap.subprocess, "run", fake_run)
    return seen


def test_import_really_invokes_offline_file_mode_and_pins_both_inputs(tmp_path, monkeypatch):
    source = _pcap(tmp_path)
    seen = _fake_zeek(monkeypatch)
    output = tmp_path / "private-output"
    result = offline_pcap.import_offline_pcap(
        source, output, lab_cidrs=CIDR, operator_confirmed_offline=True,
    )
    assert len(seen) == 1
    argv, options = seen[0]
    assert argv == ["zeek", "-r", str(source)]
    assert "-i" not in argv and options["cwd"] == output
    assert options["timeout"] == 120 and options["check"] is False
    assert result["pcap_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert result["zeek_conn_sha256"] == hashlib.sha256(log(VALUES)).hexdigest()
    assert result["flow_count"] == 1
    assert result["capture_authenticity_verified"] is False
    assert result["live_capture"] is False and result["automated_alerts"] is False
    assert json.loads((output / "offline_import_report.json").read_text()) == result
    assert source.read_bytes().startswith(bytes.fromhex("d4c3b2a1"))


@pytest.mark.parametrize("reason", [
    "no_confirmation", "bad_magic", "truncated", "oversize", "existing_output",
    "bad_scope", "bad_timeout", "relative_pcap", "repo_output",
])
def test_preflight_fails_before_running_zeek(tmp_path, monkeypatch, reason):
    source = _pcap(tmp_path)
    output = tmp_path / "private-output"
    if reason == "bad_magic":
        source.write_bytes(b"notp" + b"\x00" * 20)
    elif reason == "truncated":
        source.write_bytes(b"\x00" * 5)
    elif reason == "oversize":
        with source.open("wb") as f:
            f.truncate(offline_pcap.MAX_PCAP_BYTES + 1)
    elif reason == "existing_output":
        output.mkdir()
    args = dict(lab_cidrs=CIDR, operator_confirmed_offline=True)
    if reason == "no_confirmation":
        args["operator_confirmed_offline"] = False
    elif reason == "bad_scope":
        args["lab_cidrs"] = ["8.8.8.0/24"]
    elif reason == "bad_timeout":
        args["timeout_seconds"] = True
    elif reason == "relative_pcap":
        source = Path("relative.pcap")
    elif reason == "repo_output":
        output = ROOT / "should-never-create-pcap-output"
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Zeek must not be launched")
    monkeypatch.setattr(offline_pcap.subprocess, "run", forbidden)
    with pytest.raises((ValueError, FileNotFoundError)):
        offline_pcap.import_offline_pcap(source, output, **args)
    assert not (output / "offline_import_report.json").exists()


def test_scope_rejection_never_claims_success(tmp_path, monkeypatch):
    source = _pcap(tmp_path)
    external = list(VALUES)
    external[4] = "8.8.8.8"
    _fake_zeek(monkeypatch, data=log(tuple(external)))
    output = tmp_path / "scope-refused"
    with pytest.raises(ValueError, match="outside"):
        offline_pcap.import_offline_pcap(
            source, output, lab_cidrs=CIDR, operator_confirmed_offline=True,
        )
    assert (output / "conn.log").exists()  # preserve private failure evidence
    assert not (output / "offline_import_report.json").exists()


def test_zeek_failure_keeps_private_output_without_success_report(tmp_path, monkeypatch):
    source = _pcap(tmp_path)
    _fake_zeek(monkeypatch, returncode=2)
    output = tmp_path / "failed-run"
    with pytest.raises(ValueError, match="exited unsuccessfully"):
        offline_pcap.import_offline_pcap(
            source, output, lab_cidrs=CIDR, operator_confirmed_offline=True,
        )
    assert output.exists()
    assert not (output / "offline_import_report.json").exists()


def test_missing_zeek_or_timeout_fails_closed(tmp_path, monkeypatch):
    source = _pcap(tmp_path)
    def missing(*args, **kwargs):
        raise FileNotFoundError("zeek")
    monkeypatch.setattr(offline_pcap.subprocess, "run", missing)
    with pytest.raises(ValueError, match="failed"):
        offline_pcap.import_offline_pcap(
            source, tmp_path / "missing", lab_cidrs=CIDR,
            operator_confirmed_offline=True,
        )
    assert not (tmp_path / "missing" / "offline_import_report.json").exists()
    def timed_out(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 120)
    monkeypatch.setattr(offline_pcap.subprocess, "run", timed_out)
    with pytest.raises(ValueError, match="failed"):
        offline_pcap.import_offline_pcap(
            source, tmp_path / "timeout", lab_cidrs=CIDR,
            operator_confirmed_offline=True,
        )


def test_original_pcap_modified_during_run_is_rejected(tmp_path, monkeypatch):
    source = _pcap(tmp_path)
    def changed(argv, **kwargs):
        (Path(kwargs["cwd"]) / "conn.log").write_bytes(log(VALUES))
        source.write_bytes(source.read_bytes() + b"changed")
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(offline_pcap.subprocess, "run", changed)
    output = tmp_path / "changed"
    with pytest.raises(ValueError, match="changed"):
        offline_pcap.import_offline_pcap(
            source, output, lab_cidrs=CIDR, operator_confirmed_offline=True,
        )
    assert not (output / "offline_import_report.json").exists()
