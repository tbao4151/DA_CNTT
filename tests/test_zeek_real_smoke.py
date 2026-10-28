"""Synthetic fixture tests; actual Zeek binary acceptance runs separately on Linux."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai import offline_pcap, zeek_smoke
from test_zeek_telemetry import VALUES, log
from smoke_zeek_offline import main


def test_benign_fixture_is_deterministic_classic_pcap_with_valid_ip_checksums():
    raw = zeek_smoke.build_benign_udp_pcap()
    assert raw == zeek_smoke.build_benign_udp_pcap()
    assert len(raw) < 512
    assert struct.unpack_from("<IHHIIII", raw, 0) == (
        0xA1B2C3D4, 2, 4, 0, 0, 65535, 1,
    )
    position = 24
    for index in range(2):
        seconds, micros, captured, original = struct.unpack_from("<IIII", raw, position)
        position += 16
        assert seconds == 1700000000 + index and micros == 0
        assert captured == original
        frame = raw[position:position + captured]
        position += captured
        assert frame[12:14] == b"\x08\x00"
        header = frame[14:34]
        assert header[0] == 0x45 and header[9] == 17
        assert zeek_smoke._checksum(header) == 0
        assert str(ipaddress.IPv4Address(header[12:16])) == zeek_smoke.SOURCE_IP
        assert str(ipaddress.IPv4Address(header[16:20])) == zeek_smoke.DESTINATION_IP
        assert struct.unpack("!HH", frame[34:38]) == (51000, 53000)
        assert frame[42:] == f"DA005-BENIGN-OFFLINE-{index}".encode("ascii")
        assert struct.unpack("!H", header[2:4])[0] == len(frame) - 14
    assert position == len(raw)


def test_smoke_refuses_missing_confirmation_or_existing_output(tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("No Zeek call allowed")
    monkeypatch.setattr(zeek_smoke.subprocess, "run", forbidden)
    target = tmp_path / "smoke"
    with pytest.raises(ValueError, match="confirmation"):
        zeek_smoke.run_benign_zeek_smoke(
            target, operator_confirmed_synthetic=False,
        )
    assert not target.exists()
    target.mkdir()
    with pytest.raises(ValueError, match="already exist"):
        zeek_smoke.run_benign_zeek_smoke(
            target, operator_confirmed_synthetic=True,
        )
    assert not (target / "benign_synthetic.pcap").exists()


def test_smoke_exercises_real_import_and_verifier_with_mocked_zeek(tmp_path, monkeypatch):
    seen = []
    def fake_zeek(argv, **kwargs):
        seen.append(argv)
        if argv == ["zeek", "--version"]:
            return SimpleNamespace(returncode=0, stdout="zeek version 7.0\n", stderr="")
        assert argv[0:2] == ["zeek", "-r"]
        assert Path(argv[2]).name == "benign_synthetic.pcap"
        (Path(kwargs["cwd"]) / "conn.log").write_bytes(log(VALUES))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(offline_pcap.subprocess, "run", fake_zeek)
    target = tmp_path / "smoke"
    result = zeek_smoke.run_benign_zeek_smoke(
        target, operator_confirmed_synthetic=True,
    )
    assert seen == [["zeek", "--version"], ["zeek", "-r", str(target / "benign_synthetic.pcap")]]
    assert result["source_kind"] == "synthetic_benign_udp_fixture"
    assert result["flow_count"] == 1
    assert result["vmware_capture_performed"] is False
    assert result["ai_scoring_performed"] is False
    assert result["host_only_isolation_verified"] is False
    assert result["zeek_version_reported"] == "zeek version 7.0"
    assert result["pcap_sha256"] == hashlib.sha256(
        (target / "benign_synthetic.pcap").read_bytes()
    ).hexdigest()
    assert json.loads((target / "smoke_report.json").read_text()) == result
    assert (target / "zeek-import" / "conn.log").exists()
    assert (target / "zeek-import" / "offline_import_report.json").exists()


def test_smoke_missing_zeek_fails_without_creating_files(tmp_path, monkeypatch):
    def missing(*_args, **_kwargs):
        raise FileNotFoundError("zeek")
    monkeypatch.setattr(zeek_smoke.subprocess, "run", missing)
    target = tmp_path / "smoke"
    with pytest.raises(ValueError, match="unavailable"):
        zeek_smoke.run_benign_zeek_smoke(
            target, operator_confirmed_synthetic=True,
        )
    assert not target.exists()


def test_smoke_failed_zeek_keeps_private_fixture_but_no_success_report(tmp_path, monkeypatch):
    def failed(argv, **kwargs):
        if argv == ["zeek", "--version"]:
            return SimpleNamespace(returncode=0, stdout="zeek version test", stderr="")
        return SimpleNamespace(returncode=2)
    monkeypatch.setattr(offline_pcap.subprocess, "run", failed)
    target = tmp_path / "failed-smoke"
    with pytest.raises(ValueError, match="exited unsuccessfully"):
        zeek_smoke.run_benign_zeek_smoke(
            target, operator_confirmed_synthetic=True,
        )
    assert (target / "benign_synthetic.pcap").exists()
    assert not (target / "smoke_report.json").exists()


def test_cli_requires_explicit_confirmation(tmp_path, monkeypatch, capsys):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("No Zeek call allowed")
    monkeypatch.setattr(zeek_smoke.subprocess, "run", forbidden)
    target = tmp_path / "cli-smoke"
    assert main(["--output-dir", str(target)]) == 1
    assert not target.exists()
    assert "refused" in capsys.readouterr().err
