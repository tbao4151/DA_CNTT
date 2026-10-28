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



def _fixture_row():
    """Expected Zeek tuple for the deterministic two-packet benign PCAP."""
    values = list(VALUES)
    values[0] = "1700000000.000000"
    values[1] = "CFIXTURE"
    values[2] = zeek_smoke.SOURCE_IP
    values[3] = "51000"
    values[4] = zeek_smoke.DESTINATION_IP
    values[5] = "53000"
    values[6] = "udp"
    values[7] = "-"
    values[8] = "1.0"
    values[9] = "44"
    values[10] = "0"
    values[11] = "2"
    values[12] = "0"
    return tuple(values)


def test_fixture_contract_accepts_matching_offline_zeek_log(tmp_path):
    path = tmp_path / "conn.log"
    path.write_bytes(log(_fixture_row()))
    zeek_smoke._verify_fixture_flow(path)


@pytest.mark.parametrize("index,changed", [
    (0, "1700000001.000000"),
    (2, "192.168.56.11"),
    (3, "51001"),
    (4, "192.168.56.30"),
    (5, "53001"),
    (6, "tcp"),
])
def test_fixture_contract_rejects_unrelated_in_scope_flow(tmp_path, index, changed):
    row = list(_fixture_row())
    row[index] = changed
    path = tmp_path / "conn.log"
    path.write_bytes(log(tuple(row)))
    with pytest.raises(ValueError, match="fixture|timestamp"):
        zeek_smoke._verify_fixture_flow(path)


def test_fixture_contract_rejects_multiple_flows(tmp_path):
    path = tmp_path / "conn.log"
    path.write_bytes(log(_fixture_row(), _fixture_row()))
    with pytest.raises(ValueError, match="exactly one"):
        zeek_smoke._verify_fixture_flow(path)


def test_fixture_projection_matches_separate_lab_schema_without_identity(tmp_path):
    from blue_team_ai.features import LAB_FEATURE_COLUMNS, LAB_FEATURE_SCHEMA_VERSION

    path = tmp_path / "conn.log"
    path.write_bytes(log(_fixture_row()))
    projection = zeek_smoke.verify_fixture_feature_projection(path)
    assert projection == {
        "feature_schema_version": LAB_FEATURE_SCHEMA_VERSION,
        "feature_columns": list(LAB_FEATURE_COLUMNS),
        "feature_count": len(LAB_FEATURE_COLUMNS),
        "feature_projection_verified": True,
    }
    assert not set(projection["feature_columns"]) & {
        "uid", "src_ip", "dst_ip", "event_time_utc", "source_sha256",
        "label", "attack_cat", "research_candidate",
    }


def test_fixture_projection_rejects_invalid_optional_zeek_measurement(tmp_path):
    row = list(_fixture_row())
    row[9] = "invalid-orig-bytes"
    path = tmp_path / "conn.log"
    path.write_bytes(log(tuple(row)))
    with pytest.raises(ValueError, match="orig_bytes"):
        zeek_smoke.verify_fixture_feature_projection(path)


def test_fixture_projection_rejects_other_in_scope_flow(tmp_path):
    row = list(_fixture_row())
    row[3] = "51001"
    path = tmp_path / "conn.log"
    path.write_bytes(log(tuple(row)))
    with pytest.raises(ValueError, match="fixture"):
        zeek_smoke.verify_fixture_feature_projection(path)


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
        (Path(kwargs["cwd"]) / "conn.log").write_bytes(log(_fixture_row()))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(offline_pcap.subprocess, "run", fake_zeek)
    target = tmp_path / "smoke"
    result = zeek_smoke.run_benign_zeek_smoke(
        target, operator_confirmed_synthetic=True,
    )
    assert seen == [["zeek", "--version"], ["zeek", "-r", str(target / "benign_synthetic.pcap")]]
    assert result["source_kind"] == "synthetic_benign_udp_fixture"
    assert result["flow_count"] == 1
    assert result["fixture_flow_identity_verified"] is True
    assert result["fixture_event_time_verified"] is True
    assert result["feature_projection_verified"] is True
    assert result["feature_schema_version"] == 1
    assert "uid" not in result["feature_columns"]
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
