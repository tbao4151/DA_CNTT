"""Synthetic-only tests: private evidence inventory is not a VMware experiment."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.capture_evidence import build_capture_inventory, validate_private_output


def _log(destination: str = "192.168.56.20") -> bytes:
    return (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        f"1630000000.25\tSYNTH1\t192.168.56.10\t53000\t{destination}\t443\ttcp\n"
    ).encode("utf-8")


@pytest.fixture
def files(tmp_path):
    data = {
        "log_path": tmp_path / "conn.log",
        "vmware_screenshot": tmp_path / "vmware.png",
        "host_adapter_screenshot": tmp_path / "adapter.jpg",
        "zeek_version_file": tmp_path / "zeek-version.txt",
        "scenario_notes": tmp_path / "scenario.txt",
    }
    data["log_path"].write_bytes(_log())
    data["vmware_screenshot"].write_bytes(b"\x89PNG\r\n\x1a\nSYNTHETIC")
    data["host_adapter_screenshot"].write_bytes(b"\xff\xd8\xffSYNTHETIC")
    data["zeek_version_file"].write_text("Zeek version synthetic-test\n", encoding="utf-8")
    data["scenario_notes"].write_text("Synthetic test only, no VMware capture.\n", encoding="utf-8")
    return data


def _build(files, **changes):
    kwargs = dict(
        **files,
        expected_log_sha256=hashlib.sha256(files["log_path"].read_bytes()).hexdigest(),
        cidrs=["192.168.56.0/24"],
        origin="synthetic",
    )
    kwargs.update(changes)
    return build_capture_inventory(**kwargs)


def test_inventory_hashes_only_and_never_asserts_lab_proof(files):
    result = _build(files)
    assert result["scope_screening"]["flow_count"] == 1
    assert result["origin"] == "synthetic"
    assert result["files"]["zeek_conn_log"]["sha256"] == hashlib.sha256(_log()).hexdigest()
    assert all(result[key] is False for key in (
        "host_only_isolation_verified", "capture_authenticity_verified",
        "authorization_verified", "scenario_truth_verified", "attack_detection_performed",
    ))
    serialized = json.dumps(result)
    for forbidden in ("192.168.56.", "SYNTH1", "53000", "Zeek version synthetic-test",
                      str(files["log_path"]), "Synthetic test only"):
        assert forbidden not in serialized


def test_incorrect_independent_hash_fails(files):
    with pytest.raises(ValueError, match="SHA-256"):
        _build(files, expected_log_sha256="0" * 64)


def test_out_of_scope_log_fails(files):
    files["log_path"].write_bytes(_log("8.8.8.8"))
    with pytest.raises(ValueError, match="outside"):
        _build(files)


def test_invalid_evidence_fails(files):
    files["vmware_screenshot"].write_bytes(b"not an image")
    with pytest.raises(ValueError, match="PNG or JPEG"):
        _build(files)


def test_missing_or_empty_notes_fails(files):
    files["scenario_notes"].write_text("  \n", encoding="utf-8")
    with pytest.raises(ValueError, match="plain text"):
        _build(files)


def test_duplicate_evidence_role_fails(files):
    with pytest.raises(ValueError, match="distinct"):
        _build(files, host_adapter_screenshot=files["vmware_screenshot"])


def test_private_output_rejects_repository_and_alias(files):
    with pytest.raises(ValueError, match="private"):
        validate_private_output(ROOT / "unsafe-evidence.json", list(files.values()))
    with pytest.raises(ValueError, match="private"):
        validate_private_output(files["log_path"], list(files.values()))


def _command(files, output):
    return [
        sys.executable, str(ROOT / "scripts" / "record_zeek_lab_capture.py"),
        "--log", str(files["log_path"]),
        "--expected-log-sha256", hashlib.sha256(files["log_path"].read_bytes()).hexdigest(),
        "--cidr", "192.168.56.0/24",
        "--origin", "synthetic",
        "--vmware-screenshot", str(files["vmware_screenshot"]),
        "--host-adapter-screenshot", str(files["host_adapter_screenshot"]),
        "--zeek-version-file", str(files["zeek_version_file"]),
        "--scenario-notes", str(files["scenario_notes"]),
        "--output", str(output),
    ]


def test_cli_creates_private_report_exclusively(files, tmp_path):
    output = tmp_path / "evidence.json"
    command = _command(files, output)
    first = subprocess.run(command, capture_output=True, text=True, check=False)
    assert first.returncode == 0, first.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["origin"] == "synthetic"
    assert report["host_only_isolation_verified"] is False
    before = output.read_bytes()
    second = subprocess.run(command, capture_output=True, text=True, check=False)
    assert second.returncode == 1
    assert output.read_bytes() == before


def test_cli_refuses_bad_scope_without_writing(files, tmp_path):
    output = tmp_path / "rejected.json"
    command = _command(files, output)
    command[command.index("192.168.56.0/24")] = "10.5.0.0/24"
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert not output.exists()
