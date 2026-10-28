"""Synthetic-only integrity tests; never a real VMware capture or attack test."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.capture_evidence import build_capture_inventory
from blue_team_ai.capture_evidence_verify import verify_capture_inventory

CIDR = "192.168.56.0/24"


def _log() -> bytes:
    return (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "1630000000.25\tSYNTH1\t192.168.56.10\t53000\t192.168.56.20\t443\ttcp\n"
    ).encode("utf-8")


@pytest.fixture
def evidence(tmp_path):
    paths = {
        "log_path": tmp_path / "conn.log",
        "vmware_screenshot": tmp_path / "vmware.png",
        "host_adapter_screenshot": tmp_path / "adapter.jpg",
        "zeek_version_file": tmp_path / "zeek-version.txt",
        "scenario_notes": tmp_path / "scenario.txt",
    }
    paths["log_path"].write_bytes(_log())
    paths["vmware_screenshot"].write_bytes(b"\x89PNG\r\n\x1a\nSYNTHETIC")
    paths["host_adapter_screenshot"].write_bytes(b"\xff\xd8\xffSYNTHETIC")
    paths["zeek_version_file"].write_text("Zeek synthetic version\n", encoding="utf-8")
    paths["scenario_notes"].write_text("Synthetic authorized-fixture placeholder\n", encoding="utf-8")
    report = build_capture_inventory(
        **paths, expected_log_sha256=hashlib.sha256(_log()).hexdigest(),
        cidrs=[CIDR], origin="synthetic",
    )
    report_path = tmp_path / "inventory.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return paths, report_path


def _pin(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify(evidence, **changes):
    paths, report_path = evidence
    kwargs = dict(
        report_path=report_path, expected_report_sha256=_pin(report_path),
        log_path=paths["log_path"], vmware_screenshot=paths["vmware_screenshot"],
        host_adapter_screenshot=paths["host_adapter_screenshot"],
        zeek_version_file=paths["zeek_version_file"],
        scenario_notes=paths["scenario_notes"], cidrs=[CIDR],
    )
    kwargs.update(changes)
    return verify_capture_inventory(**kwargs)


def test_verifies_originals_scope_without_writes_or_private_values(evidence):
    paths, report_path = evidence
    before = {p.name: p.read_bytes() for p in report_path.parent.iterdir()}
    result = _verify(evidence)
    assert result["original_files_verified"] == 5
    assert result["flow_count"] == 1
    assert result["origin_operator_declared"] == "synthetic"
    assert all(result[key] is False for key in (
        "host_only_isolation_verified", "capture_authenticity_verified",
        "authorization_verified", "scenario_truth_verified", "attack_detection_performed",
    ))
    assert "192.168.56." not in json.dumps(result)
    assert "SYNTH1" not in json.dumps(result)
    assert str(report_path.parent) not in json.dumps(result)
    assert {p.name: p.read_bytes() for p in report_path.parent.iterdir()} == before


def test_requires_independent_report_pin(evidence):
    with pytest.raises(ValueError, match="SHA-256"):
        _verify(evidence, expected_report_sha256="0" * 64)
    with pytest.raises(ValueError, match="SHA-256"):
        _verify(evidence, expected_report_sha256="INVALID")


@pytest.mark.parametrize("role", [
    "log_path", "vmware_screenshot", "host_adapter_screenshot",
    "zeek_version_file", "scenario_notes",
])
def test_tampered_original_fails(evidence, role):
    paths, _ = evidence
    paths[role].write_bytes(paths[role].read_bytes() + b"MODIFIED")
    with pytest.raises(ValueError, match="integrity mismatch"):
        _verify(evidence)


def test_missing_original_fails(evidence):
    paths, _ = evidence
    paths["log_path"].unlink()
    with pytest.raises(ValueError, match="regular file"):
        _verify(evidence)


def test_changed_scope_refused(evidence):
    with pytest.raises(ValueError, match="outside"):
        _verify(evidence, cidrs=["10.10.0.0/24"])
    with pytest.raises(ValueError, match="scope evidence mismatch"):
        _verify(evidence, cidrs=["192.168.0.0/16"])


@pytest.mark.parametrize("mutate", [
    lambda r: r.update({"host_only_isolation_verified": True}),
    lambda r: r.update({"origin": "live"}),
    lambda r: r["scope_screening"].update({"flow_count": True}),
    lambda r: r["scope_screening"].update({"flow_count": 2}),
    lambda r: r["files"]["zeek_conn_log"].update({"byte_size": True}),
    lambda r: r["files"]["zeek_conn_log"].update({"sha256": "bad"}),
    lambda r: r.update({"recorded_at_utc": "2026-10-28T12:00:00"}),
    lambda r: r.update({"report_version": True}),
])
def test_re_pinned_invalid_report_refused(evidence, mutate):
    _, report_path = evidence
    report = json.loads(report_path.read_text(encoding="utf-8"))
    mutate(report)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError):
        _verify(evidence)


def test_duplicate_json_key_rejected_even_when_repinned(evidence):
    _, report_path = evidence
    raw = report_path.read_text(encoding="utf-8").replace(
        '"report_version": 1', '"report_version": 1, "report_version": 1', 1
    )
    report_path.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        _verify(evidence)


def test_symlinked_original_refused(evidence):
    paths, _ = evidence
    original = paths["log_path"]
    backup = original.with_name("backup.log")
    backup.write_bytes(original.read_bytes())
    original.unlink()
    try:
        original.symlink_to(backup)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValueError, match="regular file"):
        _verify(evidence)


def test_cli_succeeds_then_refuses_modified_original(evidence):
    paths, report_path = evidence
    command = [
        sys.executable, str(ROOT / "scripts" / "verify_zeek_capture_inventory.py"),
        "--report", str(report_path), "--expected-report-sha256", _pin(report_path),
        "--log", str(paths["log_path"]), "--cidr", CIDR,
        "--vmware-screenshot", str(paths["vmware_screenshot"]),
        "--host-adapter-screenshot", str(paths["host_adapter_screenshot"]),
        "--zeek-version-file", str(paths["zeek_version_file"]),
        "--scenario-notes", str(paths["scenario_notes"]),
    ]
    good = subprocess.run(command, capture_output=True, text=True, check=False)
    assert good.returncode == 0, good.stderr
    assert "NOT verified" in good.stdout
    paths["scenario_notes"].write_text("Modified\n", encoding="utf-8")
    bad = subprocess.run(command, capture_output=True, text=True, check=False)
    assert bad.returncode == 1
    assert "Modified" not in bad.stderr
