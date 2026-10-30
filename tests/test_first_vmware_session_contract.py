"""Static contract for the first VMware evidence runbook; NO lab execution.

This test deliberately does not run PowerShell, Zeek, packet capture or network I/O.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md"


def _declared_flags(script: str) -> set[str]:
    tree = ast.parse((ROOT / "scripts" / script).read_text(encoding="utf-8"))
    flags: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ):
            flags.update(
                arg.value for arg in node.args
                if isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and arg.value.startswith("--")
            )
    return flags


def test_first_session_runbook_matches_existing_cli_contracts():
    text = RUNBOOK.read_text(encoding="utf-8")
    expected = {
        "check_paired_network_preflight.py": {
            "--host-snapshot", "--expected-host-sha256", "--host-adapter",
            "--guest-snapshot", "--expected-guest-sha256", "--guest-adapter",
            "--cidr",
        },
        "import_offline_pcap.py": {
            "--pcap", "--output-dir", "--cidr", "--confirm-offline-only",
        },
        "verify_lab_evidence_chain.py": {
            "--host-snapshot", "--expected-host-sha256", "--host-adapter",
            "--guest-snapshot", "--expected-guest-sha256", "--guest-adapter",
            "--cidr", "--pcap", "--log", "--import-report",
            "--expected-import-report-sha256", "--expected-pcap-sha256",
            "--expected-log-sha256", "--require-independent-original-pins",
            "--require-pcap-framing",
        },
    }
    for script, flags in expected.items():
        assert f"scripts/{script}" in text
        assert flags <= _declared_flags(script), (script, flags - _declared_flags(script))
        assert all(flag in text for flag in flags), script

    for script in (
        "collect_windows_hostonly_snapshot.ps1",
        "collect_windows_guest_network_snapshot.ps1",
    ):
        assert (ROOT / "scripts" / script).is_file()
        assert f"scripts/{script}" in text
    assert (ROOT / "docs" / "ZEEK_OFFLINE_EXPERIMENT.md").is_file()
    assert "ZEEK_OFFLINE_EXPERIMENT.md" in text


def test_first_session_runbook_explicitly_separates_software_from_lab_evidence():
    text = RUNBOOK.read_text(encoding="utf-8")
    for requirement in (
        "outside Git", "written authorization", "Host-only",
        "not** a physical isolation certificate", "no packet",
        "original.pcap", "conn.log", "NOT MEASURED",
        "Dataset Mode", "Windows 11",
    ):
        assert requirement.lower() in text.lower()
    assert "zeek -i" not in text
    assert "nmap " not in text
