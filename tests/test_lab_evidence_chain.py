"""Synthetic-only integrated checks; no real VMware or authorized capture."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from test_offline_pcap_verify import imported
from test_paired_network_preflight import guest, host

ROOT = Path(__file__).resolve().parents[1]


def _run(tmp_path, evidence, *, changes=None):
    # The existing synthetic Zeek fixture uses 192.168.56.0/24; align
    # the separate host/guest synthetic snapshots with that declared scope.
    h, g = host(), guest()
    h["adapter_ipv4"][0]["address"] = "192.168.56.1"
    g["adapters"][0]["ipv4"][0]["address"] = "192.168.56.10"
    hraw, graw = json.dumps(h).encode(), json.dumps(g).encode()
    hp, gp = tmp_path / "host.json", tmp_path / "guest.json"
    hp.write_bytes(hraw)
    gp.write_bytes(graw)
    args = [
        sys.executable, str(ROOT / "scripts/verify_lab_evidence_chain.py"),
        "--host-snapshot", str(hp),
        "--expected-host-sha256", hashlib.sha256(hraw).hexdigest(),
        "--host-adapter", "VMware Network Adapter VMnet1",
        "--guest-snapshot", str(gp),
        "--expected-guest-sha256", hashlib.sha256(graw).hexdigest(),
        "--guest-adapter", "Ethernet0",
        "--cidr", "192.168.56.0/24",
        "--pcap", str(evidence["pcap"]),
        "--log", str(evidence["log"]),
        "--import-report", str(evidence["report"]),
        "--expected-import-report-sha256", evidence["pin"],
    ]
    if changes:
        changes(args, hp, gp)
    return subprocess.run(args, capture_output=True, text=True)


def test_synthetic_integrated_evidence_passes_without_claiming_detection(tmp_path, imported):
    evidence = imported
    before = {k: evidence[k].read_bytes() for k in ("pcap", "log", "report")}
    result = _run(tmp_path, evidence)
    assert result.returncode == 0, result.stderr
    obj = json.loads(result.stdout)
    assert obj["configuration_snapshots_consistent"] is True
    assert obj["offline_pcap_zeek_import_consistent"] is True
    assert obj["zeek_flow_count"] == 1
    assert all(obj[k] is False for k in (
        "vmware_isolation_verified", "capture_authenticity_verified",
        "traffic_authorized", "independent_labels_verified",
        "ai_inference_performed", "operational_alerts_created",
        "soc_case_created", "live_detection_latency_measured",
    ))
    assert "192.168.56" not in result.stdout
    assert all(evidence[k].read_bytes() == value for k, value in before.items())


@pytest.mark.parametrize("kind", [
    "bad_guest_pin", "bad_import_pin", "wrong_cidr", "duplicate_file",
    "changed_guest", "changed_pcap", "symlink_host",
])
def test_synthetic_integrated_evidence_fails_closed(tmp_path, imported, kind):
    evidence = imported

    def change(args, hp, gp):
        if kind == "bad_guest_pin":
            args[args.index("--expected-guest-sha256") + 1] = "0" * 64
        elif kind == "bad_import_pin":
            args[args.index("--expected-import-report-sha256") + 1] = "0" * 64
        elif kind == "wrong_cidr":
            args[args.index("--cidr") + 1] = "192.168.88.0/24"
        elif kind == "duplicate_file":
            args[args.index("--guest-snapshot") + 1] = str(hp)
        elif kind == "changed_guest":
            gp.write_bytes(gp.read_bytes() + b" ")
        elif kind == "changed_pcap":
            evidence["pcap"].write_bytes(evidence["pcap"].read_bytes() + b"x")
        elif kind == "symlink_host":
            alias = tmp_path / "alias.json"
            alias.symlink_to(hp)
            args[args.index("--host-snapshot") + 1] = str(alias)

    result = _run(tmp_path, evidence, changes=change)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert "192.168" not in result.stderr
    assert str(tmp_path) not in result.stderr
