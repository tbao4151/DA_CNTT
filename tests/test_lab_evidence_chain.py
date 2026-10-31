"""Synthetic-only integrated checks; no real VMware or authorized capture."""
from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from test_offline_pcap_verify import imported
from test_paired_network_preflight import guest, host

ROOT = Path(__file__).resolve().parents[1]


def _run(tmp_path, evidence, *, changes=None, independent_pins=False):
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
    if independent_pins:
        args += [
            "--expected-pcap-sha256", hashlib.sha256(evidence["pcap"].read_bytes()).hexdigest(),
            "--expected-log-sha256", hashlib.sha256(evidence["log"].read_bytes()).hexdigest(),
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
    assert obj["host_ipv6_screened"] is False
    assert obj["host_ipv6_screening_required"] is False
    assert obj["offline_pcap_zeek_import_consistent"] is True
    assert obj["pcap_framing_required"] is False
    assert obj["pcap_framing_verified"] is False
    assert obj["pcap_packet_count"] is None
    assert obj["zeek_flow_count"] == 1
    assert obj["independent_original_pcap_zeek_pins_verified"] is False
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


def test_independently_pinned_originals_are_verified(tmp_path, imported):
    result = _run(tmp_path, imported, independent_pins=True)
    assert result.returncode == 0, result.stderr
    obj = json.loads(result.stdout)
    assert obj["independent_original_pcap_zeek_pins_verified"] is True
    assert obj["pcap_sha256"] == hashlib.sha256(imported["pcap"].read_bytes()).hexdigest()
    assert obj["zeek_conn_sha256"] == hashlib.sha256(imported["log"].read_bytes()).hexdigest()
    assert obj["capture_authenticity_verified"] is False


@pytest.mark.parametrize("kind", ["missing_log_pin", "wrong_pcap_pin", "wrong_log_pin", "invalid_pcap_pin"])
def test_independent_original_pins_fail_closed(tmp_path, imported, kind):
    def change(args, hp, gp):
        if kind == "missing_log_pin":
            i = args.index("--expected-log-sha256")
            del args[i:i + 2]
        elif kind == "wrong_pcap_pin":
            args[args.index("--expected-pcap-sha256") + 1] = "0" * 64
        elif kind == "wrong_log_pin":
            args[args.index("--expected-log-sha256") + 1] = "0" * 64
        elif kind == "invalid_pcap_pin":
            args[args.index("--expected-pcap-sha256") + 1] = "A" * 64
    result = _run(tmp_path, imported, independent_pins=True, changes=change)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_re_pinned_import_report_cannot_replace_independent_pcap_pin(tmp_path, imported):
    original_digest = hashlib.sha256(imported["pcap"].read_bytes()).hexdigest()

    def change(args, hp, gp):
        # Simulate a modified original and a matching, re-pinned import report.
        raw = bytearray(imported["pcap"].read_bytes())
        raw[-1] ^= 1  # Keep the classic PCAP magic and file length intact.
        imported["pcap"].write_bytes(raw)
        report = json.loads(imported["report"].read_text(encoding="utf-8"))
        report["pcap_sha256"] = hashlib.sha256(raw).hexdigest()
        imported["report"].write_text(json.dumps(report), encoding="utf-8")
        args[args.index("--expected-import-report-sha256") + 1] = hashlib.sha256(
            imported["report"].read_bytes()
        ).hexdigest()
        args[args.index("--expected-pcap-sha256") + 1] = original_digest

    result = _run(tmp_path, imported, independent_pins=True, changes=change)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr


def test_strict_gate_refuses_missing_independent_original_pins(tmp_path, imported):
    def strict(args, hp, gp):
        args.append("--require-independent-original-pins")

    result = _run(tmp_path, imported, changes=strict)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_strict_gate_accepts_verified_original_pins(tmp_path, imported):
    def strict(args, hp, gp):
        args.append("--require-independent-original-pins")

    result = _run(tmp_path, imported, independent_pins=True, changes=strict)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["independent_original_pcap_zeek_pins_verified"] is True
    assert report["independent_original_pcap_zeek_pins_required"] is True
    assert report["vmware_isolation_verified"] is False
    assert report["independent_labels_verified"] is False



def test_guest_endpoint_presence_accepts_strictly_pinned_matching_flow(tmp_path, imported):
    def enable(args, hp, gp):
        args.extend(["--require-independent-original-pins", "--require-guest-endpoint"])

    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["guest_endpoint_presence_required"] is True
    assert report["guest_endpoint_observed_in_verified_log"] is True
    assert report["vmware_isolation_verified"] is False
    assert report["capture_authenticity_verified"] is False
    assert "192.168.56" not in result.stdout


def test_guest_endpoint_presence_requires_strict_original_pins(tmp_path, imported):
    def enable(args, hp, gp):
        args.append("--require-guest-endpoint")

    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr


def test_guest_endpoint_presence_refuses_unrelated_in_scope_flow(tmp_path, imported):
    def enable(args, hp, gp):
        args.extend(["--require-independent-original-pins", "--require-guest-endpoint"])
        guest_snapshot = json.loads(gp.read_text(encoding="utf-8"))
        # Still a valid distinct, in-scope guest address; absent from the log.
        guest_snapshot["adapters"][0]["ipv4"][0]["address"] = "192.168.56.30"
        new_bytes = json.dumps(guest_snapshot).encode()
        gp.write_bytes(new_bytes)
        args[args.index("--expected-guest-sha256") + 1] = hashlib.sha256(new_bytes).hexdigest()

    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert "192.168.56" not in result.stderr
    assert str(tmp_path) not in result.stderr


def _repin_integrated_pcap(args, evidence, raw):
    """Synthetic PCAP edits are accompanied by newly pinned import metadata."""
    evidence["pcap"].write_bytes(raw)
    report = json.loads(evidence["report"].read_text(encoding="utf-8"))
    report["pcap_sha256"] = hashlib.sha256(raw).hexdigest()
    report["pcap_size_bytes"] = len(raw)
    evidence["report"].write_text(json.dumps(report), encoding="utf-8")
    args[args.index("--expected-import-report-sha256") + 1] = hashlib.sha256(
        evidence["report"].read_bytes()
    ).hexdigest()
    args[args.index("--expected-pcap-sha256") + 1] = hashlib.sha256(raw).hexdigest()


def test_integrated_framing_requires_strict_independent_pins(tmp_path, imported):
    def enable(args, hp, gp):
        args.append("--require-pcap-framing")

    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_integrated_framing_rejects_header_only_legacy_pcap(tmp_path, imported):
    def enable(args, hp, gp):
        args.extend(["--require-independent-original-pins", "--require-pcap-framing"])

    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr


@pytest.mark.parametrize("truncated", [False, True])
def test_integrated_framing_checks_original_pcap_packet_records(tmp_path, imported, truncated):
    def enable(args, hp, gp):
        args.extend(["--require-independent-original-pins", "--require-pcap-framing"])
        captured = 5 if truncated else 4
        raw = (bytes.fromhex("d4c3b2a1")
               + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
               + struct.pack("<IIII", 100, 123, captured, captured)
               + b"test")
        _repin_integrated_pcap(args, imported, raw)

    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    if truncated:
        assert result.returncode == 1
        assert result.stdout == ""
        assert "refused" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["pcap_framing_required"] is True
        assert report["pcap_framing_verified"] is True
        assert report["pcap_packet_count"] == 1
        assert report["independent_original_pcap_zeek_pins_verified"] is True
        assert report["vmware_isolation_verified"] is False
        assert report["ai_inference_performed"] is False
        assert "192.168.56" not in result.stdout
    assert str(tmp_path) not in result.stderr


def test_strict_host_ipv6_screen_refuses_legacy_v1_without_writing_evidence(tmp_path, imported):
    before = {key: imported[key].read_bytes() for key in ("pcap", "log", "report")}

    def enable(args, hp, gp):
        args.extend(["--require-independent-original-pins", "--require-host-ipv6-screened"])

    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert "192.168" not in result.stderr
    assert all(imported[key].read_bytes() == value for key, value in before.items())


@pytest.mark.parametrize("ipv6, routes, dns, accepted", [
    (["fe80::123%11"], [], [], True),
    (["2001:db8::1"], [], [], False),
    (["fd00::1"], [], [], False),
    (["fe80::123%11"], ["fe80::2"], [], False),
    (["fe80::123%11"], [], ["fe80::2"], False),
])
def test_strict_host_ipv6_screen_v2_pinned_pair(tmp_path, imported, ipv6, routes, dns, accepted):
    def enable(args, hp, gp):
        args.extend(["--require-independent-original-pins", "--require-host-ipv6-screened"])
        snapshot = json.loads(hp.read_text(encoding="utf-8"))
        snapshot.update({
            "schema_version": 2,
            "adapter_ipv6": ipv6,
            "adapter_default_routes_ipv6": routes,
            "adapter_dns_servers_ipv6": dns,
        })
        raw = json.dumps(snapshot).encode("utf-8")
        hp.write_bytes(raw)
        args[args.index("--expected-host-sha256") + 1] = hashlib.sha256(raw).hexdigest()

    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    assert (result.returncode == 0) is accepted
    if accepted:
        report = json.loads(result.stdout)
        assert report["host_ipv6_screened"] is True
        assert report["host_ipv6_screening_required"] is True
        assert report["vmware_isolation_verified"] is False
        assert report["traffic_authorized"] is False
        assert report["ai_inference_performed"] is False
        assert "fe80" not in result.stdout
        assert "192.168" not in result.stdout
    else:
        assert result.stdout == ""
        assert "refused" in result.stderr
        assert "192.168" not in result.stderr
