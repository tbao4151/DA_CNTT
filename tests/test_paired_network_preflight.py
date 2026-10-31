"""Synthetic offline host/guest pair tests; never proof of VMware isolation."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.paired_network_preflight import assess_paired_network_snapshots


def host():
    return {
        "schema_version": 1,
        "capture_origin": "windows_host_network_configuration",
        "adapter_name": "VMware Network Adapter VMnet1",
        "adapter_status": "Up",
        "adapter_ipv4": [{"address": "192.168.77.1", "prefix_length": 24}],
        "adapter_default_routes": [], "adapter_dns_servers": [],
    }


def guest():
    return {
        "schema_version": 1,
        "capture_origin": "windows_guest_network_configuration",
        "adapters": [
            {"name": "Ethernet0", "status": "Up", "if_index": 7,
             "ipv4": [{"address": "192.168.77.10", "prefix_length": 24}],
             "ipv6": ["fe80::12"]},
            {"name": "Ethernet1", "status": "Disabled", "if_index": 8,
             "ipv4": [], "ipv6": []},
        ],
        "default_routes_ipv4": [], "default_routes_ipv6": [],
        "dns_servers_ipv4": [], "dns_servers_ipv6": [],
    }


def assess(h=None, g=None, cidr="192.168.77.0/24"):
    return assess_paired_network_snapshots(
        host() if h is None else h, guest() if g is None else g,
        host_adapter="VMware Network Adapter VMnet1", guest_adapter="Ethernet0",
        expected_cidr=cidr,
    )


def test_pair_is_consistent_but_never_attests_isolation():
    result = assess()
    assert result["declared_subnet_consistent"] is True
    assert result["host_guest_ipv4_distinct"] is True
    for field in ("physical_host_only_isolation_verified", "traffic_authorized",
                  "network_activity_performed", "attack_detection_performed",
                  "snapshot_authenticity_verified"):
        assert result[field] is False
    assert "192.168.77" not in json.dumps(result)


@pytest.mark.parametrize("variant", [
    "collision", "wrong_guest_cidr", "wrong_host_cidr", "guest_default_route",
    "guest_dns", "host_dns", "extra_guest_nic", "host_extra_field",
    "guest_global_ipv6", "guest_wrong_name",
])
def test_mismatched_or_unsafe_pair_refused(variant):
    h, g = host(), guest()
    if variant == "collision":
        g["adapters"][0]["ipv4"][0]["address"] = "192.168.77.1"
    elif variant == "wrong_guest_cidr":
        g["adapters"][0]["ipv4"][0]["address"] = "192.168.88.10"
    elif variant == "wrong_host_cidr":
        h["adapter_ipv4"][0]["prefix_length"] = 16
    elif variant == "guest_default_route":
        g["default_routes_ipv4"] = ["7:192.168.77.254"]
    elif variant == "guest_dns":
        g["dns_servers_ipv4"] = ["192.168.77.254"]
    elif variant == "host_dns":
        h["adapter_dns_servers"] = ["192.168.77.254"]
    elif variant == "extra_guest_nic":
        g["adapters"][1]["status"] = "Up"
    elif variant == "host_extra_field":
        h["untrusted_claim"] = "isolated"
    elif variant == "guest_global_ipv6":
        g["adapters"][0]["ipv6"] = ["2001:4860::1"]
    elif variant == "guest_wrong_name":
        g["adapters"][0]["name"] = "Wi-Fi"
    with pytest.raises(ValueError):
        assess(h, g)


def invoke(tmp_path, hraw=None, graw=None, host_pin=None, guest_pin=None):
    hraw = json.dumps(host()).encode() if hraw is None else hraw
    graw = json.dumps(guest()).encode() if graw is None else graw
    hpath, gpath = tmp_path / "host.json", tmp_path / "guest.json"
    hpath.write_bytes(hraw)
    gpath.write_bytes(graw)
    return subprocess.run([
        sys.executable, str(ROOT / "scripts/check_paired_network_preflight.py"),
        "--host-snapshot", str(hpath),
        "--expected-host-sha256", host_pin or hashlib.sha256(hraw).hexdigest(),
        "--host-adapter", "VMware Network Adapter VMnet1",
        "--guest-snapshot", str(gpath),
        "--expected-guest-sha256", guest_pin or hashlib.sha256(graw).hexdigest(),
        "--guest-adapter", "Ethernet0", "--cidr", "192.168.77.0/24",
    ], capture_output=True, text=True)


def test_cli_pinned_pair_success_and_hash_refusal(tmp_path):
    ok = invoke(tmp_path)
    assert ok.returncode == 0, ok.stderr
    result = json.loads(ok.stdout)
    assert result["physical_host_only_isolation_verified"] is False
    assert len(result["host_snapshot_sha256"]) == 64
    assert len(result["guest_snapshot_sha256"]) == 64
    for kwargs in ({"host_pin": "0" * 64}, {"guest_pin": "0" * 64}):
        bad = invoke(tmp_path, **kwargs)
        assert bad.returncode == 1 and bad.stdout == ""
        assert "192.168.77" not in bad.stderr


@pytest.mark.parametrize("which,raw", [
    ("host", b'{"schema_version":1,"schema_version":1}'),
    ("guest", b'{"schema_version":NaN}'),
    ("host", b"x" * (64 * 1024 + 1)),
    ("guest", b"\\xff"),
])
def test_cli_bad_snapshot_refused(tmp_path, which, raw):
    kwargs = {"hraw" if which == "host" else "graw": raw}
    bad = invoke(tmp_path, **kwargs)
    assert bad.returncode == 1 and bad.stdout == ""


def test_cli_rejects_symlink_and_same_file(tmp_path):
    hraw, graw = json.dumps(host()).encode(), json.dumps(guest()).encode()
    hpath, gpath = tmp_path / "host.json", tmp_path / "guest.json"
    hpath.write_bytes(hraw)
    gpath.symlink_to(hpath)
    cmd = [sys.executable, str(ROOT / "scripts/check_paired_network_preflight.py"),
           "--host-snapshot", str(hpath),
           "--expected-host-sha256", hashlib.sha256(hraw).hexdigest(),
           "--host-adapter", "VMware Network Adapter VMnet1",
           "--guest-snapshot", str(gpath),
           "--expected-guest-sha256", hashlib.sha256(graw).hexdigest(),
           "--guest-adapter", "Ethernet0", "--cidr", "192.168.77.0/24"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 1 and proc.stdout == ""
    cmd[cmd.index(str(gpath))] = str(hpath)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 1 and proc.stdout == ""


def test_paired_preflight_accepts_v2_host_ipv6_screen_and_rejects_global():
    legacy = assess()
    assert legacy["host_ipv6_screened"] is False
    updated = host()
    updated["schema_version"] = 2
    updated["adapter_ipv6"] = ["fe80::123%11"]
    updated["adapter_default_routes_ipv6"] = []
    updated["adapter_dns_servers_ipv6"] = []
    report = assess(h=updated)
    assert report["host_ipv6_screened"] is True
    assert report["physical_host_only_isolation_verified"] is False
    updated["adapter_ipv6"] = ["2001:db8::123"]
    with pytest.raises(ValueError):
        assess(h=updated)
