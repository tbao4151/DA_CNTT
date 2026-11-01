"""Synthetic-only Linux guest snapshot screening; no network or VMware access."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_linux_guest_network_preflight.py"


def _fixtures():
    addresses = [
        {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "addr_info": [
            {"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        {"ifname": "ens33", "flags": ["BROADCAST", "UP", "LOWER_UP"], "addr_info": [
            {"family": "inet", "local": "192.168.56.20", "prefixlen": 24},
            {"family": "inet6", "local": "fe80::1234", "prefixlen": 64}]},
    ]
    v4 = [{"dst": "192.168.56.0/24", "dev": "ens33", "protocol": "kernel", "scope": "link"}]
    v6 = [{"dst": "fe80::/64", "dev": "ens33", "metric": 256}]
    return addresses, v4, v6


def _run(tmp_path, snapshots, *, tamper=None):
    names = ("addresses", "routes-v4", "routes-v6")
    args = [sys.executable, str(SCRIPT), "--adapter", "ens33", "--cidr", "192.168.56.0/24"]
    for name, snapshot in zip(names, snapshots):
        path = tmp_path / (name + ".json")
        raw = json.dumps(snapshot).encode()
        path.write_bytes(raw)
        args.extend(["--" + name, str(path), "--expected-" + name + "-sha256",
                     hashlib.sha256(raw).hexdigest()])
    if tamper:
        tamper(args, tmp_path)
    return subprocess.run(args, capture_output=True, text=True)


def test_valid_owned_linux_guest_snapshot_is_not_isolation_attestation(tmp_path):
    result = _run(tmp_path, _fixtures())
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["linux_guest_configuration_screen_passed"] is True
    assert report["vmware_hostonly_isolation_verified"] is False
    assert report["traffic_authorized"] is False
    assert report["other_routing_tables_checked"] is False
    assert "192.168.56.20" not in result.stdout
    assert str(tmp_path) not in result.stdout


@pytest.mark.parametrize("problem", [
    "extra_active_nic", "extra_addressed_nic", "global_ipv6", "wrong_ipv4",
    "default_v4", "default_v6", "external_v4_route", "external_v6_route",
    "via_gateway", "missing_scope_route", "duplicate_nic", "duplicate_address",
    "loopback_nonlocal_v4", "loopback_global_ipv6", "loopback_wrong_prefix",
    "loopback_duplicate", "loopback_malformed_prefix",
])
def test_unsafe_or_inconsistent_linux_guest_snapshots_fail_closed(tmp_path, problem):
    addresses, v4, v6 = _fixtures()
    if problem in ("extra_active_nic", "extra_addressed_nic"):
        addresses.append({"ifname": "eth1", "flags": ["UP"] if problem == "extra_active_nic" else [],
                          "addr_info": [] if problem == "extra_active_nic" else [
                              {"family": "inet", "local": "10.0.0.2", "prefixlen": 24}]})
    elif problem == "global_ipv6":
        addresses[1]["addr_info"][1]["local"] = "2001:db8::1"
    elif problem == "wrong_ipv4":
        addresses[1]["addr_info"][0]["local"] = "192.168.57.20"
    elif problem == "default_v4":
        v4.append({"dst": "default", "dev": "ens33", "gateway": "192.168.56.1"})
    elif problem == "default_v6":
        v6.append({"dst": "default", "dev": "ens33", "via": "fe80::1"})
    elif problem == "external_v4_route":
        v4.append({"dst": "10.0.0.0/8", "dev": "ens33"})
    elif problem == "external_v6_route":
        v6.append({"dst": "2001:db8::/32", "dev": "ens33"})
    elif problem == "via_gateway":
        v4[0]["via"] = "192.168.56.1"
    elif problem == "missing_scope_route":
        v4.clear()
    elif problem == "duplicate_nic":
        addresses.append(dict(addresses[1]))
    elif problem == "duplicate_address":
        addresses[1]["addr_info"].append(dict(addresses[1]["addr_info"][0]))
    elif problem == "loopback_nonlocal_v4":
        addresses[0]["addr_info"].append(
            {"family": "inet", "local": "192.168.56.21", "prefixlen": 24})
    elif problem == "loopback_global_ipv6":
        addresses[0]["addr_info"].append(
            {"family": "inet6", "local": "2001:db8::1", "prefixlen": 128})
    elif problem == "loopback_wrong_prefix":
        addresses[0]["addr_info"][0]["prefixlen"] = 16
    elif problem == "loopback_duplicate":
        addresses[0]["addr_info"].append(dict(addresses[0]["addr_info"][0]))
    elif problem == "loopback_malformed_prefix":
        addresses[0]["addr_info"][0]["prefixlen"] = True
    result = _run(tmp_path, (addresses, v4, v6))
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_standard_dual_stack_loopback_is_accepted(tmp_path):
    addresses, v4, v6 = _fixtures()
    addresses[0]["addr_info"].append(
        {"family": "inet6", "local": "::1", "prefixlen": 128})
    result = _run(tmp_path, (addresses, v4, v6))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["linux_guest_configuration_screen_passed"] is True


def test_changed_bytes_rejected_even_when_original_pin_is_valid(tmp_path):
    def tamper(args, root):
        (root / "addresses.json").write_bytes(b"[]")
    result = _run(tmp_path, _fixtures(), tamper=tamper)
    assert result.returncode == 1
    assert result.stdout == ""


def test_duplicate_json_key_is_rejected(tmp_path):
    def tamper(args, root):
        path = root / "routes-v4.json"
        raw = b'[{"dst":"192.168.56.0/24","dst":"default","dev":"ens33"}]'
        path.write_bytes(raw)
        args[args.index("--expected-routes-v4-sha256") + 1] = hashlib.sha256(raw).hexdigest()
    result = _run(tmp_path, _fixtures(), tamper=tamper)
    assert result.returncode == 1
    assert result.stdout == ""
