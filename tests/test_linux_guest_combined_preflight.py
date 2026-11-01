"""Synthetic-only regression for the combined five-snapshot Linux guest gate."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_linux_guest_combined_preflight.py"
ROLES = ("addresses", "routes-v4", "routes-v6", "rules-v4", "rules-v6")


def _snapshots():
    return [
        [
            {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "addr_info": [
                {"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
                {"family": "inet6", "local": "::1", "prefixlen": 128},
            ]},
            {"ifname": "ens33", "flags": ["UP", "BROADCAST"], "addr_info": [
                {"family": "inet", "local": "192.168.56.20", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::1234", "prefixlen": 64},
            ]},
        ],
        [{"dst": "192.168.56.0/24", "dev": "ens33", "prefsrc": "192.168.56.20"}],
        [{"dst": "fe80::/64", "dev": "ens33", "prefsrc": "fe80::1234"}],
        [{"priority": p, "src": "all", "table": table} for p, table in (
            (0, "local"), (32766, "main"), (32767, "default"))],
        [{"priority": p, "src": "all", "table": table} for p, table in (
            (0, "local"), (32766, "main"))],
    ]


def _run(tmp_path, snapshots, *, tamper=None):
    args = [sys.executable, str(SCRIPT), "--adapter", "ens33",
            "--cidr", "192.168.56.0/24"]
    for role, data in zip(ROLES, snapshots):
        path = tmp_path / (role + ".json")
        raw = json.dumps(data).encode("utf-8")
        path.write_bytes(raw)
        args.extend(["--" + role, str(path),
                     "--expected-" + role + "-sha256",
                     hashlib.sha256(raw).hexdigest()])
    if tamper is not None:
        tamper(args, tmp_path)
    return subprocess.run(args, capture_output=True, text=True)


def test_combined_pass_is_explicitly_not_isolation_or_authorization(tmp_path):
    result = _run(tmp_path, _snapshots())
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["five_distinct_sha256_pinned_snapshots_checked"] is True
    assert report["linux_guest_main_route_snapshot_passed"] is True
    assert report["linux_guest_policy_rules_snapshot_passed"] is True
    assert report["seven_distinct_sha256_pinned_snapshots_checked"] is False
    assert report["all_routing_tables_in_supplied_snapshots_checked"] is False
    for key in ("other_routing_tables_checked", "dns_and_forwarding_checked",
                "vmware_hostonly_isolation_verified", "traffic_authorized",
                "network_activity_performed"):
        assert report[key] is False
    assert "192.168.56.20" not in result.stdout
    assert str(tmp_path) not in result.stdout


@pytest.mark.parametrize("problem", [
    "extra_active_nic", "outside_main_route", "custom_policy_rule",
    "missing_ipv6_policy", "wrong_scope",
])
def test_combined_gate_refuses_failure_in_either_screen(tmp_path, problem):
    data = _snapshots()
    if problem == "extra_active_nic":
        data[0].append({"ifname": "eth1", "flags": ["UP"], "addr_info": []})
    elif problem == "outside_main_route":
        data[1].append({"dst": "10.0.0.0/8", "dev": "ens33"})
    elif problem == "custom_policy_rule":
        data[3].append({"priority": 100, "src": "all", "table": "main"})
    elif problem == "missing_ipv6_policy":
        data[4].pop()
    elif problem == "wrong_scope":
        data[0][1]["addr_info"][0]["local"] = "192.168.57.20"
    result = _run(tmp_path, data)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_changed_snapshot_rejected_before_either_screen(tmp_path):
    def tamper(args, root):
        (root / "rules-v6.json").write_bytes(b"[]")
    result = _run(tmp_path, _snapshots(), tamper=tamper)
    assert result.returncode == 1
    assert result.stdout == ""


def test_reusing_same_file_for_two_roles_is_rejected(tmp_path):
    def tamper(args, root):
        args[args.index("--rules-v6") + 1] = str(root / "rules-v4.json")
    result = _run(tmp_path, _snapshots(), tamper=tamper)
    assert result.returncode == 1
    assert result.stdout == ""


def test_duplicate_json_keys_refused_even_when_rehashed(tmp_path):
    def tamper(args, root):
        raw = b'[{"priority":0,"priority":32766,"src":"all","table":"local"}]'
        (root / "rules-v4.json").write_bytes(raw)
        args[args.index("--expected-rules-v4-sha256") + 1] = hashlib.sha256(raw).hexdigest()
    result = _run(tmp_path, _snapshots(), tamper=tamper)
    assert result.returncode == 1
    assert result.stdout == ""


def _run_with_all_tables(tmp_path, snapshots, *, problem=None):
    """Exercise the opt-in seven-snapshot CLI using only synthetic private files."""
    def extra(args, root):
        all_v4 = [dict(route, table="main") for route in snapshots[1]]
        all_v6 = [dict(route, table="main") for route in snapshots[2]]
        all_v4.append({"table": "local", "type": "local",
                       "dst": "127.0.0.1", "dev": "lo"})
        all_v6.append({"table": "local", "type": "local",
                       "dst": "::1", "dev": "lo"})
        if problem == "alternate_v4":
            all_v4.append({"table": 100, "dst": "10.0.0.0/8", "dev": "ens33"})
        elif problem == "alternate_v6":
            all_v6.append({"table": "default", "dst": "2001:db8::/32", "dev": "ens33"})
        elif problem == "extra_main":
            all_v4.append({"table": "main", "dst": "10.0.0.0/8", "dev": "ens33"})
        elif problem == "missing_main":
            all_v6.pop(0)
        elif problem == "local_gateway":
            all_v4[-1]["gateway"] = "192.168.56.1"
        elif problem == "local_default":
            all_v4[-1]["dst"] = "0.0.0.0/0"
        elif problem == "local_wrong_family":
            all_v4[-1]["dst"] = "::1"
        elif problem == "local_wrong_dev":
            all_v4[-1]["dev"] = "eth9"
        elif problem == "local_wrong_type":
            all_v4[-1]["type"] = "unicast"
        elif problem == "local_public_ipv4":
            all_v4[-1]["dst"] = "8.8.8.8"
        elif problem == "local_other_private_subnet":
            all_v4[-1].update({"dst": "192.168.57.20", "dev": "ens33"})
        elif problem == "local_public_ipv6":
            all_v6[-1].update({"dst": "2001:db8::1234", "dev": "ens33"})
        elif problem == "local_wrong_loopback_scope":
            all_v4[-1]["dst"] = "192.168.56.20"
        elif problem == "local_wrong_multicast_type":
            all_v4[-1]["dst"] = "224.0.0.1"
        elif problem == "multicast_wrong_range":
            all_v4[-1].update({"type": "multicast", "dst": "192.168.56.20"})
        elif problem == "local_valid_scoped_ipv4":
            all_v4[-1].update({"dst": "192.168.56.20", "dev": "ens33"})
        elif problem == "local_valid_linklocal_ipv6":
            all_v6[-1].update({"dst": "fe80::1234", "dev": "ens33"})
        elif problem == "local_valid_multicast_ipv4":
            all_v4[-1].update({"type": "multicast", "dst": "224.0.0.0/4", "dev": "ens33"})
        elif problem == "local_valid_multicast_ipv6":
            all_v6[-1].update({"type": "multicast", "dst": "ff00::/8", "dev": "ens33"})
        elif problem == "local_valid_limited_broadcast":
            all_v4[-1].update({"type": "broadcast", "dst": "255.255.255.255", "dev": "ens33"})
        for role, data in (("routes-all-v4", all_v4), ("routes-all-v6", all_v6)):
            if problem == "missing_pair" and role == "routes-all-v6":
                break
            path = root / (role + ".json")
            raw = json.dumps(data).encode("utf-8")
            path.write_bytes(raw)
            args.extend(["--" + role, str(path),
                         "--expected-" + role + "-sha256",
                         hashlib.sha256(raw).hexdigest()])
        if problem == "changed_pin":
            (root / "routes-all-v4.json").write_bytes(b"[]")
        elif problem == "duplicate_path":
            args[args.index("--routes-all-v4") + 1] = str(root / "routes-v4.json")
    return _run(tmp_path, snapshots, tamper=extra)


def test_optional_seven_snapshot_all_table_screen_accepts_consistent_private_inputs(tmp_path):
    result = _run_with_all_tables(tmp_path, _snapshots())
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["seven_distinct_sha256_pinned_snapshots_checked"] is True
    assert report["all_routing_tables_in_supplied_snapshots_checked"] is True
    assert report["other_routing_tables_checked"] is False
    assert report["vmware_hostonly_isolation_verified"] is False
    assert "192.168.56.20" not in result.stdout
    assert str(tmp_path) not in result.stdout


@pytest.mark.parametrize("problem", [
    "alternate_v4", "alternate_v6", "extra_main", "missing_main",
    "local_gateway", "local_default", "local_wrong_family",
    "local_wrong_dev", "local_wrong_type", "changed_pin",
    "missing_pair", "duplicate_path", "local_public_ipv4",
    "local_other_private_subnet", "local_public_ipv6",
    "local_wrong_loopback_scope", "local_wrong_multicast_type",
    "multicast_wrong_range",
])
def test_optional_all_table_gate_refuses_unsafe_or_incomplete_snapshots(tmp_path, problem):
    result = _run_with_all_tables(tmp_path, _snapshots(), problem=problem)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert str(tmp_path) not in result.stderr


@pytest.mark.parametrize("variant", [
    "local_valid_scoped_ipv4", "local_valid_linklocal_ipv6",
    "local_valid_multicast_ipv4", "local_valid_multicast_ipv6",
    "local_valid_limited_broadcast",
])
def test_optional_all_table_gate_accepts_scoped_kernel_local_routes(tmp_path, variant):
    result = _run_with_all_tables(tmp_path, _snapshots(), problem=variant)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["all_routing_tables_in_supplied_snapshots_checked"] is True
    assert report["vmware_hostonly_isolation_verified"] is False
