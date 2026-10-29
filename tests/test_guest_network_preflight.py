"""Synthetic-only Windows guest snapshot checks; no VMware or network used."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.guest_network_preflight import (
    GuestPreflightError, assess_guest_network_snapshot,
)


def snapshot():
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


def check(data):
    return assess_guest_network_snapshot(
        data, expected_adapter="Ethernet0", expected_cidr="192.168.77.0/24",
    )


def test_guest_snapshot_passes_but_never_attests_isolation():
    report = check(snapshot())
    assert report["guest_snapshot_configuration_passed"] is True
    assert report["physical_host_only_isolation_verified"] is False
    assert report["traffic_authorized"] is False
    assert report["network_activity_performed"] is False
    assert "192.168.77" not in json.dumps(report)


@pytest.mark.parametrize("field,value", [
    ("default_routes_ipv4", ["7:192.168.77.1"]),
    ("default_routes_ipv6", ["7:fe80::1"]),
    ("dns_servers_ipv4", ["192.168.77.1"]),
    ("dns_servers_ipv6", ["fe80::1"]),
    ("capture_origin", "untrusted_live"),
    ("schema_version", True),
    ("schema_version", 2),
    ("adapters", []),
    ("adapters", "not-an-array"),
])
def test_bad_top_level_refused(field, value):
    data = snapshot()
    data[field] = value
    with pytest.raises(GuestPreflightError):
        check(data)


@pytest.mark.parametrize("field,value", [
    ("name", "Wi-Fi"), ("status", "Down"), ("if_index", True),
    ("ipv4", []),
    ("ipv4", [{"address": "8.8.8.8", "prefix_length": 24}]),
    ("ipv4", [{"address": "192.168.77.10", "prefix_length": 16}]),
    ("ipv4", [{"address": "192.168.77.10", "prefix_length": True}]),
    ("ipv6", ["2001:4860::1"]), ("ipv6", ["::1"]),
    ("ipv6", ["fe80::1%7"]),
])
def test_bad_active_adapter_refused(field, value):
    data = snapshot()
    data["adapters"][0][field] = value
    with pytest.raises(GuestPreflightError):
        check(data)


def test_second_active_nic_and_duplicate_indices_refused():
    data = snapshot()
    data["adapters"][1]["status"] = "Up"
    with pytest.raises(GuestPreflightError):
        check(data)
    data = snapshot()
    data["adapters"][1]["if_index"] = 7
    with pytest.raises(GuestPreflightError):
        check(data)
    data = snapshot()
    data["adapters"][1]["ipv4"] = [{"address": "10.0.0.2", "prefix_length": 24}]
    with pytest.raises(GuestPreflightError):
        check(data)


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "8.8.8.0/24", "198.18.0.0/24", "192.168.77.1/24", "::1/128"])
def test_noncanonical_or_nonprivate_scope_refused(cidr):
    with pytest.raises(GuestPreflightError):
        assess_guest_network_snapshot(snapshot(), expected_adapter="Ethernet0", expected_cidr=cidr)


def run_cli(tmp_path, raw, pin=None):
    path = tmp_path / "guest.json"
    path.write_bytes(raw)
    return subprocess.run([
        sys.executable, str(ROOT / "scripts/check_guest_network_preflight.py"),
        "--snapshot", str(path),
        "--expected-snapshot-sha256", pin or hashlib.sha256(raw).hexdigest(),
        "--adapter", "Ethernet0", "--cidr", "192.168.77.0/24",
    ], capture_output=True, text=True)


def test_cli_success_and_tampering(tmp_path):
    raw = json.dumps(snapshot()).encode()
    ok = run_cli(tmp_path, raw)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["physical_host_only_isolation_verified"] is False
    bad = run_cli(tmp_path, raw, "0" * 64)
    assert bad.returncode == 1 and bad.stdout == ""
    assert "192.168.77" not in bad.stderr


@pytest.mark.parametrize("raw", [
    b'{"schema_version":1,"schema_version":1}',
    b'{"schema_version":NaN}',
    b'x' * (64 * 1024 + 1),
    b'\\xff',
])
def test_cli_malformed_and_oversized_fail_closed(tmp_path, raw):
    result = run_cli(tmp_path, raw)
    assert result.returncode == 1 and result.stdout == ""
