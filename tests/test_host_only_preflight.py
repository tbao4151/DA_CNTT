"""Synthetic offline host-side configuration tests, not VMware lab acceptance."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.host_only_preflight import LabPreflightError, assess_host_only_snapshot


def snapshot():
    return {
        "schema_version": 1,
        "capture_origin": "windows_host_network_configuration",
        "adapter_name": "VMware Network Adapter VMnet1",
        "adapter_status": "Up",
        "adapter_ipv4": [{"address": "192.168.77.1", "prefix_length": 24}],
        "adapter_default_routes": [],
        "adapter_dns_servers": [],
    }


def check(s):
    return assess_host_only_snapshot(
        s, expected_adapter="VMware Network Adapter VMnet1", expected_cidr="192.168.77.0/24"
    )


def test_valid_snapshot_never_claims_physical_isolation_or_authorization():
    report = check(snapshot())
    assert report["host_adapter_configuration_passed"] is True
    assert report["physical_host_only_isolation_verified"] is False
    assert report["traffic_authorized"] is False
    assert report["network_activity_performed"] is False
    assert "192.168.77" not in json.dumps(report)


@pytest.mark.parametrize("change", [
    {"adapter_status": "Down"}, {"adapter_default_routes": ["192.168.77.254"]},
    {"adapter_dns_servers": ["8.8.8.8"]}, {"adapter_name": "Wi-Fi"},
    {"adapter_ipv4": []},
    {"adapter_ipv4": [{"address": "10.0.0.1", "prefix_length": 24}]},
    {"adapter_ipv4": [{"address": "192.168.77.1", "prefix_length": 16}]},
    {"adapter_ipv4": [{"address": "192.168.77.1", "prefix_length": True}]},
    {"adapter_ipv4": [{"address": "192.168.77.1", "prefix_length": 24},
                      {"address": "192.168.77.2", "prefix_length": 24}]},
    {"capture_origin": "synthetic_claimed_live"}, {"schema_version": 2},
])
def test_unsafe_host_config_refused(change):
    data = snapshot()
    data.update(change)
    with pytest.raises(LabPreflightError):
        check(data)


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "8.8.8.0/24", "127.0.0.0/24", "192.168.77.1/24", "192.168.0.0/8", "198.18.0.0/24", "::1/128"])
def test_unsafe_or_noncanonical_scope_refused(cidr):
    with pytest.raises(LabPreflightError):
        assess_host_only_snapshot(snapshot(), expected_adapter="VMware Network Adapter VMnet1", expected_cidr=cidr)


def run_cli(tmp_path, raw, pin=None):
    path = tmp_path / "snapshot.json"
    path.write_bytes(raw)
    if pin is None:
        pin = hashlib.sha256(raw).hexdigest()
    return subprocess.run([
        sys.executable, str(ROOT / "scripts/check_host_only_preflight.py"),
        "--snapshot", str(path), "--expected-snapshot-sha256", pin,
        "--adapter", "VMware Network Adapter VMnet1", "--cidr", "192.168.77.0/24",
    ], capture_output=True, text=True, check=False)


def test_cli_success_and_pin_refusal(tmp_path):
    raw = json.dumps(snapshot()).encode()
    good = run_cli(tmp_path, raw)
    assert good.returncode == 0
    assert json.loads(good.stdout)["physical_host_only_isolation_verified"] is False
    bom = run_cli(tmp_path, b"\xef\xbb\xbf" + raw)
    assert bom.returncode == 0
    bad = run_cli(tmp_path, raw, "0" * 64)
    assert bad.returncode == 1 and bad.stdout == ""
    assert "192.168.77" not in bad.stderr


def test_cli_rejects_duplicate_keys_and_oversized_snapshots(tmp_path):
    for raw in (b'{"schema_version":1,"schema_version":1}', b"x" * (64 * 1024 + 1)):
        proc = run_cli(tmp_path, raw)
        assert proc.returncode == 1 and proc.stdout == ""


def snapshot_v2():
    result = snapshot()
    result["schema_version"] = 2
    result["adapter_ipv6"] = ["fe80::abcd%11"]
    result["adapter_default_routes_ipv6"] = []
    result["adapter_dns_servers_ipv6"] = []
    return result


def test_v2_ipv6_link_local_only_and_legacy_v1_explicitly_unscreened():
    assert check(snapshot())["host_ipv6_screened"] is False
    assert check(snapshot())["host_non_link_local_ipv6_absent"] is None
    report = check(snapshot_v2())
    assert report["host_ipv6_screened"] is True
    assert report["host_non_link_local_ipv6_absent"] is True
    assert report["host_ipv6_default_route_dns_absent"] is True
    assert report["physical_host_only_isolation_verified"] is False
    assert "fe80" not in json.dumps(report)


@pytest.mark.parametrize("field,value", [
    ("adapter_ipv6", ["2001:4860::1"]),
    ("adapter_ipv6", ["fd00::1"]),
    ("adapter_ipv6", ["::1"]),
    ("adapter_ipv6", ["fe80::1", "fe80::1%11"]),
    ("adapter_ipv6", ["fe80::1%evil"]),
    ("adapter_ipv6", ["not-an-ip"]),
    ("adapter_ipv6", "fe80::1"),
    ("adapter_ipv6", ["fe80::1"] * 9),
    ("adapter_default_routes_ipv6", ["fe80::2"]),
    ("adapter_dns_servers_ipv6", ["fe80::2"]),
])
def test_v2_refuses_unsafe_or_malformed_ipv6(field, value):
    data = snapshot_v2()
    data[field] = value
    with pytest.raises(LabPreflightError):
        check(data)


def test_v2_refuses_missing_or_extra_fields_and_v1_extra_ipv6_claim():
    data = snapshot_v2()
    del data["adapter_ipv6"]
    with pytest.raises(LabPreflightError):
        check(data)
    data = snapshot_v2()
    data["isolation_verified"] = True
    with pytest.raises(LabPreflightError):
        check(data)
    data = snapshot()
    data["adapter_ipv6"] = []
    with pytest.raises(LabPreflightError):
        check(data)


def test_cli_accepts_pinned_v2_and_refuses_global_ipv6(tmp_path):
    valid = run_cli(tmp_path, json.dumps(snapshot_v2()).encode())
    assert valid.returncode == 0, valid.stderr
    assert json.loads(valid.stdout)["host_ipv6_screened"] is True
    data = snapshot_v2()
    data["adapter_ipv6"] = ["2001:db8::123"]
    refused = run_cli(tmp_path, json.dumps(data).encode())
    assert refused.returncode == 1 and refused.stdout == ""
