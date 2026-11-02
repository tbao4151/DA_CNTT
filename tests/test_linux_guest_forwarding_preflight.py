"""Synthetic-only tests: no VMware, sysctl invocation or network traffic."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_linux_guest_forwarding_preflight.py"
KEYS = (
    "net.ipv4.ip_forward",
    "net.ipv4.conf.all.forwarding",
    "net.ipv4.conf.default.forwarding",
    "net.ipv4.conf.ens33.forwarding",
    "net.ipv6.conf.all.forwarding",
    "net.ipv6.conf.default.forwarding",
    "net.ipv6.conf.ens33.forwarding",
)


def _raw(values=None):
    values = values or {key: "0" for key in KEYS}
    return ("\n".join(f"{key} = {value}" for key, value in values.items()) + "\n").encode()


def _run(tmp_path, raw=None, *, pin=None, adapter="ens33"):
    raw = _raw() if raw is None else raw
    path = tmp_path / "forwarding.txt"
    path.write_bytes(raw)
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--snapshot", str(path),
         "--expected-sha256", pin or hashlib.sha256(raw).hexdigest(),
         "--adapter", adapter],
        capture_output=True, text=True,
    )


def test_zero_forwarding_snapshot_passes_without_isolation_claim(tmp_path):
    result = _run(tmp_path)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["seven_required_forwarding_sysctls_pinned_and_zero"] is True
    for key in ("all_interfaces_forwarding_checked", "live_kernel_state_verified",
                "dns_and_firewall_checked", "vmware_hostonly_isolation_verified",
                "traffic_authorized", "network_activity_performed"):
        assert report[key] is False
    assert "ens33" not in result.stdout
    assert str(tmp_path) not in result.stdout


@pytest.mark.parametrize("key", KEYS)
def test_each_enabled_forwarding_setting_is_rejected(tmp_path, key):
    values = {item: ("1" if item == key else "0") for item in KEYS}
    result = _run(tmp_path, _raw(values))
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr


@pytest.mark.parametrize("variant", ["missing", "extra", "duplicate", "invalid",
                                      "bad_key", "blank", "non_utf8"])
def test_invalid_or_incomplete_snapshot_is_rejected(tmp_path, variant):
    lines = _raw().decode().splitlines()
    if variant == "missing":
        lines.pop()
    elif variant == "extra":
        lines.append("net.ipv6.conf.eth9.forwarding = 0")
    elif variant == "duplicate":
        lines[-1] = lines[0]
    elif variant == "invalid":
        lines[-1] = lines[-1].replace("= 0", "= 2")
    elif variant == "bad_key":
        lines[-1] = "net.ipv6.conf.all.accept_ra = 0"
    elif variant == "blank":
        lines.append("")
    raw = b"\xff" if variant == "non_utf8" else ("\n".join(lines) + "\n").encode()
    result = _run(tmp_path, raw)
    assert result.returncode == 1
    assert result.stdout == ""


def test_independently_pinned_hash_mismatch_is_rejected(tmp_path):
    result = _run(tmp_path, pin="0" * 64)
    assert result.returncode == 1
    assert result.stdout == ""


@pytest.mark.parametrize("adapter", ["lo", "all", "default", "../eth0", "ens33/0", ""])
def test_unapproved_interface_name_is_rejected(tmp_path, adapter):
    result = _run(tmp_path, adapter=adapter)
    assert result.returncode == 1
    assert result.stdout == ""


def test_crlf_sysctl_output_is_supported(tmp_path):
    result = _run(tmp_path, _raw().replace(b"\n", b"\r\n"))
    assert result.returncode == 0, result.stderr
