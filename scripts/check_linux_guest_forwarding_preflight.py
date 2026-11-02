"""Read-only, pinned Linux guest forwarding sysctl snapshot screen.

This validates operator-supplied text, not the running kernel, VMware
isolation, authorization or any network activity.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 4096
PIN = re.compile(r"[0-9a-f]{64}\Z")
ADAPTER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}\Z")
LINE = re.compile(r"(net\.[a-z0-9_.-]+)\s*=\s*([01])\Z")


def required_keys(adapter: str) -> set[str]:
    if (not isinstance(adapter, str) or ADAPTER.fullmatch(adapter) is None
            or adapter in {"lo", "all", "default"}):
        raise ValueError("Invalid approved Linux interface")
    return {
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.forwarding",
        "net.ipv4.conf.default.forwarding",
        f"net.ipv4.conf.{adapter}.forwarding",
        "net.ipv6.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding",
        f"net.ipv6.conf.{adapter}.forwarding",
    }


def read_pinned(path: Path, expected_sha256: str) -> bytes:
    if not isinstance(expected_sha256, str) or PIN.fullmatch(expected_sha256) is None:
        raise ValueError("Expected lowercase SHA-256 required")
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Require absolute non-symlink private file")
    if path.resolve(strict=True).is_relative_to(ROOT):
        raise ValueError("Snapshot must be outside repository")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Require regular snapshot file")
        raw = handle.read(MAX_BYTES + 1)
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("Empty or oversized forwarding snapshot")
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
        raise ValueError("Forwarding snapshot hash mismatch")
    return raw


def assess(raw: bytes, *, adapter: str) -> dict[str, object]:
    expected = required_keys(adapter)
    lines = raw.decode("utf-8", errors="strict").splitlines()
    if len(lines) != len(expected):
        raise ValueError("Missing or unexpected forwarding sysctl lines")
    seen: set[str] = set()
    for line in lines:
        match = LINE.fullmatch(line.strip())
        if match is None:
            raise ValueError("Malformed forwarding sysctl line")
        key, value = match.groups()
        if key not in expected or key in seen or value != "0":
            raise ValueError("Unexpected, duplicate or enabled forwarding sysctl")
        seen.add(key)
    if seen != expected:
        raise ValueError("Incomplete forwarding sysctl snapshot")
    return {
        "report_version": 1,
        "mode": "offline_linux_guest_forwarding_snapshot_screen_only",
        "seven_required_forwarding_sysctls_pinned_and_zero": True,
        "selected_interface_forwarding_snapshot_checked": True,
        "all_interfaces_forwarding_checked": False,
        "live_kernel_state_verified": False,
        "dns_and_firewall_checked": False,
        "vmware_hostonly_isolation_verified": False,
        "traffic_authorized": False,
        "network_activity_performed": False,
        "interpretation": (
            "Seven operator-supplied sysctl values are zero in the pinned file. "
            "This does not verify other interfaces, live kernel state, VMware "
            "network isolation, DNS, firewall or authorization."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--adapter", required=True)
    args = parser.parse_args(argv)
    try:
        report = assess(read_pinned(args.snapshot, args.expected_sha256),
                        adapter=args.adapter)
    except (OSError, ValueError, TypeError, UnicodeError):
        print("Linux guest forwarding offline snapshot screen refused.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
