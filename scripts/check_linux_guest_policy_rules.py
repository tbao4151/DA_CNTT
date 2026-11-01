"""Offline, pinned iproute2 policy-rule snapshot screen; no network activity.

This screens only operator-provided IPv4/IPv6 rule JSON, not the kernel,
other routing tables, VMware isolation, or authorization.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from check_linux_guest_network_preflight import _read_json

EXPECTED_V4 = {0: "local", 32766: "main", 32767: "default"}
EXPECTED_V6 = {0: "local", 32766: "main"}
TABLE_IDS = {"local": 255, "main": 254, "default": 253}


def _check_family(rules, expected, *, ipv6=False):
    if not isinstance(rules, list) or not 2 <= len(rules) <= 3:
        raise ValueError("Unexpected policy rule count")
    found = {}
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"priority", "src", "table"}:
            raise ValueError("Unexpected policy selector or action")
        priority = rule["priority"]
        if type(priority) is not int or priority in found:
            raise ValueError("Invalid or repeated policy priority")
        if rule["src"] != "all":
            raise ValueError("Policy rule must match all sources")
        table = rule["table"]
        if type(table) is int:
            table_id = table
        elif isinstance(table, str):
            table_id = TABLE_IDS.get(table)
        else:
            table_id = None
        if priority not in {0, 32766, 32767} or table_id != TABLE_IDS[{
                0: "local", 32766: "main", 32767: "default"}[priority]]:
            raise ValueError("Unexpected policy route table")
        found[priority] = table_id
    if not set(expected).issubset(found):
        raise ValueError("Missing mandatory kernel policy rule")
    if not ipv6 and set(found) != set(expected):
        raise ValueError("IPv4 kernel policy rule set changed")
    if ipv6 and set(found) not in ({0, 32766}, {0, 32766, 32767}):
        raise ValueError("IPv6 policy rule set changed")


def assess(rules_v4, rules_v6):
    _check_family(rules_v4, EXPECTED_V4)
    _check_family(rules_v6, EXPECTED_V6, ipv6=True)
    return {
        "report_version": 1,
        "mode": "offline_linux_guest_policy_rules_snapshot_screen_only",
        "default_ipv4_policy_rules_only": True,
        "default_ipv6_policy_rules_only": True,
        "policy_rules_snapshot_passed": True,
        "main_routes_checked": False,
        "other_routing_tables_checked": False,
        "vmware_hostonly_isolation_verified": False,
        "traffic_authorized": False,
        "network_activity_performed": False,
        "interpretation": (
            "Pinned operator-supplied policy-rule JSON only. Review all routing "
            "tables, VMnet, NIC modes, forwarding, DNS and authorization separately."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("rules-v4", "rules-v6"):
        parser.add_argument("--" + role, required=True, type=Path)
        parser.add_argument("--expected-" + role + "-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.rules_v4.resolve(strict=True) == args.rules_v6.resolve(strict=True):
            raise ValueError("Distinct policy rule snapshots required")
        v4 = _read_json(args.rules_v4, args.expected_rules_v4_sha256)
        v6 = _read_json(args.rules_v6, args.expected_rules_v6_sha256)
        report = assess(v4, v6)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        print("Linux guest offline policy rule screen refused.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
