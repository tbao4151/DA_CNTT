"""Offline combined Linux guest NIC/main-route and policy-rule snapshot screen.

This CLI never reads live kernel state, invokes iproute2, or sends traffic.
Five required and two optional SHA-256 pins cover private JSON snapshots.
The optional all-table screen checks only pinned snapshots, not live routes.
A PASS is not proof of VMware isolation or authorization.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from check_linux_guest_network_preflight import _read_json, assess as assess_network
from check_linux_guest_policy_rules import assess as assess_policy
from check_linux_guest_all_tables_preflight import assess_all_tables

ROLES = ("addresses", "routes-v4", "routes-v6", "rules-v4", "rules-v6")


def assess(addresses, routes_v4, routes_v6, rules_v4, rules_v6, *,
           adapter: str, cidr: str, routes_all_v4=None, routes_all_v6=None):
    """Require BOTH existing offline screens to pass; never merge partial PASS."""
    network = assess_network(addresses, routes_v4, routes_v6,
                             adapter=adapter, cidr=cidr)
    policy = assess_policy(rules_v4, rules_v6)
    if (routes_all_v4 is None) != (routes_all_v6 is None):
        raise ValueError("Both all-table route snapshots required")
    all_tables_supplied = routes_all_v4 is not None
    if all_tables_supplied:
        assess_all_tables(routes_v4, routes_v6, routes_all_v4,
                          routes_all_v6, adapter=adapter, cidr=cidr)
    return {
        "report_version": 1,
        "mode": "offline_linux_guest_combined_snapshot_screen_only",
        "five_distinct_sha256_pinned_snapshots_checked": True,
        "linux_guest_main_route_snapshot_passed":
            network["linux_guest_configuration_screen_passed"],
        "linux_guest_policy_rules_snapshot_passed":
            policy["policy_rules_snapshot_passed"],
        "seven_distinct_sha256_pinned_snapshots_checked": all_tables_supplied,
        "all_routing_tables_in_supplied_snapshots_checked": all_tables_supplied,
        "other_routing_tables_checked": False,
        "dns_and_forwarding_checked": False,
        "vmware_hostonly_isolation_verified": False,
        "traffic_authorized": False,
        "network_activity_performed": False,
        "interpretation": (
            "NIC/main-route and RPDB screens passed on five pinned snapshots. "
            "Optional all-table comparison, if supplied, also passed on two "
            "additional pinned snapshots. These are operator-provided files, "
            "not live kernel evidence. Independently inspect VMware NICs, "
            "routing, DNS, forwarding, firewall and written authorization."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ROLES:
        parser.add_argument("--" + role, required=True, type=Path)
        parser.add_argument("--expected-" + role + "-sha256", required=True)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--cidr", required=True)
    for role in ("routes-all-v4", "routes-all-v6"):
        parser.add_argument("--" + role, type=Path)
        parser.add_argument("--expected-" + role + "-sha256")
    args = parser.parse_args(argv)
    try:
        optional = ("routes-all-v4", "routes-all-v6")
        optional_values = [
            getattr(args, role.replace("-", "_")) for role in optional
        ] + [
            getattr(args, "expected_" + role.replace("-", "_") + "_sha256")
            for role in optional
        ]
        if any(value is not None for value in optional_values) and not all(
                value is not None for value in optional_values):
            raise ValueError("Both all-table snapshots and pins required")
        roles = ROLES + optional if all(value is not None for value in optional_values) else ROLES
        paths = [getattr(args, role.replace("-", "_")) for role in roles]
        if len({path.resolve(strict=True) for path in paths}) != len(roles):
            raise ValueError("Distinct private snapshots required")
        snapshots = [
            _read_json(path, getattr(args, "expected_" + role.replace("-", "_") + "_sha256"))
            for path, role in zip(paths, roles)
        ]
        report = assess(*snapshots[:5], adapter=args.adapter, cidr=args.cidr,
                        routes_all_v4=snapshots[5] if len(snapshots) == 7 else None,
                        routes_all_v6=snapshots[6] if len(snapshots) == 7 else None)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        print("Linux guest combined offline snapshot screen refused.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
