"""Offline combined Linux guest NIC/main-route and policy-rule snapshot screen.

This CLI never reads live kernel state, invokes iproute2, or sends traffic.
Five independent SHA-256 pins cover operator-supplied private JSON snapshots.
A PASS is not proof of VMware isolation or authorization.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from check_linux_guest_network_preflight import _read_json, assess as assess_network
from check_linux_guest_policy_rules import assess as assess_policy

ROLES = ("addresses", "routes-v4", "routes-v6", "rules-v4", "rules-v6")


def assess(addresses, routes_v4, routes_v6, rules_v4, rules_v6, *,
           adapter: str, cidr: str):
    """Require BOTH existing offline screens to pass; never merge partial PASS."""
    network = assess_network(addresses, routes_v4, routes_v6,
                             adapter=adapter, cidr=cidr)
    policy = assess_policy(rules_v4, rules_v6)
    return {
        "report_version": 1,
        "mode": "offline_linux_guest_combined_snapshot_screen_only",
        "five_distinct_sha256_pinned_snapshots_checked": True,
        "linux_guest_main_route_snapshot_passed":
            network["linux_guest_configuration_screen_passed"],
        "linux_guest_policy_rules_snapshot_passed":
            policy["policy_rules_snapshot_passed"],
        "other_routing_tables_checked": False,
        "dns_and_forwarding_checked": False,
        "vmware_hostonly_isolation_verified": False,
        "traffic_authorized": False,
        "network_activity_performed": False,
        "interpretation": (
            "Both existing screens passed on five independently pinned "
            "operator-supplied snapshots only. Independently inspect all "
            "routing tables, VMnet/NIC modes, DNS, forwarding, firewalls "
            "and written authorization before generating traffic."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ROLES:
        parser.add_argument("--" + role, required=True, type=Path)
        parser.add_argument("--expected-" + role + "-sha256", required=True)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--cidr", required=True)
    args = parser.parse_args(argv)
    try:
        paths = [getattr(args, role.replace("-", "_")) for role in ROLES]
        if len({path.resolve(strict=True) for path in paths}) != len(ROLES):
            raise ValueError("Five distinct private snapshots required")
        snapshots = [
            _read_json(path, getattr(args, "expected_" + role.replace("-", "_") + "_sha256"))
            for path, role in zip(paths, ROLES)
        ]
        report = assess(*snapshots, adapter=args.adapter, cidr=args.cidr)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        print("Linux guest combined offline snapshot screen refused.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
