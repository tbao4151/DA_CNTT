"""Read-only, SHA-256-pinned screening of Linux guest iproute2 JSON snapshots.

This checks declared configuration only. It does not contact a VM, inspect
policy-routing tables, prove VMware Host-only isolation or authorize traffic.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"[0-9a-f]{64}\\Z")
MAX_JSON_BYTES = 256 * 1024
PRIVATE_BLOCKS = tuple(map(ipaddress.IPv4Network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
)))


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate snapshot JSON key")
        result[key] = value
    return result


def _read_json(path: Path, pin: str):
    if not isinstance(pin, str) or PIN.fullmatch(pin) is None:
        raise ValueError("Expected lowercase SHA-256")
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Expected absolute non-symlink private snapshot")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT):
        raise ValueError("Do not read lab snapshots from the repository")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as source:
        if not os.path.isfile(path):
            raise ValueError("Expected regular snapshot file")
        raw = source.read(MAX_JSON_BYTES + 1)
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise ValueError("Empty or oversized snapshot")
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), pin):
        raise ValueError("Pinned Linux guest snapshot changed")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    if not isinstance(data, list) or len(data) > 64:
        raise ValueError("Expected bounded iproute2 JSON list")
    return data


def _scope(cidr: str):
    try:
        network = ipaddress.ip_network(cidr, strict=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid lab CIDR") from exc
    if (not isinstance(network, ipaddress.IPv4Network)
            or not 16 <= network.prefixlen <= 30
            or not any(network.subnet_of(block) for block in PRIVATE_BLOCKS)):
        raise ValueError("Require narrow RFC1918 lab CIDR")
    return network


def assess(addresses, routes_v4, routes_v6, *, adapter: str, cidr: str):
    """Fail closed on extra active NICs, non-lab addresses and routed egress."""
    scope = _scope(cidr)
    if not isinstance(adapter, str) or not adapter.strip() or adapter == "lo":
        raise ValueError("Explicit non-loopback guest adapter required")
    if not isinstance(addresses, list) or not 1 <= len(addresses) <= 32:
        raise ValueError("Invalid guest interface inventory")
    names = set()
    selected = None
    for nic in addresses:
        if not isinstance(nic, dict):
            raise ValueError("Malformed guest interface")
        name, flags, info = nic.get("ifname"), nic.get("flags"), nic.get("addr_info")
        if (not isinstance(name, str) or not name or name in names
                or not isinstance(flags, list) or not all(isinstance(f, str) for f in flags)
                or not isinstance(info, list) or len(info) > 32):
            raise ValueError("Malformed or duplicate guest interface")
        names.add(name)
        if name == "lo":
            if "LOOPBACK" not in flags:
                raise ValueError("Invalid loopback interface")
            continue
        if name != adapter:
            if "UP" in flags or info:
                raise ValueError("Unexpected active or addressed guest interface")
            continue
        if selected is not None or "UP" not in flags or "LOOPBACK" in flags:
            raise ValueError("Expected lab interface must be UP")
        selected = info
    if selected is None:
        raise ValueError("Missing approved Linux guest adapter")

    ipv4_count = 0
    ipv6_count = 0
    seen_addresses = set()
    for entry in selected:
        if not isinstance(entry, dict):
            raise ValueError("Malformed guest address")
        family, local, prefix = entry.get("family"), entry.get("local"), entry.get("prefixlen")
        if (family not in ("inet", "inet6") or not isinstance(local, str)
                or type(prefix) is not int or "%" in local):
            raise ValueError("Unsupported guest address")
        try:
            address = ipaddress.ip_address(local)
            interface = ipaddress.ip_interface(f"{local}/{prefix}")
        except ValueError as exc:
            raise ValueError("Invalid guest IP address") from exc
        if str(address) in seen_addresses:
            raise ValueError("Duplicate guest address")
        seen_addresses.add(str(address))
        if family == "inet":
            if (not isinstance(address, ipaddress.IPv4Address)
                    or interface.network != scope
                    or address in (scope.network_address, scope.broadcast_address)):
                raise ValueError("Guest IPv4 differs from approved scope")
            ipv4_count += 1
        else:
            if not isinstance(address, ipaddress.IPv6Address) or not address.is_link_local:
                raise ValueError("Non-link-local guest IPv6 address")
            ipv6_count += 1
    if ipv4_count != 1 or ipv6_count > 8:
        raise ValueError("Expected one scoped IPv4 and at most eight link-local IPv6 addresses")

    for version, routes in ((4, routes_v4), (6, routes_v6)):
        if not isinstance(routes, list) or len(routes) > 256:
            raise ValueError("Invalid bounded route inventory")
        for route in routes:
            if not isinstance(route, dict):
                raise ValueError("Malformed guest route")
            destination = route.get("dst")
            if (not isinstance(destination, str) or destination == "default"
                    or route.get("dev") != adapter
                    or any(key in route for key in ("gateway", "via", "multipath", "nhid"))
                    or route.get("type", "unicast") != "unicast"):
                raise ValueError("Unapproved guest route or gateway")
            try:
                network = ipaddress.ip_network(destination, strict=False)
            except ValueError as exc:
                raise ValueError("Invalid guest route destination") from exc
            if version == 4:
                if not isinstance(network, ipaddress.IPv4Network) or not network.subnet_of(scope):
                    raise ValueError("IPv4 route outside Host-only scope")
            elif (not isinstance(network, ipaddress.IPv6Network)
                  or not network.subnet_of(ipaddress.IPv6Network("fe80::/10"))):
                raise ValueError("IPv6 route outside link-local scope")
    if not any(isinstance(route, dict) and route.get("dst") == str(scope)
               for route in routes_v4):
        raise ValueError("Missing direct approved IPv4 subnet route")
    return {
        "report_version": 1,
        "mode": "offline_linux_guest_main_route_configuration_screen_only",
        "linux_guest_configuration_screen_passed": True,
        "single_approved_guest_adapter_up": True,
        "approved_ipv4_scope_matches": True,
        "non_link_local_ipv6_absent_in_snapshot": True,
        "main_table_routes_restricted_to_lab_or_link_local": True,
        "ipv6_link_local_address_count": ipv6_count,
        "other_routing_tables_checked": False,
        "dns_and_forwarding_checked": False,
        "vmware_hostonly_isolation_verified": False,
        "traffic_authorized": False,
        "network_activity_performed": False,
        "interpretation": (
            "Pinned operator-provided iproute2 address and main-table route snapshots only. "
            "Independently inspect every VM NIC, all routing tables, DNS, forwarding, "
            "VMware Virtual Network Editor, IPv6 and written authorization."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("addresses", "routes-v4", "routes-v6"):
        parser.add_argument("--" + role, type=Path, required=True)
        parser.add_argument("--expected-" + role + "-sha256", required=True)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--cidr", required=True)
    args = parser.parse_args(argv)
    try:
        paths = [args.addresses, args.routes_v4, args.routes_v6]
        if len({p.resolve(strict=True) for p in paths}) != 3:
            raise ValueError("Distinct snapshot files required")
        data = [
            _read_json(path, getattr(args, "expected_" + role.replace("-", "_") + "_sha256"))
            for path, role in zip(paths, ("addresses", "routes-v4", "routes-v6"))
        ]
        report = assess(*data, adapter=args.adapter, cidr=args.cidr)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        print("Linux guest offline configuration screen refused.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
