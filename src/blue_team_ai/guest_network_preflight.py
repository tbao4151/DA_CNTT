"""Fail-closed OFFLINE assessment of an operator-provided Windows guest snapshot.

This is a local configuration consistency screen, never an isolation attestation.
No sockets, guest control, packet capture or operating-system commands.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Mapping


class GuestPreflightError(ValueError):
    """Malformed or unsuitable declared guest network configuration."""


def assess_guest_network_snapshot(
    snapshot: Mapping[str, object], *, expected_adapter: str, expected_cidr: str
) -> dict[str, object]:
    if not isinstance(snapshot, Mapping) or set(snapshot) != {
        "schema_version", "capture_origin", "adapters", "default_routes_ipv4",
        "default_routes_ipv6", "dns_servers_ipv4", "dns_servers_ipv6",
    }:
        raise GuestPreflightError("Unexpected guest snapshot schema")
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
        raise GuestPreflightError("Unsupported guest snapshot version")
    if snapshot["capture_origin"] != "windows_guest_network_configuration":
        raise GuestPreflightError("Unexpected guest snapshot origin declaration")
    if not isinstance(expected_adapter, str) or not expected_adapter.strip():
        raise GuestPreflightError("Explicit guest adapter name required")
    try:
        scope = ipaddress.ip_network(expected_cidr, strict=True)
    except (ValueError, TypeError) as exc:
        raise GuestPreflightError("Invalid declared lab subnet") from exc
    private_blocks = tuple(map(ipaddress.IPv4Network, (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    )))
    if (not isinstance(scope, ipaddress.IPv4Network)
            or not any(scope.subnet_of(block) for block in private_blocks)
            or not 16 <= scope.prefixlen <= 30):
        raise GuestPreflightError("Expected a narrow RFC1918 IPv4 lab subnet")
    for key in ("default_routes_ipv4", "default_routes_ipv6", "dns_servers_ipv4", "dns_servers_ipv6"):
        if snapshot[key] != []:
            raise GuestPreflightError("Guest has a declared default route or DNS server")
    adapters = snapshot["adapters"]
    if not isinstance(adapters, list) or not 1 <= len(adapters) <= 16:
        raise GuestPreflightError("Invalid guest adapter inventory")
    names: set[str] = set()
    indices: set[int] = set()
    active = []
    for adapter in adapters:
        if not isinstance(adapter, Mapping) or set(adapter) != {
            "name", "status", "if_index", "ipv4", "ipv6",
        }:
            raise GuestPreflightError("Malformed guest adapter entry")
        name, status, index = adapter["name"], adapter["status"], adapter["if_index"]
        if (not isinstance(name, str) or not name.strip() or name in names
                or type(index) is not int or index <= 0 or index in indices
                or not isinstance(status, str) or not status.strip()):
            raise GuestPreflightError("Duplicate or malformed guest adapter")
        names.add(name)
        indices.add(index)
        ipv4, ipv6 = adapter["ipv4"], adapter["ipv6"]
        if not isinstance(ipv4, list) or not isinstance(ipv6, list):
            raise GuestPreflightError("Malformed guest IP inventory")
        if status == "Up":
            active.append(adapter)
        elif len(ipv4) > 0 or len(ipv6) > 0:
            raise GuestPreflightError("Inactive guest adapter has configured IPs")
    if len(active) != 1 or active[0]["name"] != expected_adapter:
        raise GuestPreflightError("Exactly one expected guest adapter must be Up")
    nic = active[0]
    if len(nic["ipv4"]) != 1:
        raise GuestPreflightError("Expected exactly one guest IPv4 address")
    entry = nic["ipv4"][0]
    if not isinstance(entry, Mapping) or set(entry) != {"address", "prefix_length"}:
        raise GuestPreflightError("Malformed guest IPv4 entry")
    if not isinstance(entry["address"], str) or type(entry["prefix_length"]) is not int:
        raise GuestPreflightError("Invalid guest IPv4 types")
    try:
        interface = ipaddress.IPv4Interface(f"{entry['address']}/{entry['prefix_length']}")
    except ValueError as exc:
        raise GuestPreflightError("Invalid guest IPv4 address") from exc
    if (interface.network != scope or interface.ip in
            (scope.network_address, scope.broadcast_address)):
        raise GuestPreflightError("Guest address/prefix outside approved lab subnet")
    if len(nic["ipv6"]) > 8:
        raise GuestPreflightError("Excessive guest IPv6 addresses")
    for value in nic["ipv6"]:
        if not isinstance(value, str) or "%" in value:
            raise GuestPreflightError("Malformed guest IPv6 address")
        try:
            address = ipaddress.IPv6Address(value)
        except ValueError as exc:
            raise GuestPreflightError("Malformed guest IPv6 address") from exc
        if not address.is_link_local:
            raise GuestPreflightError("Only IPv6 link-local addresses permitted")
    return {
        "report_version": 1,
        "mode": "offline_windows_guest_network_configuration_preflight",
        "guest_snapshot_configuration_passed": True,
        "single_approved_guest_adapter_up": True,
        "guest_ipv4_scope_matches": True,
        "guest_no_default_routes_or_dns": True,
        "guest_ipv6_global_address_absent_in_snapshot": True,
        "host_adapter_verified": False,
        "vmware_virtual_network_editor_verified": False,
        "physical_host_only_isolation_verified": False,
        "traffic_authorized": False,
        "network_activity_performed": False,
        "interpretation": (
            "Only the supplied Windows guest snapshot passed offline checks. "
            "Separately inspect VMware VMnet, host/guest NICs, routes, "
            "authorization and egress before any test traffic."
        ),
    }
