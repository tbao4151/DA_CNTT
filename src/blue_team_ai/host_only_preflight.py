"""Offline assessment of a Windows host adapter snapshot for a proposed lab.

This validates a *configuration snapshot*, not VMware guest configuration,
physical isolation, capture authenticity, or permission to generate traffic.
It never opens sockets or invokes operating-system commands.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Mapping


class LabPreflightError(ValueError):
    """Invalid, incomplete, or unsafe declared lab configuration."""


def assess_host_only_snapshot(
    snapshot: Mapping[str, object], *, expected_adapter: str, expected_cidr: str
) -> dict[str, object]:
    """Fail closed on unsafe host-side configuration, without claiming isolation.

    The caller must separately check VMware Virtual Network Editor, *every*
    guest NIC, guest routes, bridging/NAT and authorization before lab traffic.
    """
    if (not isinstance(snapshot, Mapping)
            or type(snapshot.get("schema_version")) is not int
            or snapshot["schema_version"] not in (1, 2)):
        raise LabPreflightError("Unsupported host adapter snapshot schema")
    # Legacy v1 is accepted for old evidence but has no IPv6 visibility.
    required = {
        "schema_version", "capture_origin", "adapter_name", "adapter_status",
        "adapter_ipv4", "adapter_default_routes", "adapter_dns_servers",
    }
    if snapshot["schema_version"] == 2:
        required |= {
            "adapter_ipv6", "adapter_default_routes_ipv6", "adapter_dns_servers_ipv6",
        }
    if set(snapshot) != required:
        raise LabPreflightError("Unexpected host adapter snapshot fields")
    if snapshot.get("capture_origin") != "windows_host_network_configuration":
        raise LabPreflightError("Unrecognized snapshot source declaration")
    if not isinstance(expected_adapter, str) or not expected_adapter.strip():
        raise LabPreflightError("Explicit host-only adapter name required")
    if snapshot.get("adapter_name") != expected_adapter:
        raise LabPreflightError("Host adapter name differs from expected adapter")
    if snapshot.get("adapter_status") != "Up":
        raise LabPreflightError("Host-only adapter is not Up")
    try:
        scope = ipaddress.ip_network(expected_cidr, strict=True)
    except (ValueError, TypeError) as exc:
        raise LabPreflightError("Invalid expected CIDR") from exc
    if (
        not isinstance(scope, ipaddress.IPv4Network)
        or not scope.is_private
        or scope.is_loopback
        or scope.is_link_local
        or scope.is_multicast
        or not any(scope.subnet_of(private) for private in (
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        ))
        or scope.prefixlen < 16
        or scope.prefixlen > 30
    ):
        raise LabPreflightError("Expected CIDR must be a narrow private IPv4 lab subnet")
    addresses = snapshot.get("adapter_ipv4")
    if not isinstance(addresses, list) or len(addresses) != 1:
        raise LabPreflightError("Exactly one host adapter IPv4 address required")
    address = addresses[0]
    if not isinstance(address, Mapping) or set(address) != {"address", "prefix_length"}:
        raise LabPreflightError("Invalid host adapter IPv4 entry")
    try:
        if not isinstance(address["address"], str):
            raise ValueError("Host IP must be a string")
        host_ip = ipaddress.IPv4Address(address["address"])
        prefix = address["prefix_length"]
        if type(prefix) is not int:
            raise ValueError("Prefix must be an integer")
        host_interface = ipaddress.IPv4Interface(f"{host_ip}/{prefix}")
    except (ValueError, TypeError, ipaddress.AddressValueError) as exc:
        raise LabPreflightError("Invalid host adapter IPv4 configuration") from exc
    if host_interface.network != scope or host_ip in (scope.network_address, scope.broadcast_address):
        raise LabPreflightError("Host adapter IP/prefix does not match approved subnet")
    if snapshot.get("adapter_default_routes") != []:
        raise LabPreflightError("Lab adapter must not have a default route")
    if snapshot.get("adapter_dns_servers") != []:
        raise LabPreflightError("Lab adapter must not declare DNS servers")
    ipv6_screened = snapshot["schema_version"] == 2
    if ipv6_screened:
        if (snapshot["adapter_default_routes_ipv6"] != []
                or snapshot["adapter_dns_servers_ipv6"] != []):
            raise LabPreflightError("Lab adapter must not have IPv6 default routes or DNS")
        ipv6_addresses = snapshot["adapter_ipv6"]
        if not isinstance(ipv6_addresses, list) or len(ipv6_addresses) > 8:
            raise LabPreflightError("Invalid bounded host IPv6 inventory")
        normalized: set[str] = set()
        for value in ipv6_addresses:
            if not isinstance(value, str) or not value or value.strip() != value:
                raise LabPreflightError("Invalid host IPv6 address")
            # Windows may append a numeric interface zone to link-local IPs.
            address, separator, zone = value.partition("%")
            if separator and (not zone.isascii() or not zone.isdecimal()):
                raise LabPreflightError("Invalid host IPv6 interface zone")
            try:
                parsed = ipaddress.IPv6Address(address)
            except ValueError as exc:
                raise LabPreflightError("Invalid host IPv6 address") from exc
            if not parsed.is_link_local or str(parsed) in normalized:
                raise LabPreflightError("Non-link-local or duplicate host IPv6 address")
            normalized.add(str(parsed))
    return {
        "report_version": 1,
        "mode": "offline_windows_host_adapter_configuration_preflight",
        "host_adapter_configuration_passed": True,
        "host_adapter_name_matches": True,
        "expected_private_subnet_matches": True,
        "host_adapter_has_no_default_route_or_dns": True,
        "host_ipv6_screened": ipv6_screened,
        "host_non_link_local_ipv6_absent": True if ipv6_screened else None,
        "host_ipv6_default_route_dns_absent": True if ipv6_screened else None,
        "vmware_virtual_network_editor_verified": False,
        "guest_nics_and_routes_verified": False,
        "physical_host_only_isolation_verified": False,
        "traffic_authorized": False,
        "network_activity_performed": False,
        "interpretation": (
            "Host-side IPv4 configuration passed offline checks. "
            + ("IPv6 addresses/routes/DNS were checked in snapshot v2. "
               if ipv6_screened else
               "Legacy v1 does NOT record IPv6; collect v2 before lab acceptance. ")
            + "Inspect VMware mode, all host/guest NICs/routes and written "
            "authorization independently before any lab traffic."
        ),
    }
