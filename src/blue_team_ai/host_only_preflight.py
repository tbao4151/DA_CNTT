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
    if not isinstance(snapshot, Mapping) or type(snapshot.get("schema_version")) is not int or snapshot.get("schema_version") != 1:
        raise LabPreflightError("Unsupported host adapter snapshot schema")
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
    return {
        "report_version": 1,
        "mode": "offline_windows_host_adapter_configuration_preflight",
        "host_adapter_configuration_passed": True,
        "host_adapter_name_matches": True,
        "expected_private_subnet_matches": True,
        "host_adapter_has_no_default_route_or_dns": True,
        "vmware_virtual_network_editor_verified": False,
        "guest_nics_and_routes_verified": False,
        "physical_host_only_isolation_verified": False,
        "traffic_authorized": False,
        "network_activity_performed": False,
        "interpretation": (
            "Host-side configuration snapshot passed offline checks only. "
            "Inspect VMware network mode, guest NICs/routes and written scope "
            "authorization independently before any lab traffic."
        ),
    }
