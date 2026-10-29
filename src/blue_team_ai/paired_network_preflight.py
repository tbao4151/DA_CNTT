"""Compare pinned host/guest network configuration snapshots without network I/O.

This checks declared metadata consistency, not VMware isolation or permission.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Mapping

from .guest_network_preflight import assess_guest_network_snapshot
from .host_only_preflight import assess_host_only_snapshot


def assess_paired_network_snapshots(
    host: Mapping[str, object], guest: Mapping[str, object], *,
    host_adapter: str, guest_adapter: str, expected_cidr: str,
) -> dict[str, object]:
    """Fail closed unless both strict checks pass and IPv4 addresses differ."""
    if not isinstance(host, Mapping) or set(host) != {
        "schema_version", "capture_origin", "adapter_name", "adapter_status",
        "adapter_ipv4", "adapter_default_routes", "adapter_dns_servers",
    }:
        raise ValueError("Unexpected host snapshot schema")
    host_result = assess_host_only_snapshot(
        host, expected_adapter=host_adapter, expected_cidr=expected_cidr,
    )
    guest_result = assess_guest_network_snapshot(
        guest, expected_adapter=guest_adapter, expected_cidr=expected_cidr,
    )
    if (host_result["host_adapter_configuration_passed"] is not True
            or guest_result["guest_snapshot_configuration_passed"] is not True):
        raise ValueError("Host or guest configuration check failed")
    host_ip = ipaddress.IPv4Address(host["adapter_ipv4"][0]["address"])
    guest_nic = next(nic for nic in guest["adapters"] if nic["status"] == "Up")
    guest_ip = ipaddress.IPv4Address(guest_nic["ipv4"][0]["address"])
    if host_ip == guest_ip:
        raise ValueError("Host and guest cannot share the same IPv4 address")
    return {
        "report_version": 1,
        "mode": "offline_pinned_host_guest_configuration_pair",
        "host_configuration_passed": True,
        "guest_configuration_passed": True,
        "declared_subnet_consistent": True,
        "host_guest_ipv4_distinct": True,
        "vmware_virtual_network_editor_verified": False,
        "physical_host_only_isolation_verified": False,
        "snapshot_authenticity_verified": False,
        "traffic_authorized": False,
        "network_activity_performed": False,
        "attack_detection_performed": False,
        "interpretation": (
            "Only two separately pinned, operator-supplied configuration snapshots "
            "are mutually consistent. Manually inspect VMware VMnet mode, all "
            "host/guest adapters, routes, egress and written authorization."
        ),
    }
