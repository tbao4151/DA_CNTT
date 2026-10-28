"""Offline-only CIDR scope screening for operator-supplied Zeek conn.log bytes.

Membership in declared private CIDRs is not proof of VMware Host-only isolation,
log authenticity, authorization, or attack detection. This module opens no sockets.
"""
from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Sequence

from .zeek import parse_zeek_conn_log

_RFC1918 = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))


def _networks(cidrs: Sequence[str]) -> tuple[ipaddress.IPv4Network, ...]:
    if isinstance(cidrs, (str, bytes)) or not isinstance(cidrs, Sequence) or not 1 <= len(cidrs) <= 4:
        raise ValueError("Provide 1 to 4 explicit IPv4 lab CIDRs")
    networks = []
    for value in cidrs:
        if not isinstance(value, str) or not value or value.strip() != value:
            raise ValueError("Invalid lab CIDR")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ValueError("Invalid canonical lab CIDR") from exc
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or network.prefixlen < 16
            or not any(network.subnet_of(block) for block in _RFC1918)
        ):
            raise ValueError("Lab scope must be explicit RFC1918 IPv4 CIDRs of /16 or narrower")
        if network in networks:
            raise ValueError("Duplicate lab CIDR")
        networks.append(network)
    return tuple(networks)


def inspect_zeek_lab_scope(raw: bytes, cidrs: Sequence[str]) -> dict[str, object]:
    """Fail closed when any source/destination IP falls outside declared lab CIDRs.

    Returns only aggregate counts, time bounds, and digests; no IP, UID, port,
    path, or raw log content is included. All event fields come from the file.
    """
    networks = _networks(cidrs)
    events = parse_zeek_conn_log(raw)
    source_ips: set[str] = set()
    destination_ips: set[str] = set()
    for event in events:
        for field, seen in (("src_ip", source_ips), ("dst_ip", destination_ips)):
            address = ipaddress.ip_address(event[field])
            if not isinstance(address, ipaddress.IPv4Address) or not any(address in network for network in networks):
                raise ValueError("Zeek log contains an endpoint outside the declared lab scope")
            seen.add(str(address))
    timestamps = [event["event_time_utc"] for event in events]
    canonical_scope = "\n".join(sorted(str(network) for network in networks)).encode("ascii")
    return {
        "report_version": 1,
        "mode": "offline_zeek_declared_scope_screening",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "declared_scope_sha256": hashlib.sha256(canonical_scope).hexdigest(),
        "flow_count": len(events),
        "unique_source_ip_count": len(source_ips),
        "unique_destination_ip_count": len(destination_ips),
        "first_event_utc": min(timestamps),
        "last_event_utc": max(timestamps),
        "all_endpoints_within_declared_scope": True,
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "authorization_verified": False,
        "ground_truth_verified": False,
        "model_fitted": False,
        "attack_detection_performed": False,
        "interpretation": (
            "Offline CIDR membership check only. The CIDRs and log contents are operator supplied; "
            "a passing check cannot prove VMware Host-only isolation, authorization, "
            "authenticity or detection accuracy. Preserve separate isolation evidence."
        ),
    }
