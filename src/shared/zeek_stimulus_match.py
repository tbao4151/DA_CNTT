"""Evidence-scoped candidate matching of benign Windows probes to Zeek conn.log.

Timestamp/IP/protocol/port agreement is an exploratory *candidate link*, not
packet-to-flow proof, clock-sync proof, host isolation or detection ground truth.
No sockets, model inference, new labels, or SOC writes.
"""
from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone
from collections.abc import Mapping

from blue_team_ai.zeek import parse_zeek_conn_log

_PORTS = {"baseline_web": ("tcp", 8080),
          "dns_variation": ("udp", 53),
          "connection_shift": ("tcp", 22)}
_MAX_SECONDS = 15


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Missing or invalid event timestamp")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("Invalid event timestamp") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Event timestamp must include UTC offset")
    if timestamp.utcoffset().total_seconds() != 0:
        raise ValueError("Expected UTC event timestamp")
    return timestamp.astimezone(timezone.utc)


def screen_candidate_zeek_matches(
    traffic_receipt: Mapping[str, object],
    zeek_raw: bytes,
    *,
    expected_log_sha256: str,
    tolerance_s: int = 10,
) -> dict[str, object]:
    """Allocate at most one Zeek UID to each benign probe's time/IP tuple."""
    if type(tolerance_s) is not int or not 1 <= tolerance_s <= _MAX_SECONDS:
        raise ValueError("Timestamp screen tolerance must be 1..15 seconds")
    if not isinstance(traffic_receipt, Mapping):
        raise ValueError("Expected traffic receipt mapping")
    if traffic_receipt.get("kind") != "da005_benign_vmware_hostonly_network_stimulus" or (
        traffic_receipt.get("mode") != "BENIGN_LAB_EXECUTION"
    ):
        raise ValueError("Not an executed benign lab stimulus receipt")
    if (not isinstance(zeek_raw, bytes)
        or not isinstance(expected_log_sha256, str)
        or len(expected_log_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_log_sha256)
    ):
        raise ValueError("Expected bounded raw Zeek bytes and lowercase SHA-256")
    if hashlib.sha256(zeek_raw).hexdigest() != expected_log_sha256:
        raise ValueError("Zeek capture source bytes do not match pinned SHA-256")
    scenario = traffic_receipt.get("scenario_id")
    if not isinstance(scenario, str) or scenario not in _PORTS:
        raise ValueError("Unknown fixed benign scenario")
    proto, port = _PORTS[scenario]
    scope = traffic_receipt.get("scope")
    if not isinstance(scope, Mapping):
        raise ValueError("Missing scoped probe endpoints")
    source, target = scope.get("source_ip"), scope.get("target_ip")
    subnet = scope.get("cidr")
    try:
        network = ipaddress.ip_network(subnet, strict=True)
        src_ip, dst_ip = ipaddress.ip_address(source), ipaddress.ip_address(target)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid scoped probe endpoints") from exc
    if (
        not isinstance(network, ipaddress.IPv4Network)
        or not isinstance(src_ip, ipaddress.IPv4Address)
        or not isinstance(dst_ip, ipaddress.IPv4Address)
        or network.prefixlen < 24 or not network.is_private
        or src_ip == dst_ip or src_ip not in network or dst_ip not in network
        or src_ip in (network.network_address, network.broadcast_address)
        or dst_ip in (network.network_address, network.broadcast_address)
    ):
        raise ValueError("Invalid scoped probe endpoints")
    planned = traffic_receipt.get("planned_attempts")
    attempts = traffic_receipt.get("events")
    if (
        type(planned) is not int or not 1 <= planned <= 4
        or type(traffic_receipt.get("network_attempts")) is not int
        or traffic_receipt.get("network_attempts") != planned
        or not isinstance(attempts, list) or len(attempts) != planned
    ):
        raise ValueError("Incomplete or invalid benign probe receipt")
    probe_times = []
    for attempt in attempts:
        if not isinstance(attempt, Mapping) or (
            attempt.get("scenario_id") != scenario
            or attempt.get("protocol") != proto
            or attempt.get("port") != port
        ):
            raise ValueError("Benign receipt scenario/protocol/port mismatch")
        probe_times.append(_parse_utc(attempt.get("attempted_at_utc")))

    flows = parse_zeek_conn_log(zeek_raw)
    candidates = []
    used_uids: set[str] = set()
    for index, when in enumerate(probe_times, start=1):
        options = []
        for flow in flows:
            if (
                flow["uid"] in used_uids
                or flow["src_ip"] != source or flow["dst_ip"] != target
                or flow["dst_port"] != port or flow["proto"] != proto
            ):
                continue
            seconds = abs((_parse_utc(flow["event_time_utc"]) - when).total_seconds())
            if seconds <= tolerance_s:
                options.append((seconds, flow["uid"], flow))
        if options:
            _, uid, flow = min(options, key=lambda x: (x[0], x[1]))
            used_uids.add(uid)
            candidates.append({
                "attempt_number": index,
                "zeek_uid": uid,
                "zeek_event_time_utc": flow["event_time_utc"],
                "timestamp_difference_s": round(abs((_parse_utc(flow["event_time_utc"]) - when).total_seconds()), 3),
                "status": "candidate_by_tuple_and_time_only",
            })

    return {
        "mode": "benign_probe_to_zeek_candidate_correlation",
        "source_log_sha256": expected_log_sha256,
        "probe_count": planned,
        "candidate_match_count": len(candidates),
        "unmatched_probe_count": planned - len(candidates),
        "tolerance_s": tolerance_s,
        "candidates": candidates,
        "provenance": "operator_receipt_and_sha256_pinned_zeek_snapshot",
        "clock_sync_independently_verified": False,
        "causal_packet_to_zeek_uid_proof": False,
        "physical_hostonly_isolation_verified": False,
        "attack_detection_verified": False,
        "ground_truth_verified": False,
    }
