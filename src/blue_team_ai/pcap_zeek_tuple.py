"""Conservative offline PCAP-to-Zeek 5-tuple *presence* corroboration.

This cannot prove Zeek produced the log, packet-to-flow identity, timing,
completeness, capture authenticity, isolation or ground-truth labels.
"""
from __future__ import annotations

import ipaddress
import struct
from bisect import bisect_left
from collections import Counter
from datetime import datetime

from .pcap_structure import MAGIC_FORMATS, inspect_classic_pcap_framing
from .zeek import parse_zeek_conn_log


def _bidirectional_tuple(src_ip: str, src_port: int, dst_ip: str,
                         dst_port: int, proto: str) -> tuple[object, ...]:
    """Direction-neutral grouping for ambiguity diagnostics, not flow identity."""
    a, b = (src_ip, src_port), (dst_ip, dst_port)
    return (proto, a, b) if a <= b else (proto, b, a)


def corroborate_pcap_zeek_tuples(
    pcap: bytes, zeek_log: bytes, *, require_timestamp_corroboration: bool = False,
    require_distinct_packet_corroboration: bool = False,
) -> dict[str, object]:
    """Require every Zeek TCP/UDP IPv4 flow tuple to occur in a classic PCAP.

    Supported: Ethernet (DLT_EN10MB), untagged IPv4, nonfragmented TCP/UDP.
    A packet can corroborate multiple Zeek rows with the same tuple; this is
    explicitly an existence check, NOT a one-to-one correspondence proof.
    Optional timestamp corroboration requires a same-tuple PCAP packet within
    one second of each Zeek flow start. The stricter opt-in distinct-packet
    gate greedily assigns a different matching packet record to each Zeek row.
    Neither check proves packet-to-flow identity or capture authenticity.
    """
    if require_distinct_packet_corroboration and not require_timestamp_corroboration:
        raise ValueError("Distinct packet gate requires timestamp corroboration")
    framing = inspect_classic_pcap_framing(pcap)
    endian, fraction_base = MAGIC_FORMATS[pcap[:4]]
    linktype = struct.unpack_from(endian + "I", pcap, 20)[0]
    if linktype != 1:
        raise ValueError("Tuple corroboration requires classic Ethernet PCAP linktype 1")
    events = parse_zeek_conn_log(zeek_log)
    for event in events:
        if (event["proto"] not in ("tcp", "udp")
                or ipaddress.ip_address(event["src_ip"]).version != 4
                or ipaddress.ip_address(event["dst_ip"]).version != 4):
            raise ValueError("Tuple corroboration supports only Zeek IPv4 TCP/UDP flows")

    # An existence match can reuse the same packet for several Zeek rows.
    # Surface this ambiguity without silently upgrading it to flow identity.
    zeek_tuple_counts = Counter(
        _bidirectional_tuple(
            event["src_ip"], event["src_port"], event["dst_ip"],
            event["dst_port"], event["proto"],
        )
        for event in events
    )
    packet_tuple_counts: Counter[tuple[object, ...]] = Counter()
    tuples: set[tuple[str, int, str, int, str]] = set()
    packet_times: dict[tuple[str, int, str, int, str], list[float]] = {}
    packet_count = 0
    offset = 24
    while offset < len(pcap):
        sec, fraction, captured, original = struct.unpack_from(endian + "IIII", pcap, offset)
        offset += 16
        frame = memoryview(pcap)[offset:offset + captured]
        offset += captured
        if len(frame) < 14:
            raise ValueError("Truncated Ethernet frame")
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        if ethertype in (0x8100, 0x88A8, 0x9100):
            raise ValueError("VLAN-tagged Ethernet is outside this strict tuple contract")
        if ethertype != 0x0800:
            continue  # ARP/IPv6/etc. do not corroborate IPv4 Zeek flows.
        if len(frame) < 34:
            raise ValueError("Truncated IPv4 header")
        first = frame[14]
        ihl = (first & 0x0F) * 4
        if first >> 4 != 4 or ihl < 20 or len(frame) < 14 + ihl:
            raise ValueError("Invalid IPv4 header length")
        total = struct.unpack_from("!H", frame, 16)[0]
        if total < ihl:
            raise ValueError("Invalid IPv4 total length")
        # The record may be snaplen-truncated, but its original Ethernet
        # length must still accommodate the entire declared IPv4 datagram.
        # Otherwise a forged header with plausible ports could corroborate
        # a Zeek flow even though the packet was physically too short.
        if original < 14 + total:
            raise ValueError("IPv4 total length exceeds original PCAP Ethernet frame length")
        flags_fragment = struct.unpack_from("!H", frame, 20)[0]
        # RFC 791 reserves the high flag bit; accepting it would let an
        # invalid IPv4 header contribute tuple/timestamp evidence. DF (0x4000)
        # remains valid, while MF and nonzero fragment offsets are unsupported.
        if flags_fragment & 0x8000:
            raise ValueError("IPv4 reserved fragmentation flag must be zero")
        if flags_fragment & 0x3FFF:
            raise ValueError("Fragmented IPv4 is unsupported for strict tuple corroboration")
        protocol = frame[23]
        if protocol not in (6, 17):
            continue
        transport_min = 20 if protocol == 6 else 8
        if total < ihl + transport_min or len(frame) < 14 + ihl + transport_min:
            raise ValueError("Truncated IPv4 TCP/UDP transport header")
        start = 14 + ihl
        src_port, dst_port = struct.unpack_from("!HH", frame, start)
        if protocol == 17:
            # UDP's declared datagram length must include its eight-byte
            # header and fit within the unfragmented IPv4 payload. A packet
            # with plausible port bytes but an impossible UDP length must not
            # corroborate a Zeek flow (even when its five-tuple matches).
            udp_length = struct.unpack_from("!H", frame, start + 4)[0]
            if udp_length < 8 or udp_length > total - ihl:
                raise ValueError("Invalid IPv4 UDP datagram length")
        if protocol == 6:
            tcp_header_length = (frame[start + 12] >> 4) * 4
            if (tcp_header_length < 20 or total < ihl + tcp_header_length
                    or len(frame) < start + tcp_header_length):
                raise ValueError("Invalid or truncated TCP data offset")
        src_ip = str(ipaddress.IPv4Address(bytes(frame[26:30])))
        dst_ip = str(ipaddress.IPv4Address(bytes(frame[30:34])))
        proto = "tcp" if protocol == 6 else "udp"
        key = (src_ip, src_port, dst_ip, dst_port, proto)
        tuples.add(key)
        packet_tuple_counts[_bidirectional_tuple(
            src_ip, src_port, dst_ip, dst_port, proto,
        )] += 1
        if require_timestamp_corroboration:
            packet_times.setdefault(key, []).append(sec + fraction / fraction_base)
        packet_count += 1

    if require_timestamp_corroboration:
        for times in packet_times.values():
            times.sort()

    nearest_offsets_seconds: list[float] = []
    nearest_signed_seconds: list[float] = []
    matched = 0
    for event in events:
        forward = (event["src_ip"], event["src_port"], event["dst_ip"],
                   event["dst_port"], event["proto"])
        reverse = (event["dst_ip"], event["dst_port"], event["src_ip"],
                   event["src_port"], event["proto"])
        if forward not in tuples and reverse not in tuples:
            raise ValueError("Zeek IPv4 TCP/UDP flow tuple absent from original PCAP")
        if require_timestamp_corroboration:
            event_ts = datetime.fromisoformat(event["event_time_utc"]).timestamp()
            # Sorted timestamp search avoids accepting two distant sessions
            # merely because they reused the same five-tuple.
            def nearest_signed_offset(key: tuple[str, int, str, int, str]) -> float | None:
                times = packet_times.get(key, [])
                index = bisect_left(times, event_ts)
                candidates = [
                    times[i] - event_ts
                    for i in (index - 1, index) if 0 <= i < len(times)
                ]
                # Preserve the prior nearest absolute offset. On equal absolute
                # distances, prefer the earlier packet deterministically.
                nearest = min(candidates, key=lambda delta: (abs(delta), delta),
                              default=None)
                return nearest if nearest is not None and abs(nearest) <= 1.0 else None

            offsets = [
                value for value in (nearest_signed_offset(forward),
                                    nearest_signed_offset(reverse))
                if value is not None
            ]
            if not offsets:
                raise ValueError("Zeek flow start has no same-tuple PCAP packet within one second")
            signed_offset = min(offsets, key=lambda delta: (abs(delta), delta))
            nearest_offsets_seconds.append(abs(signed_offset))
            nearest_signed_seconds.append(signed_offset)
        matched += 1
    # Stronger optional *record availability* screen: no PCAP packet record
    # may satisfy two Zeek rows, including when the directions are reversed.
    # Sorting by flow start (hence deadline) and consuming the earliest
    # eligible packet gives a deterministic interval matching for +/-1 s.
    # This is still not proof that Zeek derived a row from that packet.
    assigned_offsets_seconds: list[float] = []
    assigned_signed_seconds: list[float] = []
    if require_distinct_packet_corroboration:
        available: dict[tuple[object, ...], list[float]] = {}
        for key, times in packet_times.items():
            neutral = _bidirectional_tuple(*key)
            available.setdefault(neutral, []).extend(times)
        for times in available.values():
            times.sort()
        starts_by_tuple: dict[tuple[object, ...], list[float]] = {}
        for event in events:
            neutral = _bidirectional_tuple(
                event["src_ip"], event["src_port"], event["dst_ip"],
                event["dst_port"], event["proto"],
            )
            starts_by_tuple.setdefault(neutral, []).append(
                datetime.fromisoformat(event["event_time_utc"]).timestamp()
            )
        for neutral, starts in starts_by_tuple.items():
            starts.sort()
            times = available.get(neutral, [])
            cursor = 0
            for start in starts:
                while cursor < len(times) and times[cursor] < start - 1.0:
                    cursor += 1
                if cursor >= len(times) or times[cursor] > start + 1.0:
                    raise ValueError(
                        "Insufficient distinct same-tuple PCAP packets near Zeek flow starts"
                    )
                signed_offset = times[cursor] - start
                assigned_offsets_seconds.append(abs(signed_offset))
                assigned_signed_seconds.append(signed_offset)
                cursor += 1

    reused_zeek_rows = sum(
        count for count in zeek_tuple_counts.values() if count > 1
    )
    return {
        "distinct_zeek_bidirectional_tuples": len(zeek_tuple_counts),
        "zeek_rows_with_nonunique_bidirectional_tuple": reused_zeek_rows,
        "distinct_supported_pcap_bidirectional_tuples": len(packet_tuple_counts),
        "potential_packet_reuse_for_multiple_zeek_flows": reused_zeek_rows > 0,
        "corroboration": (
            "bidirectional_ipv4_tcp_udp_5tuple_and_one_second_timestamp_presence"
            if require_timestamp_corroboration else
            "unordered_bidirectional_ipv4_tcp_udp_5tuple_presence_only"
        ),
        "pcap_packet_count": framing["packet_count"],
        "supported_pcap_packet_count": packet_count,
        "zeek_flow_count": len(events),
        "matched_zeek_flow_count": matched,
        "packet_to_flow_identity_verified": False,
        "timestamps_correlated": require_timestamp_corroboration,
        "distinct_packet_per_flow_required": require_distinct_packet_corroboration,
        "distinct_packet_per_flow_correlated": require_distinct_packet_corroboration,
        # Aggregate packet/start offsets are consistency diagnostics only:
        # nearest presence can reuse a packet; distinct uses greedy assignment.
        # Neither quantity measures AI detection latency or clock accuracy.
        "timestamp_nearest_packet_offset_max_ms": (
            round(max(nearest_offsets_seconds) * 1000, 6)
            if require_timestamp_corroboration else None
        ),
        "timestamp_nearest_packet_offset_mean_ms": (
            round(sum(nearest_offsets_seconds) * 1000 / len(nearest_offsets_seconds), 6)
            if require_timestamp_corroboration else None
        ),
        # Signed delta = PCAP packet time - Zeek flow start. Positive means
        # packet timestamp is later; mean can cancel opposing offsets.
        "timestamp_nearest_packet_signed_offset_mean_ms": (
            round(sum(nearest_signed_seconds) * 1000 / len(nearest_signed_seconds), 6)
            if require_timestamp_corroboration else None
        ),
        "distinct_assigned_packet_offset_max_ms": (
            round(max(assigned_offsets_seconds) * 1000, 6)
            if require_distinct_packet_corroboration else None
        ),
        "distinct_assigned_packet_offset_mean_ms": (
            round(sum(assigned_offsets_seconds) * 1000 / len(assigned_offsets_seconds), 6)
            if require_distinct_packet_corroboration else None
        ),
        "distinct_assigned_packet_signed_offset_mean_ms": (
            round(sum(assigned_signed_seconds) * 1000 / len(assigned_signed_seconds), 6)
            if require_distinct_packet_corroboration else None
        ),
        "timestamp_corroboration_window_seconds": (1.0 if require_timestamp_corroboration else None),
        "capture_authenticity_verified": False,
        "host_only_isolation_verified": False,
        "ground_truth_verified": False,
        "attack_detection_verified": False,
    }
