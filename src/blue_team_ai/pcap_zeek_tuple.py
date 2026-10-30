"""Conservative offline PCAP-to-Zeek 5-tuple *presence* corroboration.

This cannot prove Zeek produced the log, packet-to-flow identity, timing,
completeness, capture authenticity, isolation or ground-truth labels.
"""
from __future__ import annotations

import ipaddress
import struct
from bisect import bisect_left
from datetime import datetime

from .pcap_structure import MAGIC_FORMATS, inspect_classic_pcap_framing
from .zeek import parse_zeek_conn_log


def corroborate_pcap_zeek_tuples(
    pcap: bytes, zeek_log: bytes, *, require_timestamp_corroboration: bool = False,
) -> dict[str, object]:
    """Require every Zeek TCP/UDP IPv4 flow tuple to occur in a classic PCAP.

    Supported: Ethernet (DLT_EN10MB), untagged IPv4, nonfragmented TCP/UDP.
    A packet can corroborate multiple Zeek rows with the same tuple; this is
    explicitly an existence check, NOT a one-to-one correspondence proof.
    Optional timestamp corroboration requires a same-tuple PCAP packet within
    one second of each Zeek flow start. It still does not prove derivation.
    """
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

    tuples: set[tuple[str, int, str, int, str]] = set()
    packet_times: dict[tuple[str, int, str, int, str], list[float]] = {}
    packet_count = 0
    offset = 24
    while offset < len(pcap):
        sec, fraction, captured, _original = struct.unpack_from(endian + "IIII", pcap, offset)
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
        flags_fragment = struct.unpack_from("!H", frame, 20)[0]
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
        if require_timestamp_corroboration:
            packet_times.setdefault(key, []).append(sec + fraction / fraction_base)
        packet_count += 1

    if require_timestamp_corroboration:
        for times in packet_times.values():
            times.sort()

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
            def near_start(key: tuple[str, int, str, int, str]) -> bool:
                times = packet_times.get(key, [])
                index = bisect_left(times, event_ts - 1.0)
                return index < len(times) and times[index] <= event_ts + 1.0
            if not near_start(forward) and not near_start(reverse):
                raise ValueError("Zeek flow start has no same-tuple PCAP packet within one second")
        matched += 1
    return {
        "corroboration": "unordered_bidirectional_ipv4_tcp_udp_5tuple_presence_only",
        "pcap_packet_count": framing["packet_count"],
        "supported_pcap_packet_count": packet_count,
        "zeek_flow_count": len(events),
        "matched_zeek_flow_count": matched,
        "packet_to_flow_identity_verified": False,
        "timestamps_correlated": require_timestamp_corroboration,
        "timestamp_corroboration_window_seconds": (1.0 if require_timestamp_corroboration else None),
        "capture_authenticity_verified": False,
        "host_only_isolation_verified": False,
        "ground_truth_verified": False,
        "attack_detection_verified": False,
    }
