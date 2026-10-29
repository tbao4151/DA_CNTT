"""Bounded classic-PCAP record framing validation for private offline evidence.

No packet decoding, Zeek correlation, network access or capture-origin claims.
"""
from __future__ import annotations

import struct

MAGIC_FORMATS = {
    bytes.fromhex("a1b2c3d4"): (">", 1_000_000),
    bytes.fromhex("d4c3b2a1"): ("<", 1_000_000),
    bytes.fromhex("a1b23c4d"): (">", 1_000_000_000),
    bytes.fromhex("4d3cb2a1"): ("<", 1_000_000_000),
}
MAX_CLASSIC_PCAP_BYTES = 64 * 1024 * 1024


def inspect_classic_pcap_framing(data: bytes) -> dict[str, int | str]:
    """Fail closed on malformed global headers, packet headers and byte bounds.

    This is an optional *structural* check only. It cannot prove that Zeek
    generated a matching conn.log, or that packets are genuine/authorized.
    """
    if not isinstance(data, bytes) or not 24 <= len(data) <= MAX_CLASSIC_PCAP_BYTES:
        raise ValueError("Classic PCAP bytes are missing or outside the bounded size")
    fmt = MAGIC_FORMATS.get(data[:4])
    if fmt is None:
        raise ValueError("Expected classic PCAP magic (not PCAPNG)")
    endian, fraction_base = fmt
    major, minor, _zone, _sigfigs, snaplen, _linktype = struct.unpack_from(
        endian + "HHIIII", data, 4,
    )
    if (major, minor) != (2, 4) or not 1 <= snaplen <= MAX_CLASSIC_PCAP_BYTES:
        raise ValueError("Invalid classic PCAP version or snapshot length")
    offset = 24
    packets = 0
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("Truncated classic PCAP packet record header")
        _seconds, fraction, captured, original = struct.unpack_from(
            endian + "IIII", data, offset,
        )
        offset += 16
        if (fraction >= fraction_base or captured == 0 or captured > original
                or captured > snaplen or captured > len(data) - offset):
            raise ValueError("Invalid classic PCAP packet timestamp or length")
        offset += captured
        packets += 1
    if packets == 0:
        raise ValueError("Classic PCAP contains no packet records")
    return {
        "packet_count": packets,
        "timestamp_resolution": "nanoseconds" if fraction_base == 1_000_000_000 else "microseconds",
    }
