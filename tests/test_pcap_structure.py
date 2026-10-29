"""Synthetic classic-PCAP framing regressions; no real packets or VMware."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.pcap_structure import MAGIC_FORMATS, inspect_classic_pcap_framing


def packet_file(magic: bytes, *, fraction: int = 1, captured: int = 4,
                original: int = 4, snaplen: int = 65535,
                version: tuple[int, int] = (2, 4), payload: bytes = b"data") -> bytes:
    endian, _ = MAGIC_FORMATS[magic]
    return (magic + struct.pack(endian + "HHIIII", *version, 0, 0, snaplen, 1)
            + struct.pack(endian + "IIII", 100, fraction, captured, original)
            + payload)


@pytest.mark.parametrize("magic", list(MAGIC_FORMATS))
def test_accepts_all_four_classic_pcap_encodings(magic):
    data = packet_file(magic)
    result = inspect_classic_pcap_framing(data)
    assert result["packet_count"] == 1
    assert result["timestamp_resolution"] == (
        "nanoseconds" if MAGIC_FORMATS[magic][1] == 1_000_000_000 else "microseconds"
    )
    endian, _ = MAGIC_FORMATS[magic]
    second = struct.pack(endian + "IIII", 101, 0, 3, 3) + b"abc"
    assert inspect_classic_pcap_framing(data + second)["packet_count"] == 2


@pytest.mark.parametrize("change", [
    "header_only", "invalid_magic", "invalid_version", "zero_snaplen",
    "truncated_packet_header", "truncated_packet_data", "captured_gt_original",
    "captured_gt_snaplen", "zero_packet", "invalid_fraction", "trailing_bytes",
])
def test_malformed_or_ambiguous_framing_rejected(change):
    magic = bytes.fromhex("d4c3b2a1")
    data = packet_file(magic)
    if change == "header_only":
        data = data[:24]
    elif change == "invalid_magic":
        data = b"BAD!" + data[4:]
    elif change == "invalid_version":
        data = packet_file(magic, version=(2, 3))
    elif change == "zero_snaplen":
        data = packet_file(magic, snaplen=0)
    elif change == "truncated_packet_header":
        data = data[:28]
    elif change == "truncated_packet_data":
        data = data[:-1]
    elif change == "captured_gt_original":
        data = packet_file(magic, captured=5, original=4, payload=b"12345")
    elif change == "captured_gt_snaplen":
        data = packet_file(magic, captured=5, original=5, snaplen=4, payload=b"12345")
    elif change == "zero_packet":
        data = packet_file(magic, captured=0, original=0, payload=b"")
    elif change == "invalid_fraction":
        data = packet_file(magic, fraction=1_000_000)
    else:
        data += b"\x00"
    with pytest.raises(ValueError):
        inspect_classic_pcap_framing(data)


def test_rejects_non_bytes_and_oversized_input():
    with pytest.raises(ValueError):
        inspect_classic_pcap_framing(bytearray(24))
    with pytest.raises(ValueError):
        inspect_classic_pcap_framing(b"\x00" * (64 * 1024 * 1024 + 1))
