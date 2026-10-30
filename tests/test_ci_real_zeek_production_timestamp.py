"""Pure synthetic regression for CI production timestamp-gate fixture mutation.

The real Zeek + production CLI end-to-end path is exercised separately by
the network-disabled GitHub Actions workflow, not these unit tests.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_real_zeek_production_timestamp import shift_all_fixture_packet_timestamps
from blue_team_ai.pcap_zeek_tuple import corroborate_pcap_zeek_tuples
from blue_team_ai.zeek_smoke import build_benign_udp_pcap
from test_pcap_zeek_tuple import zeek_log


def _log() -> bytes:
    return zeek_log(
        src="192.168.56.10", dst="192.168.56.20",
        sport=51000, dport=53000, proto="udp", ts="1700000000.0",
    )


def test_shifted_fixture_preserves_packets_but_fails_temporal_presence():
    original = build_benign_udp_pcap()
    shifted = shift_all_fixture_packet_timestamps(original)
    assert original != shifted
    assert len(original) == len(shifted)
    offset = 24
    count = 0
    while offset < len(original):
        before = struct.unpack_from("<IIII", original, offset)
        after = struct.unpack_from("<IIII", shifted, offset)
        assert after[0] == before[0] + 120
        assert after[1:] == before[1:]
        end = offset + 16 + before[2]
        assert original[offset + 16:end] == shifted[offset + 16:end]
        offset = end
        count += 1
    assert count >= 2 and offset == len(original)
    assert corroborate_pcap_zeek_tuples(
        original, _log(), require_timestamp_corroboration=True,
    )["timestamps_correlated"] is True
    assert corroborate_pcap_zeek_tuples(
        shifted, _log(),
    )["matched_zeek_flow_count"] == 1
    with pytest.raises(ValueError, match="within one second"):
        corroborate_pcap_zeek_tuples(
            shifted, _log(), require_timestamp_corroboration=True,
        )


@pytest.mark.parametrize("invalid", [
    b"",
    b"not a pcap",
    bytes.fromhex("a1b2c3d4") + b"\x00" * 20,
    build_benign_udp_pcap()[:-1],
])
def test_shifted_fixture_rejects_invalid_framing(invalid):
    with pytest.raises(ValueError):
        shift_all_fixture_packet_timestamps(invalid)


@pytest.mark.parametrize("seconds", [0, 1, 3601, True, 1.5])
def test_shifted_fixture_rejects_invalid_offset(seconds):
    with pytest.raises(ValueError, match="shift"):
        shift_all_fixture_packet_timestamps(build_benign_udp_pcap(), seconds)
