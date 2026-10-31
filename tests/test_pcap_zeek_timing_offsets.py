"""Synthetic-only timing consistency diagnostics; no capture or network activity."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.pcap_zeek_tuple import corroborate_pcap_zeek_tuples
from test_pcap_zeek_tuple import pcap, pcap_packet, zeek_log
from test_pcap_zeek_distinct_packets import repeated_log
from test_lab_evidence_chain import _repin_integrated_pcap, _run
from test_offline_pcap_verify import imported  # pytest fixture


def test_default_mode_does_not_invent_timing_offsets():
    result = corroborate_pcap_zeek_tuples(pcap(pcap_packet()), zeek_log())
    assert result["timestamp_nearest_packet_offset_max_ms"] is None
    assert result["timestamp_nearest_packet_offset_mean_ms"] is None
    assert result["distinct_assigned_packet_offset_max_ms"] is None
    assert result["distinct_assigned_packet_offset_mean_ms"] is None


@pytest.mark.parametrize("nanos,fraction", [(False, 250_000), (True, 250_000_000)])
def test_micro_and_nano_packet_offsets_are_aggregated(nanos, fraction):
    result = corroborate_pcap_zeek_tuples(
        pcap(pcap_packet(), seconds=100, fraction=fraction, nanos=nanos),
        zeek_log(ts="100.0"), require_timestamp_corroboration=True,
    )
    assert result["timestamp_nearest_packet_offset_max_ms"] == 250.0
    assert result["timestamp_nearest_packet_offset_mean_ms"] == 250.0
    assert result["distinct_assigned_packet_offset_max_ms"] is None
    assert result["packet_to_flow_identity_verified"] is False
    assert "10.1.1." not in json.dumps(result)


def test_nearest_presence_uses_closest_packet_not_first_record():
    frame = pcap_packet()
    first = pcap(frame, seconds=100, fraction=0)
    second = pcap(frame, seconds=100, fraction=700_000)
    result = corroborate_pcap_zeek_tuples(
        first + second[24:], zeek_log(ts="100.6"),
        require_timestamp_corroboration=True,
    )
    assert result["timestamp_nearest_packet_offset_max_ms"] == 100.0
    assert result["timestamp_nearest_packet_offset_mean_ms"] == 100.0


def test_distinct_assignment_offsets_are_not_reused_presence_offsets():
    frame = pcap_packet()
    first = pcap(frame, seconds=100, fraction=0)
    second = pcap(frame, seconds=100, fraction=100_000)
    result = corroborate_pcap_zeek_tuples(
        first + second[24:], repeated_log(second_ts="100.2"),
        require_timestamp_corroboration=True,
        require_distinct_packet_corroboration=True,
    )
    assert result["timestamp_nearest_packet_offset_max_ms"] == 100.0
    assert result["timestamp_nearest_packet_offset_mean_ms"] == 50.0
    assert result["distinct_assigned_packet_offset_max_ms"] == 100.0
    assert result["distinct_assigned_packet_offset_mean_ms"] == 50.0
    assert result["packet_to_flow_identity_verified"] is False


def test_strict_evidence_chain_exposes_maxima_only(tmp_path, imported):
    frame = pcap_packet(
        src="192.168.56.10", dst="192.168.56.20", sport=52344, dport=443,
    )
    raw = pcap(frame, seconds=1630000000, fraction=250_000)

    def enable(args, hp, gp):
        _repin_integrated_pcap(args, imported, raw)
        args.extend([
            "--require-independent-original-pins",
            "--require-pcap-zeek-tuples",
            "--require-pcap-zeek-timestamps",
            "--require-distinct-pcap-packets",
        ])

    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["pcap_zeek_nearest_packet_offset_max_ms"] is not None
    assert report["pcap_zeek_distinct_assigned_offset_max_ms"] is not None
    assert report["packet_to_flow_identity_verified"] is False
    assert report["live_detection_latency_measured"] is False
    assert "192.168.56" not in result.stdout
