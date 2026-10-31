"""Synthetic-only signed PCAP/Zeek clock-offset diagnostics; no network access."""
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


def test_signed_fields_absent_without_timestamp_gate():
    report = corroborate_pcap_zeek_tuples(pcap(pcap_packet()), zeek_log())
    assert report["timestamp_nearest_packet_signed_offset_mean_ms"] is None
    assert report["distinct_assigned_packet_signed_offset_mean_ms"] is None


@pytest.mark.parametrize(
    "packet_second, fraction, zeek_ts, expected_ms",
    [(100, 250_000, "100.0", 250.0),
     (99, 800_000, "100.0", -200.0),
     (100, 250_000_000, "100.0", 250.0)],
)
def test_signed_offset_direction_and_resolution(packet_second, fraction, zeek_ts, expected_ms):
    nanos = fraction >= 1_000_000
    report = corroborate_pcap_zeek_tuples(
        pcap(pcap_packet(), seconds=packet_second, fraction=fraction, nanos=nanos),
        zeek_log(ts=zeek_ts),
        require_timestamp_corroboration=True,
    )
    assert report["timestamp_nearest_packet_signed_offset_mean_ms"] == pytest.approx(expected_ms)
    assert report["timestamp_nearest_packet_offset_max_ms"] == pytest.approx(abs(expected_ms))
    assert report["distinct_assigned_packet_signed_offset_mean_ms"] is None


def test_signed_mean_can_cancel_even_when_absolute_offsets_are_nonzero():
    frame = pcap_packet()
    first = pcap(frame, seconds=99, fraction=900_000)
    second = pcap(frame, seconds=100, fraction=300_000)
    report = corroborate_pcap_zeek_tuples(
        first + second[24:], repeated_log(second_ts="100.2"),
        require_timestamp_corroboration=True,
        require_distinct_packet_corroboration=True,
    )
    assert report["timestamp_nearest_packet_signed_offset_mean_ms"] == pytest.approx(0.0)
    assert report["distinct_assigned_packet_signed_offset_mean_ms"] == pytest.approx(0.0)
    assert report["timestamp_nearest_packet_offset_mean_ms"] == pytest.approx(100.0)
    assert report["distinct_assigned_packet_offset_mean_ms"] == pytest.approx(100.0)
    assert report["packet_to_flow_identity_verified"] is False
    assert "10.1.1." not in json.dumps(report)


def test_equidistant_nearest_packet_prefers_earlier_timestamp():
    frame = pcap_packet()
    earlier = pcap(frame, seconds=99, fraction=800_000)
    later = pcap(frame, seconds=100, fraction=200_000)
    report = corroborate_pcap_zeek_tuples(
        earlier + later[24:], zeek_log(ts="100.0"),
        require_timestamp_corroboration=True,
    )
    assert report["timestamp_nearest_packet_signed_offset_mean_ms"] == pytest.approx(-200.0)
    assert report["timestamp_nearest_packet_offset_mean_ms"] == pytest.approx(200.0)


def test_reverse_direction_preserves_signed_packet_minus_flow_convention():
    report = corroborate_pcap_zeek_tuples(
        pcap(pcap_packet(), seconds=100, fraction=250_000),
        zeek_log(src="10.1.1.3", dst="10.1.1.2", sport=80, dport=1234),
        require_timestamp_corroboration=True,
        require_distinct_packet_corroboration=True,
    )
    assert report["timestamp_nearest_packet_signed_offset_mean_ms"] == pytest.approx(250.0)
    assert report["distinct_assigned_packet_signed_offset_mean_ms"] == pytest.approx(250.0)


def test_integrated_private_chain_reports_signed_aggregates_only(tmp_path, imported):
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
    assert isinstance(report["pcap_zeek_nearest_packet_signed_offset_mean_ms"], (int, float))
    assert isinstance(report["pcap_zeek_distinct_assigned_signed_offset_mean_ms"], (int, float))
    assert report["packet_to_flow_identity_verified"] is False
    assert report["live_detection_latency_measured"] is False
    assert "192.168.56" not in result.stdout
