"""Synthetic-only P95 absolute PCAP/Zeek offset diagnostics; no capture or network."""
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
from test_lab_evidence_chain import _repin_integrated_pcap, _run
from test_offline_pcap_verify import imported  # pytest fixture


def _ten_same_tuple_flows() -> bytes:
    header = b"".join(zeek_log().splitlines(keepends=True)[:2])
    rows = b"".join(
        f"100.0\tC{i}\t10.1.1.2\t1234\t10.1.1.3\t80\ttcp\n".encode()
        for i in range(1, 11)
    )
    return header + rows


def test_p95_is_null_when_timestamp_gate_is_disabled():
    report = corroborate_pcap_zeek_tuples(pcap(pcap_packet()), zeek_log())
    assert report["timestamp_nearest_packet_offset_p95_ms"] is None
    assert report["distinct_assigned_packet_offset_p95_ms"] is None


def test_single_packet_p95_equals_absolute_offset():
    report = corroborate_pcap_zeek_tuples(
        pcap(pcap_packet(), seconds=100, fraction=250_000),
        zeek_log(),
        require_timestamp_corroboration=True,
        require_distinct_packet_corroboration=True,
    )
    assert report["timestamp_nearest_packet_offset_p95_ms"] == pytest.approx(250.0)
    assert report["distinct_assigned_packet_offset_p95_ms"] == pytest.approx(250.0)


def test_distinct_p95_exposes_tail_masked_by_nearest_packet_reuse():
    frame = pcap_packet()
    early = pcap(frame, seconds=100, fraction=100_000)
    late = pcap(frame, seconds=100, fraction=900_000)
    raw = early + early[24:] * 8 + late[24:]
    report = corroborate_pcap_zeek_tuples(
        raw, _ten_same_tuple_flows(),
        require_timestamp_corroboration=True,
        require_distinct_packet_corroboration=True,
    )
    # Ten rows can all reuse the 100ms packet in the presence-only metric.
    assert report["timestamp_nearest_packet_offset_p95_ms"] == pytest.approx(100.0)
    # The distinct gate consumes nine 100ms records and one 900ms record.
    # Nearest-rank P95 for N=10 is the 10th ordered observation.
    assert report["distinct_assigned_packet_offset_p95_ms"] == pytest.approx(900.0)
    assert report["distinct_assigned_packet_offset_mean_ms"] == pytest.approx(180.0)
    assert report["packet_to_flow_identity_verified"] is False
    assert "10.1.1." not in json.dumps(report)


def test_distinct_p95_is_null_in_timestamp_presence_only_mode():
    report = corroborate_pcap_zeek_tuples(
        pcap(pcap_packet(), seconds=100, fraction=300_000),
        zeek_log(), require_timestamp_corroboration=True,
    )
    assert report["timestamp_nearest_packet_offset_p95_ms"] == pytest.approx(300.0)
    assert report["distinct_assigned_packet_offset_p95_ms"] is None


def test_private_integrated_evidence_chain_exposes_aggregate_p95_only(tmp_path, imported):
    frame = pcap_packet(
        src="192.168.56.10", dst="192.168.56.20", sport=52344, dport=443,
    )
    # Zeek fixture starts at 1630000000.25; packet at .50 is +250 ms.
    raw = pcap(frame, seconds=1630000000, fraction=500_000)

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
    assert report["pcap_zeek_nearest_packet_offset_p95_ms"] == pytest.approx(250.0)
    assert report["pcap_zeek_distinct_assigned_offset_p95_ms"] == pytest.approx(250.0)
    assert report["live_detection_latency_measured"] is False
    assert report["packet_to_flow_identity_verified"] is False
    assert "192.168.56" not in result.stdout
