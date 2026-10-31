"""Synthetic-only tests: distinct PCAP packet records per Zeek row, no network."""
from __future__ import annotations

import hashlib
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
from verify_pcap_zeek_tuple import main as standalone_main


def repeated_log(*, second_ts="100.2"):
    return (zeek_log()
            + f"{second_ts}\tC2\t10.1.1.2\t1234\t10.1.1.3\t80\ttcp\n".encode())


def test_distinct_gate_requires_timestamp_mode():
    with pytest.raises(ValueError, match="requires timestamp"):
        corroborate_pcap_zeek_tuples(
            pcap(pcap_packet()), zeek_log(),
            require_distinct_packet_corroboration=True,
        )


def test_one_packet_cannot_corroborate_two_same_tuple_rows():
    raw = pcap(pcap_packet(), seconds=100)
    log = repeated_log()
    # Existing existence/time gates intentionally permit packet reuse.
    assert corroborate_pcap_zeek_tuples(
        raw, log, require_timestamp_corroboration=True,
    )["matched_zeek_flow_count"] == 2
    with pytest.raises(ValueError, match="Insufficient distinct"):
        corroborate_pcap_zeek_tuples(
            raw, log, require_timestamp_corroboration=True,
            require_distinct_packet_corroboration=True,
        )


def test_two_packet_records_satisfy_two_rows_without_identity_claim():
    frame = pcap_packet()
    result = corroborate_pcap_zeek_tuples(
        pcap(frame, frame, seconds=100), repeated_log(),
        require_timestamp_corroboration=True,
        require_distinct_packet_corroboration=True,
    )
    assert result["matched_zeek_flow_count"] == 2
    assert result["distinct_packet_per_flow_required"] is True
    assert result["distinct_packet_per_flow_correlated"] is True
    assert result["packet_to_flow_identity_verified"] is False
    assert result["capture_authenticity_verified"] is False


def test_reverse_direction_does_not_allow_packet_reuse():
    forward = zeek_log()
    reverse = b"100.1\tC2\t10.1.1.3\t80\t10.1.1.2\t1234\ttcp\n"
    with pytest.raises(ValueError, match="Insufficient distinct"):
        corroborate_pcap_zeek_tuples(
            pcap(pcap_packet(), seconds=100), forward + reverse,
            require_timestamp_corroboration=True,
            require_distinct_packet_corroboration=True,
        )


def test_distinct_gate_uses_per_flow_timestamp_window():
    frame = pcap_packet()
    raw = pcap(frame, frame, seconds=100)
    with pytest.raises(ValueError, match="within one second"):
        corroborate_pcap_zeek_tuples(
            raw, repeated_log(second_ts="104.0"),
            require_timestamp_corroboration=True,
            require_distinct_packet_corroboration=True,
        )


def test_standalone_cli_requires_timestamp_and_preserves_originals(tmp_path, capsys):
    capture, log = tmp_path / "original.pcap", tmp_path / "conn.log"
    capture.write_bytes(pcap(pcap_packet(), pcap_packet(), seconds=100))
    log.write_bytes(repeated_log())
    before = (capture.read_bytes(), log.read_bytes())
    args = [
        "--pcap", str(capture),
        "--expected-pcap-sha256", hashlib.sha256(before[0]).hexdigest(),
        "--log", str(log),
        "--expected-log-sha256", hashlib.sha256(before[1]).hexdigest(),
        "--require-distinct-packet-corroboration",
    ]
    assert standalone_main(args) == 2
    assert capsys.readouterr().out == ""
    args.append("--require-timestamp-corroboration")
    assert standalone_main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["distinct_packet_per_flow_correlated"] is True
    assert (capture.read_bytes(), log.read_bytes()) == before


def test_integrated_gate_requires_timestamp_and_accepts_pinned_originals(tmp_path, imported):
    frame = pcap_packet(
        src="192.168.56.10", dst="192.168.56.20", sport=52344, dport=443,
    )
    raw = pcap(frame, seconds=1630000000, fraction=250000)

    def enable(args, hp, gp):
        _repin_integrated_pcap(args, imported, raw)
        args.extend([
            "--require-independent-original-pins",
            "--require-pcap-zeek-tuples",
            "--require-distinct-pcap-packets",
        ])

    refused = _run(tmp_path, imported, independent_pins=True, changes=enable)
    assert refused.returncode == 1
    assert refused.stdout == ""

    def enable_with_time(args, hp, gp):
        enable(args, hp, gp)
        args.append("--require-pcap-zeek-timestamps")

    accepted = _run(tmp_path, imported, independent_pins=True,
                    changes=enable_with_time)
    assert accepted.returncode == 0, accepted.stderr
    result = json.loads(accepted.stdout)
    assert result["pcap_zeek_distinct_packets_required"] is True
    assert result["pcap_zeek_distinct_packets_correlated"] is True
    assert result["pcap_zeek_matched_flow_count"] == 1
    assert result["packet_to_flow_identity_verified"] is False
    assert result["vmware_isolation_verified"] is False
    assert "192.168.56" not in accepted.stdout
