"""Synthetic-only RFC 791 IPv4 header checksum opt-in; no VMware or traffic."""
from __future__ import annotations

import hashlib
import json
import struct
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
from verify_pcap_zeek_tuple import main


def _checksum_frame(frame: bytes) -> bytes:
    """Build a valid header checksum from synthetic bytes (not a real capture)."""
    raw = bytearray(frame)
    ihl = (raw[14] & 15) * 4
    raw[24:26] = b"\x00\x00"
    header = raw[14:14 + ihl]
    total = sum(int.from_bytes(header[i:i + 2], "big")
                for i in range(0, len(header), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    raw[24:26] = struct.pack("!H", (~total) & 0xFFFF)
    return bytes(raw)


@pytest.mark.parametrize("proto", [6, 17])
def test_opt_in_accepts_valid_tcp_udp_header_checksum(proto):
    frame = _checksum_frame(pcap_packet(proto=proto))
    log = zeek_log(proto="tcp" if proto == 6 else "udp")
    report = corroborate_pcap_zeek_tuples(
        pcap(frame), log, require_ipv4_header_checksum=True,
        require_timestamp_corroboration=True,
    )
    assert report["ipv4_header_checksum_required"] is True
    assert report["ipv4_header_checksum_verified"] is True
    assert report["matched_zeek_flow_count"] == 1
    assert report["packet_to_flow_identity_verified"] is False
    assert "10.1.1." not in json.dumps(report)


def test_legacy_zero_checksum_remains_compatible_by_default():
    report = corroborate_pcap_zeek_tuples(pcap(pcap_packet()), zeek_log())
    assert report["ipv4_header_checksum_required"] is False
    assert report["ipv4_header_checksum_verified"] is False
    with pytest.raises(ValueError, match="IPv4 header checksum"):
        corroborate_pcap_zeek_tuples(
            pcap(pcap_packet()), zeek_log(), require_ipv4_header_checksum=True,
        )


@pytest.mark.parametrize("mutation", ["ttl", "checksum"])
def test_opt_in_rejects_corrupted_ipv4_header_even_with_matching_tuple(mutation):
    frame = bytearray(_checksum_frame(pcap_packet()))
    frame[22 if mutation == "ttl" else 24] ^= 1
    # The 5-tuple is intact: default tuple presence is not a checksum check.
    assert corroborate_pcap_zeek_tuples(pcap(bytes(frame)), zeek_log())[
        "matched_zeek_flow_count"
    ] == 1
    with pytest.raises(ValueError, match="IPv4 header checksum"):
        corroborate_pcap_zeek_tuples(
            pcap(bytes(frame)), zeek_log(),
            require_ipv4_header_checksum=True,
            require_timestamp_corroboration=True,
            require_distinct_packet_corroboration=True,
        )


def test_opt_in_checks_full_ipv4_options_header_and_ignores_arp():
    raw = bytearray(pcap_packet())
    raw[14] = 0x46  # 24-byte IPv4 header
    raw[16:18] = struct.pack("!H", 44)  # 24-byte IPv4 + 20-byte TCP
    raw[34:34] = b"\x01\x01\x01\x01"  # four NOP options
    frame = _checksum_frame(bytes(raw))
    arp = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28
    report = corroborate_pcap_zeek_tuples(
        pcap(arp, frame), zeek_log(), require_ipv4_header_checksum=True,
    )
    assert report["pcap_packet_count"] == 2
    assert report["supported_pcap_packet_count"] == 1


def test_standalone_cli_rechecks_pinned_checksum_without_success_on_failure(tmp_path, capsys):
    capture = tmp_path / "owned.pcap"
    log = tmp_path / "conn.log"
    capture.write_bytes(pcap(_checksum_frame(pcap_packet())))
    log.write_bytes(zeek_log())
    args = [
        "--pcap", str(capture),
        "--expected-pcap-sha256", hashlib.sha256(capture.read_bytes()).hexdigest(),
        "--log", str(log),
        "--expected-log-sha256", hashlib.sha256(log.read_bytes()).hexdigest(),
        "--require-ipv4-header-checksum",
    ]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["ipv4_header_checksum_verified"] is True
    damaged = bytearray(capture.read_bytes())
    damaged[-1] ^= 1  # TCP payload/header byte: IPv4 checksum does NOT cover this.
    capture.write_bytes(damaged)
    args[args.index("--expected-pcap-sha256") + 1] = hashlib.sha256(damaged).hexdigest()
    assert main(args) == 0  # Checksum is only over the IPv4 header.
    capsys.readouterr()
    damaged[16 + 24 + 8] ^= 1  # IPv4 TTL at Ethernet offset 22, PCAP record starts at 40.
    capture.write_bytes(damaged)
    args[args.index("--expected-pcap-sha256") + 1] = hashlib.sha256(damaged).hexdigest()
    assert main(args) == 2
    assert capsys.readouterr().out == ""


def test_integrated_checksum_gate_requires_tuple_and_strict_pins(tmp_path, imported):
    def enable(args, hp, gp):
        args.append("--require-pcap-ipv4-header-checksum")
    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr


@pytest.mark.parametrize("corrupt", [False, True])
def test_integrated_checksum_gate_is_private_and_fail_closed(tmp_path, imported, corrupt):
    def enable(args, hp, gp):
        args.extend([
            "--require-independent-original-pins",
            "--require-pcap-zeek-tuples",
            "--require-pcap-ipv4-header-checksum",
        ])
        frame = bytearray(_checksum_frame(pcap_packet(
            src="192.168.56.10", dst="192.168.56.20",
            sport=52344, dport=443,
        )))
        if corrupt:
            frame[22] ^= 1
        _repin_integrated_pcap(
            args, imported, pcap(bytes(frame), seconds=1630000000),
        )
    result = _run(tmp_path, imported, independent_pins=True, changes=enable)
    if corrupt:
        assert result.returncode == 1
        assert result.stdout == ""
        assert "refused" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["pcap_ipv4_header_checksum_required"] is True
        assert report["pcap_ipv4_header_checksum_verified"] is True
        assert report["capture_authenticity_verified"] is False
        assert report["vmware_isolation_verified"] is False
        assert "192.168.56" not in result.stdout
