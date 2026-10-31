"""Synthetic offline PCAP/Zeek tuple presence regressions; no VMware or traffic."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.pcap_zeek_tuple import corroborate_pcap_zeek_tuples
from verify_pcap_zeek_tuple import main


def zeek_log(*, src="10.1.1.2", dst="10.1.1.3", sport=1234, dport=80,
             proto="tcp", second=False, ts="100.0") -> bytes:
    rows = [f"{ts}\tC1\t{src}\t{sport}\t{dst}\t{dport}\t{proto}"]
    if second:
        rows.append("101.0\tC2\t10.1.1.4\t5555\t10.1.1.5\t443\ttcp")
    return ("#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            + "\n".join(rows) + "\n").encode()


def pcap_packet(*, src="10.1.1.2", dst="10.1.1.3", sport=1234, dport=80,
                proto=6, fragment=0, ethertype=0x0800, truncate=0) -> bytes:
    if proto == 6:
        transport = struct.pack("!HHIIHHHH", sport, dport, 0, 0, 0x5000, 0, 0, 0)
    else:
        transport = struct.pack("!HHHH", sport, dport, 8, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 0,
                     fragment, 64, proto, 0,
                     ipaddress.IPv4Address(src).packed,
                     ipaddress.IPv4Address(dst).packed)
    return (b"\x00" * 12 + struct.pack("!H", ethertype) + ip + transport)[:-truncate or None]


def pcap(*frames: bytes, linktype=1, seconds=100, fraction=0, nanos=False) -> bytes:
    magic = "4d3cb2a1" if nanos else "d4c3b2a1"
    out = bytearray(bytes.fromhex(magic) + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, linktype))
    for frame in frames:
        out.extend(struct.pack("<IIII", seconds, fraction, len(frame), len(frame)))
        out.extend(frame)
    return bytes(out)


def test_exact_and_reverse_packet_directions():
    packet = pcap_packet()
    result = corroborate_pcap_zeek_tuples(pcap(packet), zeek_log())
    assert result["matched_zeek_flow_count"] == 1
    assert result["packet_to_flow_identity_verified"] is False
    assert result["timestamps_correlated"] is False
    reverse = zeek_log(src="10.1.1.3", dst="10.1.1.2", sport=80, dport=1234)
    assert corroborate_pcap_zeek_tuples(pcap(packet), reverse)["matched_zeek_flow_count"] == 1


def test_udp_and_unrelated_non_ipv4_packet():
    arp = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28
    result = corroborate_pcap_zeek_tuples(
        pcap(arp, pcap_packet(proto=17)), zeek_log(proto="udp"),
    )
    assert result["pcap_packet_count"] == 2
    assert result["supported_pcap_packet_count"] == 1


@pytest.mark.parametrize("mutation", ["wrong_port", "wrong_ip", "missing_second",
                                    "unsupported_linktype", "fragment", "vlan",
                                    "short_ethernet", "short_ip", "short_tcp",
                                    "header_only", "unsupported_zeek_proto", "ipv6_zeek"])
def test_refuse_unsupported_or_missing_corroboration(mutation):
    packet = pcap_packet()
    log = zeek_log()
    linktype = 1
    if mutation == "wrong_port":
        log = zeek_log(dport=81)
    elif mutation == "wrong_ip":
        log = zeek_log(dst="10.1.1.9")
    elif mutation == "missing_second":
        log = zeek_log(second=True)
    elif mutation == "unsupported_linktype":
        linktype = 101
    elif mutation == "fragment":
        packet = pcap_packet(fragment=0x2000)
    elif mutation == "vlan":
        packet = pcap_packet(ethertype=0x8100)
    elif mutation == "short_ethernet":
        packet = b"1234"
    elif mutation == "short_ip":
        packet = pcap_packet(truncate=35)
    elif mutation == "short_tcp":
        packet = pcap_packet(truncate=8)
    elif mutation == "header_only":
        packet = None
    elif mutation == "unsupported_zeek_proto":
        log = zeek_log(proto="icmp")
    elif mutation == "ipv6_zeek":
        log = zeek_log(src="fd00::1")
    with pytest.raises(ValueError):
        corroborate_pcap_zeek_tuples(pcap(*([] if packet is None else [packet]), linktype=linktype), log)


@pytest.mark.parametrize("declared_udp_length", [0, 7, 9, 65535])
def test_udp_tuple_corroboration_refuses_impossible_datagram_length(declared_udp_length):
    # IPv4 payload is exactly the eight-byte UDP header in this fixture.
    # Re-pinning the packet would not make a malformed UDP length valid.
    frame = bytearray(pcap_packet(proto=17))
    struct.pack_into("!H", frame, 14 + 20 + 4, declared_udp_length)
    with pytest.raises(ValueError, match="Invalid IPv4 UDP datagram length"):
        corroborate_pcap_zeek_tuples(
            pcap(bytes(frame)), zeek_log(proto="udp"),
        )
    with pytest.raises(ValueError, match="Invalid IPv4 UDP datagram length"):
        corroborate_pcap_zeek_tuples(
            pcap(bytes(frame)), zeek_log(proto="udp"),
            require_timestamp_corroboration=True,
        )



@pytest.mark.parametrize("proto,zeek_proto", [(6, "tcp"), (17, "udp")])
@pytest.mark.parametrize("timestamp_gate", [False, True])
def test_ipv4_total_length_must_fit_original_pcap_frame(proto, zeek_proto, timestamp_gate):
    # Captured transport headers alone do not validate an impossible
    # original-frame length, even when tuple and timestamps match.
    frame = bytearray(pcap_packet(proto=proto))
    struct.pack_into("!H", frame, 14 + 2, 200)
    if proto == 17:
        struct.pack_into("!H", frame, 14 + 20 + 4, 180)
    with pytest.raises(ValueError, match="exceeds original PCAP Ethernet frame"):
        corroborate_pcap_zeek_tuples(
            pcap(bytes(frame)), zeek_log(proto=zeek_proto),
            require_timestamp_corroboration=timestamp_gate,
        )


@pytest.mark.parametrize("proto,zeek_proto", [(6, "tcp"), (17, "udp")])
@pytest.mark.parametrize("timestamp_gate", [False, True])
def test_snaplen_truncated_ipv4_payload_with_valid_original_length(proto, zeek_proto, timestamp_gate):
    # A real snapshot can contain the full IP/transport headers but omit
    # payload bytes; original length (not captured length) is the bound.
    frame = bytearray(pcap_packet(proto=proto))
    struct.pack_into("!H", frame, 14 + 2, 200)
    if proto == 17:
        struct.pack_into("!H", frame, 14 + 20 + 4, 180)
    raw = bytearray(pcap(bytes(frame)))
    struct.pack_into("<I", raw, 16, len(frame))  # snaplen
    struct.pack_into("<I", raw, 24 + 12, 14 + 200)  # original record length
    result = corroborate_pcap_zeek_tuples(
        bytes(raw), zeek_log(proto=zeek_proto),
        require_timestamp_corroboration=timestamp_gate,
    )
    assert result["matched_zeek_flow_count"] == 1
    assert result["packet_to_flow_identity_verified"] is False

def test_repeated_zeek_tuples_are_only_existence_correlated():
    log = zeek_log().decode()
    log += "101.0\tC2\t10.1.1.2\t1234\t10.1.1.3\t80\ttcp\n"
    result = corroborate_pcap_zeek_tuples(pcap(pcap_packet()), log.encode())
    assert result["matched_zeek_flow_count"] == 2
    assert result["supported_pcap_packet_count"] == 1
    assert result["packet_to_flow_identity_verified"] is False


def test_cli_independent_sha_pins_and_no_success_on_tamper(tmp_path, capsys):
    capture = tmp_path / "capture.pcap"
    log = tmp_path / "conn.log"
    capture.write_bytes(pcap(pcap_packet()))
    log.write_bytes(zeek_log())
    cmd = ["--pcap", str(capture), "--expected-pcap-sha256",
           hashlib.sha256(capture.read_bytes()).hexdigest(),
           "--log", str(log), "--expected-log-sha256",
           hashlib.sha256(log.read_bytes()).hexdigest()]
    assert main(cmd) == 0
    success = json.loads(capsys.readouterr().out)
    assert success["matched_zeek_flow_count"] == 1
    assert "10.1.1." not in json.dumps(success)
    log.write_bytes(zeek_log(dport=81))
    assert main(cmd) == 2
    assert capsys.readouterr().out == ""


def test_cli_refuses_invalid_pin_and_repo_relative_path(tmp_path, capsys):
    capture = tmp_path / "capture.pcap"
    log = tmp_path / "conn.log"
    capture.write_bytes(pcap(pcap_packet()))
    log.write_bytes(zeek_log())
    cmd = ["--pcap", str(capture), "--expected-pcap-sha256", "0" * 64,
           "--log", str(log), "--expected-log-sha256", "1" * 64]
    assert main(cmd) == 2
    assert capsys.readouterr().out == ""
    cmd[1] = "relative.pcap"
    assert main(cmd) == 2
    assert capsys.readouterr().out == ""


def test_opt_in_timestamp_correspondence_micro_and_nano():
    packet = pcap_packet()
    for nanos, fraction in ((False, 500_000), (True, 500_000_000)):
        raw = pcap(packet, seconds=100, fraction=fraction, nanos=nanos)
        log = zeek_log(ts="100.5")
        result = corroborate_pcap_zeek_tuples(
            raw, log, require_timestamp_corroboration=True,
        )
        assert result["timestamps_correlated"] is True
        assert result["timestamp_corroboration_window_seconds"] == 1.0
        reverse = zeek_log(
            src="10.1.1.3", dst="10.1.1.2", sport=80, dport=1234, ts="100.5",
        )
        assert corroborate_pcap_zeek_tuples(
            raw, reverse, require_timestamp_corroboration=True,
        )["matched_zeek_flow_count"] == 1


def test_opt_in_timestamp_rejects_reused_tuple_from_distant_session():
    raw = pcap(pcap_packet(), seconds=100)
    forged_time = zeek_log(ts="105.0")
    legacy = corroborate_pcap_zeek_tuples(raw, forged_time)
    assert legacy["timestamps_correlated"] is False
    assert legacy["timestamp_corroboration_window_seconds"] is None
    with pytest.raises(ValueError, match="within one second"):
        corroborate_pcap_zeek_tuples(
            raw, forged_time, require_timestamp_corroboration=True,
        )


def test_opt_in_timestamp_requires_each_zeek_flow_to_match():
    raw = pcap(pcap_packet(), seconds=100)
    log = zeek_log().decode() + "105.0\tC2\t10.1.1.2\t1234\t10.1.1.3\t80\ttcp\n"
    with pytest.raises(ValueError, match="within one second"):
        corroborate_pcap_zeek_tuples(
            raw, log.encode(), require_timestamp_corroboration=True,
        )


def test_cli_opt_in_timestamp_gate_fails_closed(tmp_path, capsys):
    capture = tmp_path / "owned.pcap"
    log = tmp_path / "conn.log"
    capture.write_bytes(pcap(pcap_packet()))
    log.write_bytes(zeek_log())
    args = [
        "--pcap", str(capture),
        "--expected-pcap-sha256", hashlib.sha256(capture.read_bytes()).hexdigest(),
        "--log", str(log),
        "--expected-log-sha256", hashlib.sha256(log.read_bytes()).hexdigest(),
        "--require-timestamp-corroboration",
    ]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["timestamps_correlated"] is True
    log.write_bytes(zeek_log(ts="105.0"))
    args[args.index("--expected-log-sha256") + 1] = hashlib.sha256(log.read_bytes()).hexdigest()
    assert main(args) == 2
    assert capsys.readouterr().out == ""
