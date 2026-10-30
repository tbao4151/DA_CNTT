"""Synthetic Zeek replay comparison regressions; no Zeek binary or VMware."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.zeek_reprocessing_compare import compare_parsed_zeek_reprocessing
from compare_zeek_reprocessing import main


FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
          "id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes",
          "orig_pkts", "resp_pkts", "conn_state")


def _row(ts="100.0", uid="A", src="10.1.1.2", sport="1234", dst="10.1.1.3",
         dport="80", proto="tcp", duration="1.0", orig_bytes="10",
         resp_bytes="20", orig_pkts="2", resp_pkts="3", conn_state="SF"):
    return (ts, uid, src, sport, dst, dport, proto, duration, orig_bytes,
            resp_bytes, orig_pkts, resp_pkts, conn_state)


def _log(*rows):
    return ("#separator \\x09\n"
            + "#fields\t" + "\t".join(FIELDS) + "\n"
            + "".join("\t".join(row) + "\n" for row in rows)).encode()


def test_uid_changes_and_row_order_do_not_create_false_mismatch():
    original = _log(_row(), _row(ts="101.0", uid="B", sport="5555"))
    replayed = _log(_row(ts="101.0", uid="NEW2", sport="5555"),
                    _row(uid="NEW1"))
    report = compare_parsed_zeek_reprocessing(original, replayed)
    assert report["flow_count"] == 2
    assert report["uid_equivalence_verified"] is False
    assert report["pcap_origin_verified"] is False
    assert "10.1.1." not in json.dumps(report)
    assert "NEW1" not in json.dumps(report)


@pytest.mark.parametrize("change", [
    {"ts": "100.000001"},
    {"src": "10.1.1.9"},
    {"dport": "81"},
    {"proto": "udp"},
    {"duration": "1.1"},
    {"orig_bytes": "11"},
    {"resp_bytes": "21"},
    {"orig_pkts": "4"},
    {"resp_pkts": "5"},
])
def test_supported_field_change_is_refused(change):
    with pytest.raises(ValueError, match="differ"):
        compare_parsed_zeek_reprocessing(_log(_row()), _log(_row(uid="B", **change)))


def test_duplicate_multiplicity_must_match():
    left = _log(_row(), _row(uid="B"))
    with pytest.raises(ValueError, match="differ"):
        compare_parsed_zeek_reprocessing(left, _log(_row(uid="NEW")))


def test_unparsed_fields_are_explicitly_not_compared():
    report = compare_parsed_zeek_reprocessing(
        _log(_row(conn_state="SF")),
        _log(_row(uid="B", conn_state="S0")),
    )
    assert report["unparsed_zeek_fields_compared"] is False


def test_malformed_zeek_log_refused():
    with pytest.raises(ValueError):
        compare_parsed_zeek_reprocessing(_log(_row()), b"not a Zeek log")


def test_cli_independent_pins_and_private_report(tmp_path, capsys):
    first = tmp_path / "original.log"
    second = tmp_path / "reprocessed.log"
    first.write_bytes(_log(_row()))
    second.write_bytes(_log(_row(uid="REPLAY")))
    args = ["--original-log", str(first), "--expected-original-sha256",
            hashlib.sha256(first.read_bytes()).hexdigest(),
            "--reprocessed-log", str(second), "--expected-reprocessed-sha256",
            hashlib.sha256(second.read_bytes()).hexdigest()]
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["flow_count"] == 1
    assert "10.1.1." not in json.dumps(report)
    second.write_bytes(_log(_row(uid="REPLAY", dport="81")))
    assert main(args) == 2
    assert capsys.readouterr().out == ""


def test_cli_rejects_same_path_bad_pin_and_relative_path(tmp_path, capsys):
    first = tmp_path / "original.log"
    second = tmp_path / "reprocessed.log"
    first.write_bytes(_log(_row()))
    second.write_bytes(_log(_row(uid="B")))
    pin = hashlib.sha256(first.read_bytes()).hexdigest()
    args = ["--original-log", str(first), "--expected-original-sha256", pin,
            "--reprocessed-log", str(first), "--expected-reprocessed-sha256", pin]
    assert main(args) == 2
    assert capsys.readouterr().out == ""
    args[args.index("--reprocessed-log") + 1] = str(second)
    args[-1] = "0" * 64
    assert main(args) == 2
    assert capsys.readouterr().out == ""
    args[1] = "relative.log"
    assert main(args) == 2
    assert capsys.readouterr().out == ""


from blue_team_ai.zeek_reprocessing_compare import compare_strict_zeek_reprocessing


def _extra_log(*, uid="A", conn_state="SF", history="ShADad", order=None,
               extra_field=True, typed=False, unset_header=False):
    fields = list(FIELDS) + (["history"] if extra_field else [])
    row = list(_row(uid=uid, conn_state=conn_state)) + ([history] if extra_field else [])
    if order is not None:
        fields = [fields[i] for i in order]
        row = [row[i] for i in order]
    header = "#separator \\x09\n"
    if unset_header:
        header += "#unset_field\t-\n"
    header += "#fields\t" + "\t".join(fields) + "\n"
    if typed:
        header += "#types\t" + "\t".join(
            "time" if name == "ts" else "string" for name in fields
        ) + "\n"
    return (header + "\t".join(row) + "\n").encode()


def test_strict_comparison_accepts_uid_change_and_reordered_schema():
    count = len(FIELDS) + 1
    left = _extra_log(uid="FIRST", typed=True)
    right = _extra_log(uid="SECOND", order=list(reversed(range(count))), typed=True)
    report = compare_strict_zeek_reprocessing(left, right)
    assert report["flow_count"] == 1
    assert report["unparsed_zeek_fields_compared"] is True
    assert report["declared_types_compared"] is True
    assert report["uid_equivalence_verified"] is False
    assert "history" in report["compared_fields"]
    assert "10.1.1." not in json.dumps(report)


@pytest.mark.parametrize("change", [
    {"conn_state": "S0"},
    {"history": "different"},
    {"extra_field": False},
    {"typed": True},
    {"unset_header": True},
])
def test_strict_comparison_refuses_unparsed_or_schema_changes(change):
    with pytest.raises(ValueError, match="strict"):
        compare_strict_zeek_reprocessing(_extra_log(), _extra_log(uid="B", **change))


def test_strict_comparison_preserves_default_legacy_behavior():
    left = _extra_log()
    right = _extra_log(uid="B", history="different")
    assert compare_parsed_zeek_reprocessing(left, right)["unparsed_zeek_fields_compared"] is False
    with pytest.raises(ValueError, match="strict"):
        compare_strict_zeek_reprocessing(left, right)


def test_strict_comparison_is_sensitive_to_raw_numeric_format():
    original = _log(_row(ts="100.0"))
    replayed = _log(_row(uid="B", ts="100.00"))
    assert compare_parsed_zeek_reprocessing(original, replayed)["flow_count"] == 1
    with pytest.raises(ValueError, match="strict"):
        compare_strict_zeek_reprocessing(original, replayed)


def test_cli_strict_mode_and_no_partial_success(tmp_path, capsys):
    original = tmp_path / "strict-a.log"
    second = tmp_path / "strict-b.log"
    original.write_bytes(_extra_log())
    second.write_bytes(_extra_log(uid="B"))
    args = ["--original-log", str(original),
            "--expected-original-sha256", hashlib.sha256(original.read_bytes()).hexdigest(),
            "--reprocessed-log", str(second),
            "--expected-reprocessed-sha256", hashlib.sha256(second.read_bytes()).hexdigest(),
            "--strict-all-fields"]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["unparsed_zeek_fields_compared"] is True
    second.write_bytes(_extra_log(uid="B", conn_state="S0"))
    args[7] = hashlib.sha256(second.read_bytes()).hexdigest()
    assert main(args) == 2
    assert capsys.readouterr().out == ""


# Synthetic classic Ethernet IPv4/TCP evidence for optional PCAP/Zeek gate.
def _tcp_pcap(*, dport=80, linktype=1):
    import ipaddress
    import struct

    transport = struct.pack("!HHIIHHHH", 1234, dport, 0, 0, 0x5000, 0, 0, 0)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 0, 0, 64, 6, 0,
        ipaddress.IPv4Address("10.1.1.2").packed,
        ipaddress.IPv4Address("10.1.1.3").packed,
    )
    frame = b"\x00" * 12 + struct.pack("!H", 0x0800) + ipv4 + transport
    return (bytes.fromhex("d4c3b2a1")
            + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, linktype)
            + struct.pack("<IIII", 100, 0, len(frame), len(frame))
            + frame)


def _pinned_compare_args(first, second):
    return [
        "--original-log", str(first),
        "--expected-original-sha256", hashlib.sha256(first.read_bytes()).hexdigest(),
        "--reprocessed-log", str(second),
        "--expected-reprocessed-sha256", hashlib.sha256(second.read_bytes()).hexdigest(),
    ]


def test_cli_pinned_pcap_corrob_checks_both_logs_and_preserves_default(tmp_path, capsys, monkeypatch):
    import compare_zeek_reprocessing as cli

    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    capture = tmp_path / "original.pcap"
    first.write_bytes(_log(_row()))
    second.write_bytes(_log(_row(uid="REPLAY")))
    capture.write_bytes(_tcp_pcap())
    args = _pinned_compare_args(first, second)
    assert main(args) == 0
    assert "pcap_tuple_presence_checked" not in json.loads(capsys.readouterr().out)

    actual = cli.corroborate_pcap_zeek_tuples
    seen = []

    def observed(pcap_bytes, log_bytes):
        seen.append(log_bytes)
        return actual(pcap_bytes, log_bytes)

    monkeypatch.setattr(cli, "corroborate_pcap_zeek_tuples", observed)
    args += ["--pcap", str(capture), "--expected-pcap-sha256",
             hashlib.sha256(capture.read_bytes()).hexdigest()]
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert seen == [first.read_bytes(), second.read_bytes()]
    assert report["pcap_tuple_presence_for_both_logs"] is True
    assert report["pcap_origin_verified"] is False
    assert report["packet_to_flow_identity_verified"] is False
    assert report["pcap_packet_count"] == 1
    assert "10.1.1." not in json.dumps(report)


@pytest.mark.parametrize("failure", [
    "missing_pin", "missing_pcap", "wrong_pin", "unmatched_tuple",
    "unsupported_linktype", "same_path",
])
def test_cli_pinned_pcap_corrob_refuses_without_partial_success(tmp_path, capsys, failure):
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    capture = tmp_path / "original.pcap"
    first.write_bytes(_log(_row(dport="81" if failure == "unmatched_tuple" else "80")))
    second.write_bytes(_log(_row(uid="REPLAY", dport="81" if failure == "unmatched_tuple" else "80")))
    capture.write_bytes(_tcp_pcap(linktype=101 if failure == "unsupported_linktype" else 1))
    args = _pinned_compare_args(first, second)
    pcap_path = first if failure == "same_path" else capture
    if failure != "missing_pcap":
        args += ["--pcap", str(pcap_path)]
    if failure != "missing_pin":
        args += ["--expected-pcap-sha256",
                 ("0" * 64 if failure == "wrong_pin" else
                  hashlib.sha256(pcap_path.read_bytes()).hexdigest())]
    assert main(args) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "refused" in output.err.lower()


def test_cli_strict_all_fields_combines_with_pinned_pcap(tmp_path, capsys):
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    capture = tmp_path / "original.pcap"
    first.write_bytes(_extra_log())
    second.write_bytes(_extra_log(uid="REPLAY"))
    capture.write_bytes(_tcp_pcap())
    args = _pinned_compare_args(first, second)
    args += ["--strict-all-fields", "--pcap", str(capture),
             "--expected-pcap-sha256", hashlib.sha256(capture.read_bytes()).hexdigest()]
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["unparsed_zeek_fields_compared"] is True
    assert report["pcap_tuple_presence_for_both_logs"] is True
