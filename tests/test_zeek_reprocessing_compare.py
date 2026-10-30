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
