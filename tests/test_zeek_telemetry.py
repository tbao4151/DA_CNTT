"""Offline Zeek contract regression tests; all fixtures are synthetic."""
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from blue_team_ai.zeek import load_zeek_conn_log, parse_zeek_conn_log


FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "proto", "service", "duration", "orig_bytes", "resp_bytes",
          "orig_pkts", "resp_pkts")
VALUES = ("1630000000.25", "C123", "192.168.56.10", "52344", "192.168.56.20",
          "443", "tcp", "ssl", "1.25", "100", "200", "2", "3")


def log(*rows, fields=FIELDS):
    header = "#separator \\x09\n#fields\t" + "\t".join(fields) + "\n"
    return (header + "".join("\t".join(row) + "\n" for row in rows)).encode()


def test_offline_event_provenance_and_real_timestamp(tmp_path):
    data = log(VALUES)
    path = tmp_path / "conn.log"
    path.write_bytes(data)
    events = load_zeek_conn_log(path)
    assert len(events) == 1
    event = events[0]
    assert event["origin"] == "offline_zeek_log"
    assert event["source_sha256"] == hashlib.sha256(data).hexdigest()
    assert event["event_time_utc"] == "2021-08-26T17:46:40.250000+00:00"
    assert (event["src_ip"], event["dst_port"], event["orig_bytes"]) == (
        "192.168.56.10", 443, 100)
    assert "label" not in event and "AI_verdict" not in event
    assert "dur" not in event  # Not an UNSW-NB15 feature vector.


def test_missing_optional_zeek_fields_are_unknown_not_zero():
    fields = FIELDS[:7]
    event = parse_zeek_conn_log(log(VALUES[:7], fields=fields))[0]
    assert event["service"] is None
    assert event["duration_s"] is None
    assert event["orig_bytes"] is None


@pytest.mark.parametrize("index,bad", [
    (0, "-"), (0, "nan"), (2, "not-an-ip"), (3, "65536"),
    (5, "-"), (8, "inf"), (9, "-1"), (11, "1.5"),
])
def test_invalid_zeek_fields_rejected(index, bad):
    values = list(VALUES)
    values[index] = bad
    with pytest.raises(ValueError):
        parse_zeek_conn_log(log(values))


def test_wrong_field_count_and_duplicate_header_rejected():
    with pytest.raises(ValueError, match="field count"):
        parse_zeek_conn_log(log(VALUES[:-1]))
    with pytest.raises(ValueError, match="Duplicate"):
        parse_zeek_conn_log(log(VALUES).replace(b"#fields\t", b"#fields\t", 1) +
                            b"#fields\tts\n")


def test_duplicate_uid_rejected_even_if_endpoints_differ():
    second = list(VALUES)
    second[4] = "192.168.56.21"
    with pytest.raises(ValueError, match="Duplicate Zeek UID"):
        parse_zeek_conn_log(log(VALUES, second))
    # Reusing a five-tuple is legitimate when Zeek assigns a distinct UID.
    second[1] = "C124"
    assert len(parse_zeek_conn_log(log(VALUES, second))) == 2


def test_record_and_size_limits(tmp_path):
    with pytest.raises(ValueError, match="record limit"):
        parse_zeek_conn_log(log(VALUES, VALUES), max_records=1)
    with pytest.raises(ValueError, match="limits"):
        parse_zeek_conn_log(log(VALUES), max_bytes=16)
    path = tmp_path / "huge.log"
    path.write_bytes(b"x" * (15 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="limits"):
        load_zeek_conn_log(path)


def test_invalid_utf8_and_non_zeek_file_rejected():
    with pytest.raises(UnicodeDecodeError):
        parse_zeek_conn_log(log(VALUES) + b"\xff")
    with pytest.raises(ValueError, match="separator"):
        parse_zeek_conn_log(b"ts,uid\n1,C1\n")


def test_ipv6_and_absent_bytes_supported():
    values = list(VALUES)
    values[2] = "2001:db8::1"
    values[4] = "2001:db8::2"
    values[9] = "-"
    event = parse_zeek_conn_log(log(values))[0]
    assert event["src_ip"] == "2001:db8::1"
    assert event["orig_bytes"] is None


def test_single_zeek_types_header_accepted_but_duplicate_or_late_refused():
    # Real Zeek ASCII includes #types; legacy minimal fixtures may omit it.
    types = ("time", "string", "addr", "port", "addr", "port", "enum",
             "string", "interval", "count", "count", "count", "count")
    declaration = ("#types\t" + "\t".join(types) + "\n").encode()
    original = log(VALUES)
    header = original.splitlines(keepends=True)[1]
    typed = original.replace(header, header + declaration, 1)
    typed_event = parse_zeek_conn_log(typed)[0]
    minimal_event = parse_zeek_conn_log(original)[0]
    # The source digest must differ because the exact bytes differ.
    assert typed_event["source_sha256"] != minimal_event["source_sha256"]
    assert {key: value for key, value in typed_event.items()
            if key != "source_sha256"} == {
                key: value for key, value in minimal_event.items()
                if key != "source_sha256"
            }

    with pytest.raises(ValueError, match="Zeek types header"):
        parse_zeek_conn_log(typed.replace(declaration, declaration * 2, 1))
    with pytest.raises(ValueError, match="Zeek types header"):
        parse_zeek_conn_log(original + declaration)
    with pytest.raises(ValueError, match="Zeek types header"):
        parse_zeek_conn_log(typed + declaration)

def test_zeek_close_is_optional_but_terminal():
    original = log(VALUES)
    closed = original + b"#close\t2026-10-29-17-00-00\n"
    assert len(parse_zeek_conn_log(original)) == 1
    assert len(parse_zeek_conn_log(closed)) == 1

    second = list(VALUES)
    second[1] = "C124"
    second_row = ("\t".join(second) + "\n").encode()
    for invalid in (
        closed + second_row,
        closed + b"#close\t2026-10-29-17-01-00\n",
        closed + b"#fields\tts\n",
        original.replace(b"#fields\t", b"#close\t2026-10-29-17-00-00\n#fields\t", 1),
        original + b"#separator \\x09\n",
        original + b"#close\n",
    ):
        with pytest.raises(ValueError, match="Zeek (content after close|close marker|separator)"):
            parse_zeek_conn_log(invalid)
