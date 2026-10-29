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


def test_canonical_zeek_ascii_sentinels_preserve_missing_vs_empty_service():
    # Zeek's default ASCII metadata is optional for minimal fixtures, but
    # when present it must describe the parser's actual missing-value rules.
    original = log(VALUES)
    metadata = (
        b"#set_separator\t,\n"
        b"#empty_field\t(empty)\n"
        b"#unset_field\t-\n"
        b"#path\tconn\n"
        b"#open\t2026-10-29-17-00-00\n"
    )
    declared = original.replace(b"#fields\t", metadata + b"#fields\t", 1)
    assert parse_zeek_conn_log(declared)[0]["service"] == "ssl"

    empty = list(VALUES)
    empty[7] = "(empty)"
    empty_log = log(empty).replace(b"#fields\t", metadata + b"#fields\t", 1)
    assert parse_zeek_conn_log(empty_log)[0]["service"] == ""
    # No declaration means the literal string remains unchanged for legacy
    # minimal logs: do not silently reinterpret arbitrary source values.
    assert parse_zeek_conn_log(log(empty))[0]["service"] == "(empty)"

    unset = list(VALUES)
    unset[7] = "-"
    unset_log = log(unset).replace(b"#fields\t", metadata + b"#fields\t", 1)
    assert parse_zeek_conn_log(unset_log)[0]["service"] is None


@pytest.mark.parametrize("metadata,expected", [
    (b"#unset_field\t?\n", "unset_field"),
    (b"#unset_field\n", "unset_field"),
    (b"#empty_field\t?\n", "empty_field"),
    (b"#empty_field\n", "empty_field"),
    (b"#path\tdns\n", "conn path"),
    (b"#path\n", "conn path"),
    (b"#unset_field\t-\n#unset_field\t-\n", "unset_field"),
    (b"#empty_field\t(empty)\n#empty_field\t(empty)\n", "empty_field"),
    (b"#path\tconn\n#path\tconn\n", "conn path"),
])
def test_zeek_metadata_mismatch_and_duplicates_fail_closed(metadata, expected):
    original = log(VALUES)
    malformed = original.replace(b"#fields\t", metadata + b"#fields\t", 1)
    with pytest.raises(ValueError, match=expected):
        parse_zeek_conn_log(malformed)


@pytest.mark.parametrize("metadata,expected", [
    (b"#unset_field\t-\n", "unset_field"),
    (b"#empty_field\t(empty)\n", "empty_field"),
    (b"#path\tconn\n", "conn path"),
])
def test_late_zeek_metadata_cannot_redefine_existing_flows(metadata, expected):
    with pytest.raises(ValueError, match=expected):
        parse_zeek_conn_log(log(VALUES) + metadata)


def test_zeek_open_and_set_separator_are_optional_but_checked():
    original = log(VALUES)
    metadata = b"#set_separator\t,\n#open\t2026-10-29-17-00-00\n"
    declared = original.replace(b"#fields\t", metadata + b"#fields\t", 1)
    assert parse_zeek_conn_log(declared)[0]["uid"] == "C123"
    assert parse_zeek_conn_log(original)[0]["uid"] == "C123"


@pytest.mark.parametrize("metadata,expected", [
    (b"#set_separator\t;\n", "set_separator"),
    (b"#set_separator\n", "set_separator"),
    (b"#set_separator\t,\n#set_separator\t,\n", "set_separator"),
    (b"#open\n", "open marker"),
    (b"#open\t2026-02-30-17-00-00\n", "open marker timestamp"),
    (b"#open\t2026-10-29-17-00-00\n#open\t2026-10-29-17-00-01\n", "open marker"),
])
def test_noncanonical_or_duplicate_open_and_set_metadata_refused(metadata, expected):
    original = log(VALUES)
    with pytest.raises(ValueError, match=expected):
        parse_zeek_conn_log(original.replace(b"#fields\t", metadata + b"#fields\t", 1))


@pytest.mark.parametrize("metadata,expected", [
    (b"#set_separator\t,\n", "set_separator"),
    (b"#open\t2026-10-29-17-00-00\n", "open marker"),
])
def test_late_open_and_set_metadata_refused_before_or_after_rows(metadata, expected):
    original = log(VALUES)
    for malformed in (
        original + metadata,
        original.replace(b"\n1630000000.25", b"\n" + metadata + b"1630000000.25", 1),
    ):
        with pytest.raises(ValueError, match=expected):
            parse_zeek_conn_log(malformed)
