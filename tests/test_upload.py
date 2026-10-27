"""CSV import regression tests; no model, network or real SOC database needed."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.upload import read_uploaded_flows

HEADER = "dur,proto,service,state,sbytes,dbytes,spkts,dpkts"
ROW = "1,tcp,http,FIN,120,30,2,1"


def test_upload_accepts_utf8_bom_and_limits_preview_rows():
    data = (HEADER + "\n" + ROW + "\n" + ROW + "\n").encode("utf-8-sig")
    frame = read_uploaded_flows(data, limit=1)
    assert len(frame) == 1
    assert frame.columns.tolist() == HEADER.split(",")
    assert frame.iloc[0]["proto"] == "tcp"


def test_upload_rejects_duplicate_raw_header_before_pandas_mangles_names():
    data = (HEADER + ",proto\n" + ROW + ",udp\n").encode()
    with pytest.raises(ValueError, match="Duplicate CSV"):
        read_uploaded_flows(data, limit=100)


@pytest.mark.parametrize("data, message", [
    (b"", "CSV must"),
    (b"\n", "CSV header is missing"),
    (b"proto,,state\ntcp,,FIN\n", "blank column"),
    (b"\xff\xfe\n", "Invalid UTF-8 CSV content"),
])
def test_upload_rejects_invalid_headers(data, message):
    with pytest.raises(ValueError, match=message):
        read_uploaded_flows(data, limit=100)


def test_upload_rejects_oversized_content_before_parsing():
    data = (HEADER + "\n" + ROW + "\n").encode()
    with pytest.raises(ValueError, match="CSV must"):
        read_uploaded_flows(data, limit=100, max_bytes=len(data) - 1)


@pytest.mark.parametrize("limit", [0, -1, 10001, True])
def test_upload_rejects_invalid_row_limit(limit):
    with pytest.raises(ValueError, match="Preview row limit"):
        read_uploaded_flows((HEADER + "\n" + ROW).encode(), limit=limit)


def test_upload_rejects_invalid_utf8_in_body():
    data = (HEADER + "\n").encode() + b"1,tcp,\xff,FIN,120,30,2,1\n"
    with pytest.raises(ValueError, match="Invalid UTF-8 CSV content"):
        read_uploaded_flows(data, limit=100)


@pytest.mark.parametrize("bad_row", [
    ROW + ",unexpected",  # Pandas may silently treat the first field as an index.
    "1,tcp,http,FIN,120,30,2",  # Missing one field.
])
def test_upload_rejects_ragged_preview_rows(bad_row):
    data = (HEADER + "\n" + bad_row + "\n").encode()
    with pytest.raises(ValueError, match="fields; expected 8"):
        read_uploaded_flows(data, limit=100)


def test_upload_accepts_quoted_comma_without_false_field_mismatch():
    data = (HEADER + "\n" + '1,tcp,"http,proxy",FIN,120,30,2,1\n').encode()
    frame = read_uploaded_flows(data, limit=100)
    assert frame.iloc[0]["service"] == "http,proxy"


def test_upload_rejects_unclosed_quoted_field():
    data = (HEADER + "\n" + '1,tcp,"http,FIN,120,30,2,1\n').encode()
    with pytest.raises(ValueError, match="Invalid CSV structure"):
        read_uploaded_flows(data, limit=100)


@pytest.mark.parametrize("bad_tail", [
    ROW + ",unexpected",
    "1,tcp,http,FIN,120,30,2",
])
def test_upload_rejects_ragged_rows_after_preview(bad_tail):
    # The tail is not displayed, but must not silently bypass validation.
    data = (HEADER + "\n" + ROW + "\n" + bad_tail + "\n").encode()
    with pytest.raises(ValueError, match="fields; expected 8"):
        read_uploaded_flows(data, limit=1)


def test_upload_rejects_unclosed_quote_after_preview():
    data = (HEADER + "\n" + ROW + '\n1,tcp,"unclosed\n').encode()
    with pytest.raises(ValueError, match="Invalid CSV structure"):
        read_uploaded_flows(data, limit=1)


def test_upload_accepts_valid_quoted_multiline_tail():
    data = (HEADER + "\n" + ROW + '\n1,tcp,"http,\nproxy",FIN,120,30,2,1\n').encode()
    frame = read_uploaded_flows(data, limit=1)
    assert len(frame) == 1
    assert frame.iloc[0]["proto"] == "tcp"


def test_upload_checks_row_beyond_max_preview_rows():
    data = (HEADER + "\n" + (ROW + "\n") * 10_000 + ROW + ",unexpected\n").encode()
    with pytest.raises(ValueError, match="fields; expected 8"):
        read_uploaded_flows(data, limit=10_000)

@pytest.mark.parametrize("data", [
    (HEADER.replace("proto", "proto\x00hidden") + "\n" + ROW + "\n").encode(),
    (HEADER + "\n" + ROW.replace("tcp", "tcp\x00hidden") + "\n").encode(),
    (HEADER + "\n" + ROW + "\n" + ROW.replace("tcp", "tcp\x00hidden") + "\n").encode(),
])
def test_upload_rejects_nul_bytes_in_header_or_data(data):
    # pandas' C parser can silently discard the suffix following a NUL byte.
    with pytest.raises(ValueError, match="NUL bytes"):
        read_uploaded_flows(data, limit=1)


def test_upload_accepts_empty_lines_between_preview_flows():
    # pandas skips physically empty CSV lines; validation must use the same
    # logical row count, not treat a blank line as a malformed flow.
    data = (HEADER + "\n" + ROW + "\n\n" + ROW + "\n").encode()
    frame = read_uploaded_flows(data, limit=2)
    assert len(frame) == 2
    assert frame["proto"].tolist() == ["tcp", "tcp"]


def test_upload_checks_row_after_blank_line_within_preview():
    data = (HEADER + "\n" + ROW + "\n\n" + ROW + ",unexpected\n").encode()
    with pytest.raises(ValueError, match="fields; expected 8"):
        read_uploaded_flows(data, limit=2)


def test_upload_does_not_skip_quoted_empty_field_row():
    # A quoted empty value is a real CSV record, not a physically blank line.
    data = (HEADER + "\n" + ROW + "\n\"\"\n").encode()
    with pytest.raises(ValueError, match="fields; expected 8"):
        read_uploaded_flows(data, limit=2)


def test_upload_rejects_malformed_row_after_logical_preview_with_blank_lines():
    data = (HEADER + "\n" + ROW + "\n\n" + ROW + "\n" + ROW + ",unexpected\n").encode()
    with pytest.raises(ValueError, match="fields; expected 8"):
        read_uploaded_flows(data, limit=2)


@pytest.mark.parametrize("tail", [
    b"1,tcp,\xff,FIN,120,30,2,1\n",
    b"1,tcp,\xc3",
    b"1,tcp,\xe2\x82",
])
def test_upload_rejects_invalid_utf8_after_preview(tail):
    # The pandas nrows limit alone would not decode this unselected tail.
    data = (HEADER + "\n" + ROW + "\n").encode() + tail
    with pytest.raises(ValueError, match="Invalid UTF-8 CSV content"):
        read_uploaded_flows(data, limit=1)


def test_upload_accepts_valid_utf8_after_preview():
    data = (HEADER + "\n" + ROW + "\n" + "1,tcp,café,FIN,120,30,2,1\n").encode("utf-8")
    frame = read_uploaded_flows(data, limit=1)
    assert len(frame) == 1
    assert frame.iloc[0]["proto"] == "tcp"


def test_upload_rejects_utf8_sequence_split_across_decoder_chunks():
    # The invalid continuation crosses the 64-KiB decoder chunk boundary.
    prefix = (HEADER + "\n" + ROW + "\n").encode()
    padding = b" " * (65535 - len(prefix))
    data = prefix + padding + b"\xc3\x28"
    with pytest.raises(ValueError, match="Invalid UTF-8 CSV content"):
        read_uploaded_flows(data, limit=1)
