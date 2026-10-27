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


def test_upload_only_checks_preview_rows():
    data = (HEADER + "\n" + ROW + "\n" + ROW + ",unexpected\n").encode()
    frame = read_uploaded_flows(data, limit=1)
    assert len(frame) == 1

@pytest.mark.parametrize("data", [
    (HEADER.replace("proto", "proto\x00hidden") + "\n" + ROW + "\n").encode(),
    (HEADER + "\n" + ROW.replace("tcp", "tcp\x00hidden") + "\n").encode(),
    (HEADER + "\n" + ROW + "\n" + ROW.replace("tcp", "tcp\x00hidden") + "\n").encode(),
])
def test_upload_rejects_nul_bytes_in_header_or_data(data):
    # pandas' C parser can silently discard the suffix following a NUL byte.
    with pytest.raises(ValueError, match="NUL bytes"):
        read_uploaded_flows(data, limit=1)
