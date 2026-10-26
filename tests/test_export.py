"""Regression tests for exported CSV opened by spreadsheet programs."""
import io
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.export import safe_csv_bytes


def test_csv_export_escapes_formula_strings_but_keeps_numbers():
    rows = pd.DataFrame({
        "proto": ["=1+1", " +SUM(1,2)", "\t@HYPERLINK(\"x\")", "tcp", "\u200b=2+2"],
        "service": ["-cmd", "@SUM(1,2)", "normal", "http", "+1"],
        "sbytes": [0, -12, 30, 50, 99],
    })
    output = safe_csv_bytes(rows)
    assert output.startswith(b"\xef\xbb\xbf")
    loaded = pd.read_csv(io.BytesIO(output), dtype=str, keep_default_na=False)
    assert loaded["proto"].tolist() == ["'=1+1", "' +SUM(1,2)", "'\t@HYPERLINK(\"x\")", "tcp", "'\u200b=2+2"]
    assert loaded["service"].tolist() == ["'-cmd", "'@SUM(1,2)", "normal", "http", "'+1"]
    assert loaded["sbytes"].tolist() == ["0", "-12", "30", "50", "99"]


def test_csv_export_escapes_header_and_preserves_empty_values():
    rows = pd.DataFrame({"=dangerous": ["", None], "label": ["safe", "=HYPERLINK(\"x\")"]})
    loaded = pd.read_csv(io.BytesIO(safe_csv_bytes(rows)), dtype=str, keep_default_na=False)
    assert loaded.columns.tolist() == ["'=dangerous", "label"]
    assert loaded["'=dangerous"].tolist() == ["", ""]
    assert loaded["label"].tolist() == ["safe", "'=HYPERLINK(\"x\")"]


def test_export_does_not_modify_input():
    frame = pd.DataFrame({"text": ["=SUM(1,2)"]})
    safe_csv_bytes(frame)
    assert frame.iloc[0, 0] == "=SUM(1,2)"
