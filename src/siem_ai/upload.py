"""Bounded CSV import for the offline UNSW-NB15 dashboard.

Pandas renames repeated CSV headers (e.g. ``proto,proto`` to ``proto,proto.1``),
so validating DataFrame.columns alone cannot detect ambiguous source headers.
"""
from __future__ import annotations

import codecs
import csv
import io

import pandas as pd

MAX_CSV_BYTES = 15 * 1024 * 1024
MAX_PREVIEW_ROWS = 10_000


def read_uploaded_flows(content: bytes, *, limit: int, max_bytes: int = MAX_CSV_BYTES) -> pd.DataFrame:
    """Return at most ``limit`` rows after validating the entire bounded CSV.

    Only UTF-8 CSV is supported. Every logical row is checked for the same
    field count as the header, including rows outside the displayed preview.
    The caller must still run ``validate_flows`` for network-flow semantics.
    """
    if not isinstance(content, bytes):
        raise TypeError("Uploaded CSV must be bytes")
    if not content or len(content) > max_bytes:
        raise ValueError(f"CSV must be 1..{max_bytes:,} bytes")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PREVIEW_ROWS:
        raise ValueError(f"Preview row limit must be 1..{MAX_PREVIEW_ROWS:,}")

    # Python's csv.reader retains NUL characters while pandas' C CSV parser
    # silently truncates affected field values. Refuse ambiguous inputs rather
    # than presenting altered network features to the AI model or SOC analyst.
    if b"\x00" in content:
        raise ValueError("CSV contains NUL bytes; refusing ambiguous network-flow fields")

    # pandas.read_csv(nrows=limit) may never decode bytes after the preview.
    # Check the entire bounded upload with a streaming UTF-8 decoder so an
    # invalid tail is not accepted merely because it is outside the preview.
    try:
        decoder = codecs.getincrementaldecoder("utf-8-sig")(errors="strict")
        for start in range(0, len(content), 64 * 1024):
            decoder.decode(content[start:start + 64 * 1024], final=False)
        decoder.decode(b"", final=True)
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid UTF-8 CSV content") from exc

    try:
        with io.TextIOWrapper(io.BytesIO(content), encoding="utf-8-sig", newline="") as stream:
            reader = csv.reader(stream, strict=True)
            header = next(reader, None)
            if not header:
                raise ValueError("CSV header is missing")
            if any(not name.strip() for name in header):
                raise ValueError("CSV header contains blank column names")
            if len(header) != len(set(header)):
                raise ValueError("Duplicate CSV column names are not allowed")
            # Pandas can silently reinterpret extra fields as an index.
            # Validate every logical row in the already size-bounded upload,
            # not just the preview: malformed tails must not be accepted.
            # pandas.read_csv skips physically empty CSV lines by default;
            # a quoted empty field (['']) is still a row and must be checked.
            for row in reader:
                if not row:
                    continue
                if len(row) != len(header):
                    raise ValueError(
                        f"CSV row ending at line {reader.line_num} has {len(row)} "
                        f"fields; expected {len(header)}"
                    )
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid UTF-8 CSV content") from exc
    except csv.Error as exc:
        raise ValueError("Invalid CSV structure") from exc

    try:
        return pd.read_csv(io.BytesIO(content), nrows=limit, encoding="utf-8-sig")
    except (UnicodeDecodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        raise ValueError("Invalid UTF-8 CSV content") from exc
