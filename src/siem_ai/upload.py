"""Bounded CSV import for the offline UNSW-NB15 dashboard.

Pandas renames repeated CSV headers (e.g. ``proto,proto`` to ``proto,proto.1``),
so validating DataFrame.columns alone cannot detect ambiguous source headers.
"""
from __future__ import annotations

import csv
import io
from itertools import islice

import pandas as pd

MAX_CSV_BYTES = 15 * 1024 * 1024
MAX_PREVIEW_ROWS = 10_000


def read_uploaded_flows(content: bytes, *, limit: int, max_bytes: int = MAX_CSV_BYTES) -> pd.DataFrame:
    """Read at most ``limit`` rows, rejecting oversized or ambiguous CSV input.

    Only UTF-8 CSV is supported. The caller must still run ``validate_flows``
    to check required network-flow columns and row counts.
    """
    if not isinstance(content, bytes):
        raise TypeError("Uploaded CSV must be bytes")
    if not content or len(content) > max_bytes:
        raise ValueError(f"CSV must be 1..{max_bytes:,} bytes")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PREVIEW_ROWS:
        raise ValueError(f"Preview row limit must be 1..{MAX_PREVIEW_ROWS:,}")

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
            # Pandas can silently reinterpret the first field as an index when
            # a data row has more fields than its header. Validate the preview
            # with the CSV dialect parser before allowing AI inference.
            for row in islice(reader, limit):
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
