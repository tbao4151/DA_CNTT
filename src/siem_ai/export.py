"""CSV export helpers that prevent spreadsheet formula injection.

Spreadsheet programs may evaluate a text cell beginning with =, +, - or @ as a
formula. CSV quoting alone does not prevent that behavior. Keep numeric values
numeric; prefix only dangerous *text* cells with an apostrophe.
"""
from __future__ import annotations

import pandas as pd

_FORMULA_START = ("=", "+", "-", "@")
_IGNORABLE_PREFIX = "".join(chr(i) for i in range(33)) + "\ufeff\u200b\u200c\u200d\u2060"


def _escape_formula(value: object) -> object:
    if not isinstance(value, str):
        return value
    # Treat leading whitespace, control characters and invisible Unicode as
    # ignorable when detecting a spreadsheet formula. Preserve the original
    # text, adding a leading apostrophe only when potentially unsafe.
    visible = value.lstrip(_IGNORABLE_PREFIX)
    if visible.startswith(_FORMULA_START) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def safe_csv_bytes(frame: pd.DataFrame) -> bytes:
    """Export a DataFrame for spreadsheet viewing without active text formulas.

    The UTF-8 BOM improves Excel's Unicode handling. Do not use this function
    as a reversible archival serialization: escaped text gains an apostrophe.
    """
    safe = frame.copy()
    safe.columns = [_escape_formula(str(column)) for column in safe.columns]
    for column in safe.columns:
        if pd.api.types.is_object_dtype(safe[column].dtype) or pd.api.types.is_string_dtype(safe[column].dtype):
            safe[column] = safe[column].map(_escape_formula)
    return safe.to_csv(index=False).encode("utf-8-sig")
