"""Explicit offline analyst review cases for validated Zeek telemetry.

These are *unclassified manual-review records*, never AI detections or alerts.
Re-parse the original bounded bytes on submission so the selected evidence is
always tied to the exact source digest rather than a mutable UI dictionary.
"""
from __future__ import annotations

from pathlib import Path

from siem_ai.core import create_case

from .zeek import parse_zeek_conn_log


def create_offline_review_case(
    db_path: str | Path, *, source_data: bytes, record_index: int
) -> int:
    """Persist one operator-selected Zeek flow in a dedicated Cyber Lab DB.

    Does not infer attack labels, execute any network operation, or modify
    Dataset Mode's database. Each explicit call creates a new case; callers
    should not invoke this automatically on upload or page reruns.
    """
    if isinstance(record_index, bool) or not isinstance(record_index, int):
        raise ValueError("Record index must be an integer")
    if record_index < 0:
        raise ValueError("Record index out of range")

    # Parse from the original bytes, not a client-supplied event dictionary.
    events = parse_zeek_conn_log(source_data)
    if record_index >= len(events):
        raise ValueError("Record index out of range")
    return create_case(
        db_path, row=events[record_index], verdict="Unclassified", confidence=None
    )
