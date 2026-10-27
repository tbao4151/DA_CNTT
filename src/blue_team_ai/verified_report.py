"""Verified, type-preserving export of one manually reviewed offline Zeek flow.

This is a source-consistency check, not forensic authentication or AI inference.
The original Zeek bytes must be supplied again; the legacy SOC evidence table
intentionally stores only a bounded, stringified analyst-readable snapshot.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from siem_ai.case_report import export_case_report
from siem_ai.core import flow_id

from .zeek import parse_zeek_conn_log


def export_verified_offline_case(
    db_path: str | Path, *, case_id: int, source_data: bytes, record_index: int
) -> bytes:
    """Export case history plus typed Zeek fields verified against original bytes.

    Reject a mismatched source digest, selected record, or altered SOC snapshot.
    The original log remains necessary: this function does not claim the mutable
    SQLite store or source file is tamper-proof, and never assigns an attack label.
    """
    if isinstance(case_id, bool) or not isinstance(case_id, int) or case_id <= 0:
        raise ValueError("Case ID must be a positive integer")
    if isinstance(record_index, bool) or not isinstance(record_index, int) or record_index < 0:
        raise ValueError("Record index must be a non-negative integer")

    events = parse_zeek_conn_log(source_data)
    if record_index >= len(events):
        raise ValueError("Record index out of range")
    event = events[record_index]
    report = json.loads(export_case_report(db_path, case_id))
    snapshot = report["flow_evidence"]

    # The existing SOC store caps all values at 256 characters and stringifies
    # None. Compare against that exact contract; preserve typed values separately.
    expected_snapshot = {str(k): str(v)[:256] for k, v in event.items()}
    digest = hashlib.sha256(source_data).hexdigest()
    if (
        snapshot.get("origin") != "offline_zeek_log"
        or not isinstance(snapshot.get("source_sha256"), str)
        or not hmac.compare_digest(snapshot["source_sha256"], digest)
        or snapshot != expected_snapshot
        or report["case"]["flow_id"] != flow_id(event)
    ):
        raise ValueError("Case evidence does not match the selected original Zeek record")

    report["schema_version"] = 2
    report["typed_zeek_event"] = event
    report["typed_event_source"] = {
        "record_index_zero_based": record_index,
        "source_sha256": digest,
        "verification": "Matches the supplied original bytes and stored case snapshot",
        "integrity_limit": (
            "This verifies internal consistency only. Original log and SQLite "
            "are editable and are not cryptographically signed."
        ),
    }
    return (json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
