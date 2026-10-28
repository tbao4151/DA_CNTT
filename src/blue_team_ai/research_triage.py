"""Explicit, source-verified analyst triage of OFFLINE research candidates.

A candidate is only a held-out experiment prediction, not an operational
AI alert or an authenticated attack. No network access or model loading.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from .trace_review import review_private_zeek_trace
from .triage import create_offline_review_case
from .zeek import parse_zeek_conn_log


def create_research_candidate_case(
    db_path: str | Path, *, source_data: bytes, trace_data: bytes,
    record_index: int, analyst_confirmed: bool,
) -> int:
    """Create ONE Unclassified case only after explicit analyst confirmation.

    Revalidates the original source and complete private trace at click time.
    The stored audit note identifies a *research-only* score and trace hash;
    it never stores supplied ground-truth labels or calls a live detector.
    """
    if analyst_confirmed is not True:
        raise ValueError("Explicit analyst confirmation is required")
    if type(record_index) is not int or record_index < 0 or record_index >= 500:
        raise ValueError("Select a valid visible Zeek record index (0..499)")
    review = review_private_zeek_trace(source_data, trace_data)
    if record_index >= review["flow_count"]:
        raise ValueError("Selected Zeek record index is out of range")
    candidate = review["rows"][record_index]
    if candidate["record_index"] != record_index or candidate["predicted_attack"] is not True:
        raise ValueError("Only validated research Attack candidates can be selected")
    events = parse_zeek_conn_log(source_data)
    if candidate["uid"] != events[record_index]["uid"]:
        raise ValueError("Selected Zeek UID does not match original source")

    note = (
        "Analyst-selected OFFLINE research candidate; NOT a live AI alert "
        "or verified attack. "
        f"source_sha256={review['source_sha256']}; "
        f"trace_sha256={hashlib.sha256(trace_data).hexdigest()}; "
        f"zeek_uid={candidate['uid']}; "
        f"research_attack_probability={candidate['attack_probability']:.8f}; "
        f"validation_threshold={review['selected_threshold']:.8f}. "
        "Operator-supplied ground truth is not authenticated or stored."
    )
    return create_offline_review_case(
        db_path, source_data=source_data, record_index=record_index,
        research_note=note,
    )
