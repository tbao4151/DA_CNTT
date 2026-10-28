"""Private, offline Zeek disagreement worksheet; never infer attack ground truth.

The existing aggregate agreement report remains UID-free. This separate,
explicitly requested worksheet includes sensitive Zeek UIDs and MUST remain
outside the repository. It never modifies reviewer annotations.
"""
from __future__ import annotations

from .annotation_agreement import MAX_ANNOTATION_BYTES, _annotations, _digest
from .zeek import MAX_LOG_BYTES, parse_zeek_conn_log

MAX_WORKSHEET_BYTES = 4 * 1024 * 1024


def build_private_disagreement_template(
    source_data: bytes,
    annotation_a_data: bytes,
    annotation_b_data: bytes,
    *,
    expected_log_sha256: str,
    expected_a_sha256: str,
    expected_b_sha256: str,
) -> dict[str, object]:
    """Produce a null-only adjudication worksheet for disagreements.

    A/B labels are shown for review, but adjudicated_label and
    evidence_reference are always null. No consensus is produced.
    """
    source_sha = _digest(source_data, expected_log_sha256, "Zeek log", MAX_LOG_BYTES)
    a_sha = _digest(annotation_a_data, expected_a_sha256, "annotation A", MAX_ANNOTATION_BYTES)
    b_sha = _digest(annotation_b_data, expected_b_sha256, "annotation B", MAX_ANNOTATION_BYTES)
    events = parse_zeek_conn_log(source_data)
    uids = [event["uid"] for event in events]
    if len(uids) != len(set(uids)):
        raise ValueError("Duplicate Zeek UID in original source")
    expected = set(uids)
    a = _annotations(annotation_a_data, source_sha, expected)
    b = _annotations(annotation_b_data, source_sha, expected)

    disagreements = {
        uid: {
            "reviewer_a_label": a[uid],
            "reviewer_b_label": b[uid],
            "adjudicated_label": None,
            "evidence_reference": None,
        }
        for uid in uids if a[uid] != b[uid]
    }
    return {
        "report_version": 1,
        "mode": "private_disagreement_review_template_only",
        "source_sha256": source_sha,
        "annotation_a_sha256": a_sha,
        "annotation_b_sha256": b_sha,
        "disagreement_count": len(disagreements),
        "disagreements_by_uid": disagreements,
        "ground_truth_verified": False,
        "annotator_independence_verified": False,
        "consensus_labels_generated": False,
        "interpretation": (
            "Private UID-level disagreement worksheet only. Null adjudication "
            "fields require independent scenario evidence and manual review. "
            "Do not use this worksheet as a training annotation."
        ),
    }
