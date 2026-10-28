"""Read-only, SHA-pinned verification of a private manual Zeek label chain.

Reconstructs the finalized annotation from original log, two reviewer files,
and the completed adjudication worksheet. Does not authenticate ground truth,
run inference, contact a network, or modify any evidence.
"""
from __future__ import annotations

import json

from .adjudicated_labels import finalize_private_adjudication
from .annotation_agreement import (
    MAX_ANNOTATION_BYTES, _annotations, _bad_constant, _digest, _unique_keys,
)
from .disagreement_review import MAX_WORKSHEET_BYTES


def verify_finalized_annotation_chain(
    source_data: bytes,
    annotation_a_data: bytes,
    annotation_b_data: bytes,
    worksheet_data: bytes,
    final_data: bytes,
    *,
    expected_log_sha256: str,
    expected_a_sha256: str,
    expected_b_sha256: str,
    expected_worksheet_sha256: str,
    expected_final_sha256: str,
) -> dict[str, object]:
    """Recompute every final UID label and compare to independently pinned output.

    No output UID, IP, path, or reviewer label is disclosed. Hashes establish
    byte consistency only, not authenticity or physical lab isolation.
    """
    final_sha = _digest(
        final_data, expected_final_sha256, "final annotation", MAX_ANNOTATION_BYTES
    )
    recomputed = finalize_private_adjudication(
        source_data, annotation_a_data, annotation_b_data, worksheet_data,
        expected_log_sha256=expected_log_sha256,
        expected_a_sha256=expected_a_sha256,
        expected_b_sha256=expected_b_sha256,
        expected_worksheet_sha256=expected_worksheet_sha256,
    )
    try:
        final = json.loads(
            final_data.decode("utf-8"),
            object_pairs_hook=_unique_keys,
            parse_constant=_bad_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid finalized annotation JSON") from exc
    if not isinstance(final, dict) or set(final) != {"source_sha256", "labels_by_uid"}:
        raise ValueError("Invalid finalized annotation-v1 contract")
    _annotations(final_data, recomputed["source_sha256"], set(recomputed["labels_by_uid"]))
    if final != recomputed:
        raise ValueError("Final annotation differs from the pinned manual adjudication chain")
    labels = recomputed["labels_by_uid"]
    return {
        "report_version": 1,
        "mode": "offline_finalized_annotation_chain_verification",
        "source_sha256": recomputed["source_sha256"],
        "annotation_a_sha256": expected_a_sha256,
        "annotation_b_sha256": expected_b_sha256,
        "worksheet_sha256": expected_worksheet_sha256,
        "final_annotation_sha256": final_sha,
        "flow_count": len(labels),
        "normal_count": sum(label == 0 for label in labels.values()),
        "attack_count": sum(label == 1 for label in labels.values()),
        "chain_consistency_verified": True,
        "ground_truth_verified": False,
        "annotator_independence_verified": False,
        "host_only_isolation_verified": False,
        "interpretation": (
            "Pinned byte integrity and agreement with the operator-supplied manual "
            "worksheet only. No attack truth, independent review or lab isolation proof."
        ),
    }
