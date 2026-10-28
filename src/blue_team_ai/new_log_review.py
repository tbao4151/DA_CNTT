"""Recompute and verify a PRIVATE new-log Zeek research prediction report.

The caller must supply the original capture and a separately SHA-256-pinned
research model. This is read-only software consistency checking, not evidence
of genuine Host-only capture, ground truth, model authorship or detection.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

from .new_log_inference import score_new_zeek_log

MAX_NEW_LOG_REPORT_BYTES = 16 * 1024 * 1024


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key in private research report")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite numeric value in private research report")


def _canonical(value: object) -> str:
    # Unlike Python dict equality, JSON serialization distinguishes bool/int.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def review_pinned_new_log_report(
    source_data: bytes,
    model: Mapping[str, object],
    report_data: bytes,
    *,
    expected_log_sha256: str,
    lab_cidrs: Sequence[str],
    model_sha256: str,
) -> dict[str, object]:
    """Verify EVERY report field and prediction by re-scoring pinned inputs.

    Recomputing is essential: checking only the report's claimed source/model
    hashes cannot detect modified probabilities, endpoints or candidate flags.
    Never trust a report as evidence of operational detection.
    """
    if not isinstance(report_data, bytes) or not 0 < len(report_data) <= MAX_NEW_LOG_REPORT_BYTES:
        raise ValueError("Private research report is empty or exceeds size limit")
    try:
        report = json.loads(
            report_data.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise ValueError("Malformed private new-log research JSON") from exc
    if not isinstance(report, dict):
        raise ValueError("Expected a JSON object for private research report")

    expected = score_new_zeek_log(
        source_data,
        model,
        expected_log_sha256=expected_log_sha256,
        lab_cidrs=lab_cidrs,
        model_sha256=model_sha256,
    )
    try:
        consistent = _canonical(report) == _canonical(expected)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("Invalid private research report structure") from exc
    if not consistent:
        raise ValueError("Private research report differs from recomputed pinned inference")

    return {
        "review_version": 1,
        "mode": "offline_new_zeek_research_report_consistency_only",
        "source_sha256": expected_log_sha256,
        "model_sha256": model_sha256,
        "report_sha256": hashlib.sha256(report_data).hexdigest(),
        "flow_count": expected["flow_count"],
        "research_candidate_count": expected["research_candidate_count"],
        "report_matches_recomputed_predictions": True,
        "test_partition_exclusion_verified": False,
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "model_authorship_verified": False,
        "operational_attack_detection_verified": False,
        "automated_alerts": False,
        "soc_cases_created": False,
        "live_capture": False,
    }
