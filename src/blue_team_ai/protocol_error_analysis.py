"""Privacy-preserving protocol-stratified error audit for pinned offline Zeek.

Descriptive agreement with operator labels, never operational detection.
Only four fixed protocol buckets are exported; no UID, IP, port or free-text
protocol values leave this function.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from .uncertainty import wilson_interval

PROTOCOL_BUCKETS = ("tcp", "udp", "icmp", "other")
MIN_INTERPRETABLE_BUCKET_SUPPORT = 30


def summarize_protocol_error_rates(
    events: Sequence[Mapping[str, object]],
    predictions: Sequence[Mapping[str, object]],
    labels_by_uid: Mapping[str, int],
) -> dict[str, object]:
    """Count TP/FP/TN/FN per fixed protocol bucket without fitting or tuning.

    Original parsed events and recomputed predictions must align by UID and
    order. Undefined denominators stay null; small buckets are explicitly
    marked as descriptive rather than statistically reliable.
    """
    if (
        isinstance(events, (str, bytes))
        or isinstance(predictions, (str, bytes))
        or not isinstance(events, Sequence)
        or not isinstance(predictions, Sequence)
        or not isinstance(labels_by_uid, Mapping)
        or not events
        or len(events) != len(predictions)
    ):
        raise ValueError("Nonempty aligned Zeek events and predictions required")

    counts = {
        bucket: {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        for bucket in PROTOCOL_BUCKETS
    }
    seen_uids: set[str] = set()
    for event, prediction in zip(events, predictions, strict=True):
        if not isinstance(event, Mapping) or not isinstance(prediction, Mapping):
            raise ValueError("Expected Zeek event and prediction mappings")
        uid = event.get("uid")
        protocol = event.get("proto")
        predicted = prediction.get("research_candidate")
        if (
            type(uid) is not str or not uid or uid in seen_uids
            or prediction.get("uid") != uid
            or type(protocol) is not str or not protocol
            or type(predicted) is not bool
        ):
            raise ValueError("Invalid Zeek protocol audit alignment")
        seen_uids.add(uid)
        truth = labels_by_uid.get(uid)
        if type(truth) is not int or truth not in (0, 1):
            raise ValueError("Every Zeek UID requires an external binary label")
        bucket = protocol if protocol in PROTOCOL_BUCKETS[:-1] else "other"
        outcome = (
            "tp" if predicted and truth == 1 else
            "fp" if predicted else
            "fn" if truth == 1 else "tn"
        )
        counts[bucket][outcome] += 1

    if set(labels_by_uid) != seen_uids:
        raise ValueError("Zeek protocol audit labels must match observed UIDs")

    summaries: dict[str, dict[str, object]] = {}
    for bucket, row in counts.items():
        tp, fp, tn, fn = (row[key] for key in ("tp", "fp", "tn", "fn"))
        support = tp + fp + tn + fn
        summaries[bucket] = {
            "confusion_matrix": {**row, "support": support},
            "attack_precision": tp / (tp + fp) if tp + fp else None,
            "attack_recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "flow_level_wilson_intervals": {
                "attack_precision": wilson_interval(tp, tp + fp),
                "attack_recall": wilson_interval(tp, tp + fn),
                "false_positive_rate": wilson_interval(fp, fp + tn),
            },
            "small_denominator_warning": min(tp + fp, tp + fn, fp + tn) < MIN_INTERPRETABLE_BUCKET_SUPPORT,
            "insufficient_flow_support": support < MIN_INTERPRETABLE_BUCKET_SUPPORT,
        }
    return {
        "mode": "offline_operator_labeled_protocol_error_audit_only",
        "unit_of_analysis": "network_flow",
        "flow_count": len(events),
        "minimum_interpretable_bucket_support": MIN_INTERPRETABLE_BUCKET_SUPPORT,
        "buckets": summaries,
        "independent_ground_truth_verified": False,
        "host_session_cluster_adjusted": False,
        "threshold_selection_performed": False,
        "interpretation": (
            "Fixed protocol strata of a single offline capture, using supplied "
            "labels and the unchanged validation-selected threshold. Small or "
            "single-class buckets are descriptive only; no host/session-adjusted "
            "uncertainty, operational alerts, or physical isolation is established. "
            "Wilson intervals treat correlated flows as independent and are "
            "not host/session-cluster adjusted."
        ),
    }


def summarize_protocol_probability_quality(
    events: Sequence[Mapping[str, object]],
    predictions: Sequence[Mapping[str, object]],
    labels_by_uid: Mapping[str, int],
) -> dict[str, object]:
    """Describe probability error by fixed Zeek protocol, without recalibration.

    Uses only externally supplied labels and verified prediction probabilities.
    This is exploratory, flow-level Brier loss, not host/session-adjusted
    validation, a calibrated-probability claim, or model/threshold selection.
    """
    import math

    # Reuse strict UID/order, binary-label and fixed-protocol validation.
    # No private identifiers are included in either aggregate result.
    audit = summarize_protocol_error_rates(events, predictions, labels_by_uid)
    totals = {
        bucket: {"score_sum": 0.0, "squared_error_sum": 0.0}
        for bucket in PROTOCOL_BUCKETS
    }
    for event, prediction in zip(events, predictions, strict=True):
        probability = prediction.get("attack_probability")
        if (
            type(probability) not in (int, float)
            or not math.isfinite(probability)
            or not 0.0 <= probability <= 1.0
        ):
            raise ValueError("Expected finite Zeek attack probability in [0,1]")
        bucket = event["proto"] if event["proto"] in PROTOCOL_BUCKETS[:-1] else "other"
        truth = labels_by_uid[event["uid"]]
        totals[bucket]["score_sum"] += probability
        totals[bucket]["squared_error_sum"] += (probability - truth) ** 2

    summaries: dict[str, dict[str, object]] = {}
    total_squared_error = 0.0
    for bucket in PROTOCOL_BUCKETS:
        confusion = audit["buckets"][bucket]["confusion_matrix"]
        support = confusion["support"]
        attack_count = confusion["tp"] + confusion["fn"]
        score_sum = totals[bucket]["score_sum"]
        squared_error_sum = totals[bucket]["squared_error_sum"]
        total_squared_error += squared_error_sum
        summaries[bucket] = {
            "support": support,
            "operator_labeled_attack_prevalence": (
                attack_count / support if support else None
            ),
            "mean_predicted_attack_probability": (
                score_sum / support if support else None
            ),
            "brier_score": squared_error_sum / support if support else None,
            "insufficient_flow_support": support < MIN_INTERPRETABLE_BUCKET_SUPPORT,
        }
    return {
        "mode": "offline_operator_labeled_protocol_probability_diagnostics_only",
        "unit_of_analysis": "network_flow",
        "flow_count": len(events),
        "overall_brier_score": total_squared_error / len(events),
        "buckets": summaries,
        "independent_ground_truth_verified": False,
        "host_session_cluster_adjusted": False,
        "probabilities_calibrated_verified": False,
        "threshold_selection_performed": False,
        "interpretation": (
            "Brier loss and mean risk by four fixed protocol strata, using "
            "operator-supplied labels and existing offline model probabilities. "
            "Empty buckets are null; small or correlated host/session samples "
            "are descriptive only. No calibration, independent ground truth, "
            "physical isolation or live detection is established."
        ),
    }
