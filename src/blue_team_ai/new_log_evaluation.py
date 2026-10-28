"""Descriptive, operator-labeled evaluation of pinned NEW Zeek research predictions.

Offline only. The supplied binary labels are not authenticated ground truth.
No fitting, threshold selection, live traffic, alert or SOC database write.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

from .new_log_inference import score_new_zeek_log
from .new_log_review import review_pinned_new_log_report
from .uncertainty import summarize_detection_uncertainty

MAX_NEW_ANNOTATION_BYTES = 2 * 1024 * 1024
_HEX = frozenset("0123456789abcdef")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate annotation JSON key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("Invalid annotation numeric constant")


def evaluate_new_log_operator_labels(
    source_data: bytes,
    model: Mapping[str, object],
    report_data: bytes,
    annotation_data: bytes,
    *,
    expected_log_sha256: str,
    expected_annotation_sha256: str,
    model_sha256: str,
    lab_cidrs: Sequence[str],
) -> dict[str, object]:
    """Evaluate fixed, recomputed predictions against exact external UID labels.

    Never use this output to tune the model or validation-selected threshold.
    Independently verify partition exclusion and label authenticity elsewhere.
    """
    if (
        not isinstance(annotation_data, bytes)
        or not 0 < len(annotation_data) <= MAX_NEW_ANNOTATION_BYTES
        or not isinstance(expected_annotation_sha256, str)
        or len(expected_annotation_sha256) != 64
        or any(char not in _HEX for char in expected_annotation_sha256)
        or hashlib.sha256(annotation_data).hexdigest() != expected_annotation_sha256
    ):
        raise ValueError("Annotation does not match an independently pinned SHA-256")
    try:
        annotation = json.loads(
            annotation_data.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Malformed private annotation JSON") from exc
    if (
        not isinstance(annotation, dict)
        or set(annotation) != {"source_sha256", "labels_by_uid"}
        or annotation["source_sha256"] != expected_log_sha256
        or not isinstance(annotation["labels_by_uid"], dict)
    ):
        raise ValueError("Annotation source or schema does not match pinned log")

    # Reject tampered report before computing any metrics.
    verified = review_pinned_new_log_report(
        source_data, model, report_data,
        expected_log_sha256=expected_log_sha256,
        lab_cidrs=lab_cidrs, model_sha256=model_sha256,
    )
    predictions = score_new_zeek_log(
        source_data, model,
        expected_log_sha256=expected_log_sha256,
        lab_cidrs=lab_cidrs, model_sha256=model_sha256,
    )["predictions"]
    labels = annotation["labels_by_uid"]
    uids = [row["uid"] for row in predictions]
    if (
        len(uids) != len(set(uids))
        or set(labels) != set(uids)
        or any(type(label) is not int or label not in (0, 1) for label in labels.values())
    ):
        raise ValueError("Every observed UID requires one external binary 0/1 label")
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for row in predictions:
        truth = labels[row["uid"]]
        predicted = row["research_candidate"]
        if type(predicted) is not bool:
            raise ValueError("Expected verified boolean research prediction")
        counts["tp" if truth == 1 else "fp"] += 1 if predicted else 0
        counts["fn" if truth == 1 else "tn"] += 1 if not predicted else 0

    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    support = tp + fp + tn + fn
    if support != len(predictions) or support == 0:
        raise ValueError("Confusion counts do not cover the new capture")
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    confusion = {**counts, "support": support}
    return {
        "report_version": 1,
        "mode": "offline_new_zeek_operator_labeled_descriptive_evaluation_only",
        "source_sha256": expected_log_sha256,
        "model_sha256": model_sha256,
        "prediction_report_sha256": verified["report_sha256"],
        "annotation_sha256": expected_annotation_sha256,
        "selected_validation_threshold": model["selected_threshold"],
        "confusion_matrix": confusion,
        "metrics": {
            "attack_precision": precision,
            "attack_recall": recall,
            "false_positive_rate": fpr,
            "attack_f1": f1,
        },
        "flow_level_uncertainty": summarize_detection_uncertainty(confusion),
        "label_authenticity_verified": False,
        "independent_partition_history_verified": False,
        "physical_host_only_isolation_verified": False,
        "operational_attack_detection_verified": False,
        "automated_alerts": False,
        "soc_cases_created": False,
        "live_capture": False,
        "detection_latency_measured": False,
        "interpretation": (
            "Descriptive agreement with operator-supplied labels on a fixed "
            "offline NEW capture. No label authentication, independent capture "
            "history, host-cluster-adjusted intervals or deployment validity. "
            "Do not select thresholds/models from these evaluation results."
        ),
    }
