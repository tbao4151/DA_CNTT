"""Descriptive class-imbalance diagnostics for a fixed offline Zeek confusion matrix.

All labels are operator supplied. These flow-level rates do not establish
host/session independence, authentic attack truth, or operational detection.
No threshold or model selection is performed.
"""
from __future__ import annotations

import math
from collections.abc import Mapping


def summarize_class_balance(confusion: Mapping[str, object]) -> dict[str, object]:
    """Return JSON-safe balanced accuracy and MCC with explicit denominators."""
    fields = ("tp", "fp", "tn", "fn", "support")
    if not isinstance(confusion, Mapping) or any(
        key not in confusion or type(confusion[key]) is not int or confusion[key] < 0
        for key in fields
    ):
        raise ValueError("Expected nonnegative integer confusion counts and support")
    tp, fp, tn, fn, support = (confusion[key] for key in fields)
    if support == 0 or support != tp + fp + tn + fn:
        raise ValueError("Confusion counts must match nonempty support")

    attacks, normals = tp + fn, tn + fp
    predicted_attacks, predicted_normals = tp + fp, tn + fn
    attack_recall = tp / attacks if attacks else None
    normal_recall = tn / normals if normals else None
    balanced_accuracy = (
        (attack_recall + normal_recall) / 2
        if attack_recall is not None and normal_recall is not None else None
    )
    mcc_denominator_squared = predicted_attacks * attacks * normals * predicted_normals
    mcc = (
        (tp * tn - fp * fn) / math.sqrt(mcc_denominator_squared)
        if mcc_denominator_squared else None
    )
    return {
        "attack_recall": attack_recall,
        "normal_recall_specificity": normal_recall,
        "balanced_accuracy": balanced_accuracy,
        "matthews_correlation_coefficient": mcc,
        "operator_labeled_attack_support": attacks,
        "operator_labeled_normal_support": normals,
        "predicted_attack_support": predicted_attacks,
        "predicted_normal_support": predicted_normals,
        "small_class_support_warning": min(attacks, normals) < 30,
        "unit_of_analysis": "network_flow",
        "independent_ground_truth_verified": False,
        "interpretation": (
            "Descriptive flow-level class-balance diagnostics from operator-supplied "
            "labels only. No verified attack truth, independent host/session "
            "generalization, model selection, or live detection."
        ),
    }
