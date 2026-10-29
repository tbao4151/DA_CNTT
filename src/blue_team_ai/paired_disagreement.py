"""Aggregate paired held-out Zeek correctness without exposing flow identities.

Descriptive comparison only: not label authentication, statistical inference,
causal attribution, live detection, or an operational alert.
"""
from __future__ import annotations

from collections.abc import Sequence

_CELLS = ("both_correct", "full_only_correct", "without_ports_only_correct", "neither_correct")


def summarize_paired_zeek_test(
    labels: Sequence[int], full_predictions: Sequence[bool],
    without_ports_predictions: Sequence[bool],
) -> dict[str, object]:
    """Count correctness on the same operator-labeled held-out TEST rows.

    The caller must preserve the original row order for both predictions.
    This output contains only aggregate counts, never individual flow data.
    """
    if (
        not isinstance(labels, (list, tuple))
        or not isinstance(full_predictions, (list, tuple))
        or not isinstance(without_ports_predictions, (list, tuple))
        or not labels
        or len(labels) != len(full_predictions)
        or len(labels) != len(without_ports_predictions)
    ):
        raise ValueError("Paired TEST rows must be nonempty and aligned")
    if any(type(label) is not int or label not in (0, 1) for label in labels):
        raise ValueError("Expected operator-supplied binary TEST labels")
    if any(
        type(value) is not bool
        for predictions in (full_predictions, without_ports_predictions)
        for value in predictions
    ):
        raise ValueError("Expected boolean paired TEST predictions")

    overall = {key: 0 for key in _CELLS}
    by_label = {
        "normal": {key: 0 for key in _CELLS},
        "attack": {key: 0 for key in _CELLS},
    }
    for label, full, without_ports in zip(
        labels, full_predictions, without_ports_predictions, strict=True
    ):
        full_correct = int(full) == label
        without_ports_correct = int(without_ports) == label
        cell = (
            "both_correct" if full_correct and without_ports_correct else
            "full_only_correct" if full_correct else
            "without_ports_only_correct" if without_ports_correct else
            "neither_correct"
        )
        overall[cell] += 1
        by_label["attack" if label else "normal"][cell] += 1

    return {
        "support": len(labels),
        "overall": overall,
        "by_operator_supplied_label": by_label,
        "discordant_correctness_count": (
            overall["full_only_correct"] + overall["without_ports_only_correct"]
        ),
        "statistical_significance_test_performed": False,
        "independent_ground_truth_verified": False,
        "interpretation": (
            "Descriptive paired correctness on identical held-out TEST rows "
            "using operator-supplied labels. Flows within hosts/sessions can "
            "be dependent; no statistical significance or causal port effect "
            "is established."
        ),
    }
