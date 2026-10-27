"""Descriptive 95% Wilson intervals for offline Zeek flow-level detection rates.

Intervals treat flows as independent Bernoulli trials. Repeated flows from the
same host/session are correlated, so these are NOT host-cluster-adjusted
confidence intervals and must not be used to claim deployment reliability.
No labels, IPs, UIDs, or test observations are used for model selection.
"""
from __future__ import annotations

import math
from collections.abc import Mapping

_Z_95 = 1.959963984540054
_COUNT_FIELDS = ("tp", "fp", "tn", "fn")


def wilson_interval(successes: int, trials: int) -> dict[str, object]:
    """Return a bounded two-sided 95% Wilson interval, or nulls if n=0."""
    if (
        type(successes) is not int or type(trials) is not int
        or trials < 0 or successes < 0 or successes > trials
    ):
        raise ValueError("Expected nonnegative integer binomial counts")
    if trials == 0:
        return {
            "successes": 0, "trials": 0,
            "estimate": None, "lower": None, "upper": None,
            "method": "wilson_score_95_percent",
        }
    p = successes / trials
    z2 = _Z_95 * _Z_95
    denominator = 1.0 + z2 / trials
    center = (p + z2 / (2.0 * trials)) / denominator
    radius = (_Z_95 / denominator) * math.sqrt(
        p * (1.0 - p) / trials + z2 / (4.0 * trials * trials)
    )
    return {
        "successes": successes, "trials": trials,
        "estimate": p,
        "lower": max(0.0, center - radius),
        "upper": min(1.0, center + radius),
        "method": "wilson_score_95_percent",
    }


def summarize_detection_uncertainty(metrics: Mapping[str, object]) -> dict[str, object]:
    """Derive intervals from a fixed confusion matrix without model fitting."""
    if not isinstance(metrics, Mapping) or any(
        key not in metrics or type(metrics[key]) is not int or metrics[key] < 0
        for key in _COUNT_FIELDS
    ):
        raise ValueError("Expected nonnegative integer confusion counts")
    tp, fp, tn, fn = (metrics[key] for key in _COUNT_FIELDS)
    if (
        "support" not in metrics or type(metrics["support"]) is not int
        or metrics["support"] != tp + fp + tn + fn
        or metrics["support"] == 0
    ):
        raise ValueError("Confusion counts must match nonempty support")
    positive = tp + fn
    negative = fp + tn
    predicted_positive = tp + fp
    return {
        "attack_precision": wilson_interval(tp, predicted_positive),
        "attack_recall": wilson_interval(tp, positive),
        "false_positive_rate": wilson_interval(fp, negative),
        "small_denominator_warning": min(positive, negative, predicted_positive) < 30,
        "unit_of_analysis": "network_flow",
        "interpretation": "descriptive_only_flows_may_be_correlated_no_host_cluster_adjustment",
    }
