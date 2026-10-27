"""Descriptive probability diagnostics for OFFLINE Zeek research only.

Brier score and fixed-width reliability bins measure probabilistic error.
They do NOT calibrate probabilities, select a threshold, certify ground truth,
or authorize deployment. Use on validation and on held-out test only once.
"""
from __future__ import annotations

import math
from collections.abc import Sequence

PROBABILITY_BINS = 5


def summarize_probability_quality(
    labels: Sequence[int], probabilities: Sequence[float], *, bins: int = PROBABILITY_BINS,
) -> dict[str, object]:
    """Return JSON-safe Brier/ECE diagnostics with empty-bin nulls.

    Equal-width bins are fixed in advance. ECE is descriptive and sensitive to
    binning/sample size; it is not a calibrated-probability guarantee.
    """
    if type(bins) is not int or not 2 <= bins <= 20:
        raise ValueError("Invalid fixed probability bin count")
    try:
        truth = list(labels)
        scores = list(probabilities)
    except TypeError as exc:
        raise ValueError("Expected one-dimensional probability sequences") from exc
    if not truth or len(truth) != len(scores):
        raise ValueError("Probability/label lengths must match and be nonempty")
    if any(type(label) is not int or label not in (0, 1) for label in truth):
        raise ValueError("Expected exact binary integer labels")
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0.0 <= value <= 1.0
        for value in scores
    ):
        raise ValueError("Expected finite probabilities within [0, 1]")

    n = len(truth)
    counts = [0] * bins
    sums = [0.0] * bins
    positives = [0] * bins
    squared_error = 0.0
    for label, probability in zip(truth, scores):
        index = min(int(probability * bins), bins - 1)
        counts[index] += 1
        sums[index] += probability
        positives[index] += label
        squared_error += (probability - label) ** 2

    reliability = []
    ece = 0.0
    for index, count in enumerate(counts):
        if count:
            mean_score = sums[index] / count
            observed = positives[index] / count
            gap = abs(mean_score - observed)
            ece += count / n * gap
        else:
            mean_score = observed = gap = None
        reliability.append({
            "lower": index / bins,
            "upper": (index + 1) / bins,
            "upper_inclusive": index == bins - 1,
            "count": count,
            "mean_predicted_probability": mean_score,
            "observed_attack_rate": observed,
            "absolute_gap": gap,
        })

    occupied = [count for count in counts if count]
    return {
        "sample_size": n,
        "attack_prevalence": sum(truth) / n,
        "brier_score": squared_error / n,
        "expected_calibration_error": ece,
        "reliability_bins": reliability,
        "small_sample_warning": n < 100 or min(occupied) < 20,
        "interpretation": "descriptive_only_uncalibrated_probabilities",
    }
