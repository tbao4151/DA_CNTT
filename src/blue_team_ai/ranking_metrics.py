"""Threshold-free, tie-aware ranking diagnostics for pinned offline Zeek scores.

Only descriptive agreement with supplied labels. This does not tune thresholds,
authenticate ground truth, establish host-level independence or detect live traffic.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from itertools import groupby


def summarize_binary_ranking(
    scores: Sequence[float], labels: Sequence[int],
) -> dict[str, object]:
    """Compute ROC AUC and average precision with deterministic score-tie groups.

    ROC AUC counts positive/negative concordant pairs, with half credit for
    equal scores. Average precision uses precision AFTER each whole tied-score
    group, weighted by the group's increase in recall (not trapezoidal PR AUC).
    Undefined rates are None rather than fabricated zero.
    """
    if (
        isinstance(scores, (str, bytes))
        or isinstance(labels, (str, bytes))
        or not isinstance(scores, Sequence)
        or not isinstance(labels, Sequence)
        or not scores
        or len(scores) != len(labels)
    ):
        raise ValueError("Nonempty equal-length score and binary label sequences required")
    pairs: list[tuple[float, int]] = []
    for score, label in zip(scores, labels, strict=True):
        if (
            type(score) not in (int, float)
            or not math.isfinite(score)
            or not 0 <= score <= 1
            or type(label) is not int
            or label not in (0, 1)
        ):
            raise ValueError("Expected finite probabilities in [0,1] and integer 0/1 labels")
        pairs.append((float(score), label))

    positive = sum(label for _, label in pairs)
    negative = len(pairs) - positive
    seen_positive = seen_negative = 0
    twice_concordant_pairs = 0
    weighted_precision = 0.0
    tied_groups = 0
    for _, iterator in groupby(
        sorted(pairs, key=lambda item: item[0], reverse=True),
        key=lambda item: item[0],
    ):
        group = list(iterator)
        group_positive = sum(label for _, label in group)
        group_negative = len(group) - group_positive
        tied_groups += len(group) > 1
        # Positive scores above negatives below win; equal-score pairs tie.
        twice_concordant_pairs += (
            2 * group_positive * (negative - seen_negative - group_negative)
            + group_positive * group_negative
        )
        seen_positive += group_positive
        seen_negative += group_negative
        if positive:
            weighted_precision += (
                group_positive * seen_positive / (seen_positive + seen_negative)
            )

    return {
        "roc_auc": (
            twice_concordant_pairs / (2 * positive * negative)
            if positive and negative else None
        ),
        "average_precision": weighted_precision / positive if positive else None,
        "positive_prevalence": positive / len(pairs),
        "positive_support": positive,
        "negative_support": negative,
        "tied_score_groups": tied_groups,
        "unit_of_analysis": "network_flow",
        "roc_auc_tie_rule": "half_credit_for_equal_positive_negative_scores",
        "average_precision_tie_rule": "precision_after_entire_equal_score_group",
        "threshold_selection_performed": False,
    }
