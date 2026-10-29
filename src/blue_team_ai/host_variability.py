"""Descriptive host-group variability for independently labeled offline Zeek flows.

This does not estimate cluster-adjusted confidence intervals. Groups are
operator-declared, not authenticated, and may represent correlated sessions.
Never use held-out test summaries to tune a model or threshold.
"""
from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Mapping, Sequence


def summarize_host_variability(
    labels: Sequence[int],
    probabilities: Sequence[float],
    host_groups: Sequence[str],
    threshold: float,
    *,
    suppress_small_groups: bool = False,
) -> dict[str, object]:
    """Summarize fixed-threshold confusion counts and rates per host group.

    Group identifiers are omitted from the JSON result. Anonymous group numbers
    are deterministic within a report but are not cross-report identities.
    Undefined rate denominators are represented as None, never fabricated zero.
    """
    try:
        truth, scores, groups = list(labels), list(probabilities), list(host_groups)
    except TypeError as exc:
        raise ValueError("Expected aligned offline sequences") from exc
    if type(suppress_small_groups) is not bool:
        raise ValueError("Small-group suppression flag must be boolean")
    if not truth or len(truth) != len(scores) or len(truth) != len(groups):
        raise ValueError("Host variability inputs must align and be nonempty")
    if any(type(y) is not int or y not in (0, 1) for y in truth):
        raise ValueError("Expected exact binary labels")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(threshold) or not 0 < threshold < 1:
        raise ValueError("Expected finite fixed threshold within (0,1)")
    if any(isinstance(p, bool) or not isinstance(p, (int, float)) or not math.isfinite(p) or not 0 <= p <= 1 for p in scores):
        raise ValueError("Expected finite Attack probabilities within [0,1]")
    if any(not isinstance(group, str) or not 1 <= len(group) <= 256 or group.strip() != group or any(ord(ch) < 33 or ord(ch) == 127 for ch in group) for group in groups):
        raise ValueError("Expected nonempty host group identifiers")

    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    for label, probability, group in zip(truth, scores, groups):
        predicted = probability >= threshold
        key = "tp" if label == 1 and predicted else (
            "fn" if label == 1 else ("fp" if predicted else "tn")
        )
        counts[group][key] += 1

    summaries: list[dict[str, object]] = []
    for index, group in enumerate(sorted(counts), start=1):
        row = counts[group]
        tp, fp, tn, fn = row["tp"], row["fp"], row["tn"], row["fn"]
        support = tp + fp + tn + fn
        summaries.append({
            "anonymous_group_number": index,
            "support": support,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "attack_precision": tp / (tp + fp) if tp + fp else None,
            "attack_recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "small_group_warning": support < 30,
        })

    ranges: dict[str, dict[str, float | None]] = {}
    for metric in ("attack_precision", "attack_recall", "false_positive_rate"):
        observed = [row[metric] for row in summaries if row[metric] is not None]
        ranges[metric] = {
            "min": min(observed) if observed else None,
            "max": max(observed) if observed else None,
            "macro_mean": sum(observed) / len(observed) if observed else None,
            "defined_groups": len(observed),
        }
    result: dict[str, object] = {
        "unit_of_grouping": "operator_declared_host_group",
        "group_count": len(summaries),
        "groups": summaries,
        "rate_ranges": ranges,
        "single_group_warning": len(summaries) < 2,
        "small_group_warning": any(row["small_group_warning"] for row in summaries),
        "interpretation": "descriptive_only_not_cluster_adjusted_not_ground_truth_verified",
    }
    if suppress_small_groups:
        # Suppress *every* group if even one has <30 flows: otherwise a small
        # group's counts could be recovered by subtracting visible groups
        # from aggregate confusion counts in the same ablation report.
        # Rate ranges/macro means must also be removed; they can disclose
        # a small group's performance even when its row is hidden.
        suppressed = any(row["small_group_warning"] for row in summaries)
        result["minimum_support_per_group"] = 30
        result["all_group_counts_suppressed"] = suppressed
        if suppressed:
            result["groups"] = []
            result["rate_ranges"] = None
            result["interpretation"] = (
                "descriptive_only_small_groups_suppressed_no_ground_truth_verification"
            )
    return result
