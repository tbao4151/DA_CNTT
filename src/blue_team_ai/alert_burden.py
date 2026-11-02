"""Descriptive manual-review burden for a fixed offline Zeek confusion matrix.

Counts refer to research candidates, not operational alerts or SOC cases.
Operator-provided labels are not authenticated. No model/threshold selection.
"""
from __future__ import annotations

from collections.abc import Mapping


def summarize_research_candidate_burden(confusion: Mapping[str, object]) -> dict[str, object]:
    """Report denominators explicitly; undefined rates are JSON-safe None."""
    if not isinstance(confusion, Mapping) or any(
        key not in confusion or type(confusion[key]) is not int or confusion[key] < 0
        for key in ("tp", "fp", "tn", "fn", "support")
    ):
        raise ValueError("Expected nonnegative integer confusion counts and support")
    tp, fp, tn, fn, support = (confusion[k] for k in ("tp", "fp", "tn", "fn", "support"))
    if support == 0 or support != tp + fp + tn + fn:
        raise ValueError("Nonempty support must equal the confusion counts")

    attacks = tp + fn
    normals = tn + fp
    candidates = tp + fp
    return {
        "unit_of_analysis": "network_flow",
        "observed_flows": support,
        "operator_labeled_attack_flows": attacks,
        "operator_labeled_normal_flows": normals,
        "research_candidate_flows": candidates,
        "false_candidate_flows": fp,
        "missed_operator_labeled_attack_flows": fn,
        "operator_labeled_attack_prevalence": attacks / support,
        "research_candidate_fraction": candidates / support,
        "research_candidates_per_1000_observed_flows": 1000.0 * candidates / support,
        "false_candidates_per_1000_observed_flows": 1000.0 * fp / support,
        "false_candidates_per_1000_operator_labeled_normal_flows": (
            1000.0 * fp / normals if normals else None
        ),
        "missed_attacks_per_1000_operator_labeled_attack_flows": (
            1000.0 * fn / attacks if attacks else None
        ),
        "false_discovery_fraction_among_candidates": (
            fp / candidates if candidates else None
        ),
        "small_class_support_warning": min(attacks, normals) < 30,
        "independent_ground_truth_verified": False,
        "operational_alerts_created": False,
        "soc_cases_created": False,
        "interpretation": (
            "Descriptive candidate review workload only; all rates use operator-supplied "
            "labels and flow denominators. Not actual analyst time, authenticated "
            "attack truth, independent host/session inference or live alert volume."
        ),
    }
