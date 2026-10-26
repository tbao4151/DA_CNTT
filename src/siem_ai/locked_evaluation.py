"""Compare preselected validation threshold to 0.50 on one untouched test set.

This module must not choose a threshold using any official-test labels or
scores. It only evaluates a candidate that was committed before test evaluation.
"""
from __future__ import annotations

import math

from .thresholds import threshold_diagnostics

VALIDATION_SOURCE = "UNSW-NB15 official training split only"
COUNT_COLUMNS = (
    "true_positive", "false_positive", "true_negative",
    "false_negative", "alerts",
)


def evaluate_locked_threshold(labels, probabilities, selection: dict) -> dict:
    """Evaluate baseline and previously selected candidate using the same scores."""
    if not isinstance(selection, dict) or selection.get("selection_source") != VALIDATION_SOURCE:
        raise ValueError("Threshold must originate from training-only validation")
    raw = selection.get("threshold")
    if isinstance(raw, bool) or not isinstance(raw, (float, int)):
        raise ValueError("Candidate threshold must be numeric")
    threshold = float(raw)
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("Candidate threshold must be finite and in [0, 1]")
    if not isinstance(selection.get("source_run_id"), int) or selection["source_run_id"] <= 0:
        raise ValueError("Expected traceable validation experiment run ID")
    # Shared score vector: no re-training and no threshold search on official test.
    rows = threshold_diagnostics(labels, probabilities, thresholds=[0.5, threshold])
    baseline, candidate = rows.to_dict("records")

    def normalize(row):
        for key in COUNT_COLUMNS:
            row[key] = int(row[key])
        return {key: (float(value) if key not in COUNT_COLUMNS else value)
                for key, value in row.items()}

    baseline, candidate = normalize(baseline), normalize(candidate)
    return {
        "comparison_method": "single locked validation candidate vs 0.50 on identical test probabilities",
        "validation_selection_run_id": selection["source_run_id"],
        "validation_selection_source": VALIDATION_SOURCE,
        "candidate_threshold": threshold,
        "baseline": baseline,
        "candidate": candidate,
        "delta_false_positive_candidate_minus_baseline": candidate["false_positive"] - baseline["false_positive"],
        "delta_false_negative_candidate_minus_baseline": candidate["false_negative"] - baseline["false_negative"],
        "delta_recall_attack_candidate_minus_baseline": candidate["recall_attack"] - baseline["recall_attack"],
        "interpretation": "Held-out test comparison. Lower FP can coincide with more missed attacks; no re-selection from test.",
    }
