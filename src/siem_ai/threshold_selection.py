"""Select an alert threshold using validation labels only, never official test."""
from __future__ import annotations

import numpy as np

from .thresholds import threshold_diagnostics


def select_threshold(labels, probabilities, *, min_recall=0.95,
                     candidates=(0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95)):
    """Minimize false positives subject to a validation recall floor.

    Returns a selected threshold and its validation-only diagnostic metrics.
    The caller must ensure labels/scores are from a held-out validation split.
    """
    y = np.asarray(labels)
    if y.ndim != 1 or not np.isin(y, [0, 1]).all() or not (y == 0).any() or not (y == 1).any():
        raise ValueError("Validation labels must contain both Normal (0) and Attack (1)")
    if not np.isfinite(min_recall) or not 0 < min_recall <= 1:
        raise ValueError("min_recall must be finite and in (0, 1]")
    table = threshold_diagnostics(y, probabilities, thresholds=candidates)
    feasible = table.loc[table["recall_attack"] >= min_recall]
    if feasible.empty:
        raise ValueError("No candidate threshold satisfies the validation recall constraint")
    # Deterministic policy: fewest FP; among ties maximize recall, then lower threshold.
    selected = feasible.sort_values(
        ["false_positive", "recall_attack", "threshold"],
        ascending=[True, False, True],
    ).iloc[0]
    return {"threshold": float(selected["threshold"]),
            "validation_metrics": selected.to_dict(),
            "min_recall": float(min_recall),
            "candidates_evaluated": len(table)}
