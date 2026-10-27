"""Aggregate held-out classification errors without exporting individual network flows."""
from __future__ import annotations

import pandas as pd


def summarize_group_errors(actual, predicted, groups) -> list[dict]:
    """Count TP/FP/TN/FN per ground-truth category or protocol.

    Descriptive analysis only: never use held-out test errors to choose a model,
    features or a decision threshold. No raw flow fields are exported.
    """
    actual, predicted, groups = list(actual), list(predicted), list(groups)
    if len(actual) != len(predicted) or len(actual) != len(groups):
        raise ValueError("Error-analysis arrays must have identical lengths")
    counts: dict[str, dict] = {}
    for truth, guess, raw_group in zip(actual, predicted, groups):
        if truth not in (0, 1) or guess not in (0, 1):
            raise ValueError("Error analysis requires binary 0/1 labels and predictions")
        group = "(missing)" if pd.isna(raw_group) or not str(raw_group).strip() else str(raw_group)
        entry = counts.setdefault(group, {"group": group, "flows": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0})
        entry["flows"] += 1
        key = "tp" if truth == 1 and guess == 1 else "fn" if truth == 1 else "fp" if guess == 1 else "tn"
        entry[key] += 1
    result = []
    for group in sorted(counts):
        entry = counts[group]
        attack_count = entry["tp"] + entry["fn"]
        normal_count = entry["tn"] + entry["fp"]
        result.append({**entry,
            "attack_recall": entry["tp"] / attack_count if attack_count else None,
            "normal_false_positive_rate": entry["fp"] / normal_count if normal_count else None,
        })
    return result
