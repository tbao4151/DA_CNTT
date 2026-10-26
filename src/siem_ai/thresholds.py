"""Threshold diagnostics for held-out binary intrusion scores.

For analysis only: selecting a final threshold on the official test set would
bias reported performance. Choose thresholds on validation data, then evaluate
once on the untouched official test split.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score


def threshold_diagnostics(labels, probabilities, thresholds=(0.5, 0.6, 0.7, 0.8, 0.9)):
    y = np.asarray(labels)
    p = np.asarray(probabilities, dtype=float)
    levels = list(thresholds)
    if y.ndim != 1 or p.ndim != 1 or y.size != p.size or y.size == 0:
        raise ValueError("Expected nonempty equally sized 1-D arrays")
    if not np.isin(y, [0, 1]).all():
        raise ValueError("Labels must contain only 0/1")
    if not np.isfinite(p).all() or ((p < 0) | (p > 1)).any():
        raise ValueError("Probabilities must be finite values in [0, 1]")
    if not levels or not np.isfinite(np.asarray(levels, dtype=float)).all():
        raise ValueError("Thresholds must be finite")
    if any(t < 0 or t > 1 for t in levels):
        raise ValueError("Thresholds must be in [0, 1]")

    output = []
    for threshold in levels:
        pred = (p >= threshold).astype(int)
        tp = int(((y == 1) & (pred == 1)).sum())
        fp = int(((y == 0) & (pred == 1)).sum())
        tn = int(((y == 0) & (pred == 0)).sum())
        fn = int(((y == 1) & (pred == 0)).sum())
        output.append({
            "threshold": float(threshold),
            "true_positive": tp, "false_positive": fp,
            "true_negative": tn, "false_negative": fn,
            "precision_attack": float(precision_score(y, pred, zero_division=0)),
            "recall_attack": float(recall_score(y, pred, zero_division=0)),
            "f1_attack": float(f1_score(y, pred, zero_division=0)),
            "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
            "alerts": tp + fp,
        })
    return pd.DataFrame(output)
