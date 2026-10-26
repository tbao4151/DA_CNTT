"""Provenance-aware global MDI report for a fitted DA005 Random Forest.

The importances come solely from the fitted model; held-out test labels are
never used to derive or rank features. Do not interpret as causal or local.
"""
from __future__ import annotations

import math
import re

from .explain import global_feature_importance

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def build_importance_report(model, metrics: dict, *,
                            training_sha256: str, model_sha256: str) -> dict:
    if not isinstance(metrics, dict) or not isinstance(metrics.get("features"), list):
        raise ValueError("Missing recorded model feature list")
    if type(metrics.get("train_size")) is not int or metrics["train_size"] < 1:
        raise ValueError("Missing positive recorded train size")
    if metrics.get("model") != "RandomForestClassifier":
        raise ValueError("Expected RandomForestClassifier baseline")
    if not _SHA256.fullmatch(training_sha256) or not _SHA256.fullmatch(model_sha256):
        raise ValueError("Expected valid SHA-256 checksums")

    importance = global_feature_importance(model)
    fitted_fields = list(model.named_steps["preprocess"].feature_names_in_)
    if metrics["features"] != fitted_fields or set(importance["feature"]) != set(fitted_fields):
        raise ValueError("Fitted model fields differ from recorded training fields")
    if len(importance) != len(fitted_fields):
        raise ValueError("Unexpected number of importance rows")
    total = float(importance["importance"].sum())
    if not math.isclose(total, 1.0, abs_tol=1e-8):
        raise ValueError("Feature importances must sum to 1 on a fitted model")

    forest = model.named_steps["forest"]
    features = []
    for rank, row in enumerate(importance.itertuples(index=False), start=1):
        features.append({
            "rank": rank,
            "feature": row.feature,
            "mdi_importance": float(row.importance),
            "mdi_percent": float(row.importance_percent),
            "encoded_dimensions": int(row.encoded_dimensions),
        })
    return {
        "dataset": "UNSW-NB15",
        "training_partition": "official UNSW_NB15_training-set.csv",
        "training_rows": metrics["train_size"],
        "training_csv_sha256": training_sha256,
        "model_file_sha256": model_sha256,
        "model": "RandomForestClassifier",
        "n_estimators": int(forest.n_estimators),
        "random_state": int(forest.random_state),
        "method": "mean decrease in impurity (MDI / Gini importance), grouped over one-hot dimensions",
        "importance_scope": "global; fitted training model only",
        "uses_test_labels": False,
        "note": "Descriptive, potentially biased towards high-cardinality features. Not causal or per-flow explanation.",
        "feature_count": len(features),
        "encoded_feature_count": int(importance["encoded_dimensions"].sum()),
        "importance_sum": total,
        "features": features,
    }
