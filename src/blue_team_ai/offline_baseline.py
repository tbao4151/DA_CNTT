"""Offline Zeek-only research baseline; never loads the UNSW-NB15 classifier.

The caller must build an independently annotated, host-disjoint dataset first.
All preprocessing and the classifier are fitted on TRAIN only; threshold choice
uses VALIDATION only; TEST is scored once after that choice. No artifacts,
network activity, automated alerts or SOC cases are produced.
"""
from __future__ import annotations

import math
from collections.abc import Mapping

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .features import LAB_FEATURE_COLUMNS, LAB_FEATURE_SCHEMA_VERSION, validate_zeek_model_features
from .labeled_dataset import LabeledLabDataset, SPLITS
from .host_variability import summarize_host_variability
from .probability_diagnostics import summarize_probability_quality
from .uncertainty import summarize_detection_uncertainty

CATEGORICAL = ("proto", "service")
NUMERIC = tuple(name for name in LAB_FEATURE_COLUMNS if name not in CATEGORICAL)
THRESHOLDS = (0.25, 0.40, 0.50, 0.60, 0.75)
_PROVENANCE_FIELDS = frozenset({
    "source_sha256", "session_id", "host_group", "uid",
    "label_method", "label_reference",
})


def _validate_dataset(dataset: LabeledLabDataset) -> None:
    if not isinstance(dataset, LabeledLabDataset):
        raise ValueError("Expected a validated LabeledLabDataset")
    if dataset.feature_schema_version != LAB_FEATURE_SCHEMA_VERSION or tuple(dataset.feature_columns) != LAB_FEATURE_COLUMNS:
        raise ValueError("Zeek feature schema mismatch")
    if any(set(partition) != set(SPLITS) for partition in (dataset.features, dataset.labels, dataset.provenance)):
        raise ValueError("Missing or unexpected dataset split")
    seen_sources: dict[str, str] = {}
    seen_hosts: dict[str, str] = {}
    seen_sessions: dict[str, str] = {}
    for split in SPLITS:
        rows, labels, provenance = dataset.features[split], dataset.labels[split], dataset.provenance[split]
        if not rows or len(rows) != len(labels) or len(rows) != len(provenance):
            raise ValueError("Split rows, labels and provenance must align")
        if any(type(label) is not int or label not in (0, 1) for label in labels) or set(labels) != {0, 1}:
            raise ValueError("Each split needs independently labeled binary classes")
        for row, meta in zip(rows, provenance):
            validate_zeek_model_features(row)
            if not isinstance(meta, Mapping) or set(meta) != _PROVENANCE_FIELDS:
                raise ValueError("Missing Zeek provenance fields")
            for field in _PROVENANCE_FIELDS:
                value = meta[field]
                if not isinstance(value, str) or not value or len(value) > 256:
                    raise ValueError("Missing Zeek provenance field value")
            digest = meta["source_sha256"]
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValueError("Invalid Zeek provenance SHA-256")
            for field, registry in (
                ("source_sha256", seen_sources),
                ("host_group", seen_hosts),
                ("session_id", seen_sessions),
            ):
                value = meta[field]
                if not isinstance(value, str) or not value or (value in registry and registry[value] != split):
                    raise ValueError(f"Cross-split {field} leakage or invalid provenance")
                registry[value] = split
    if len(seen_hosts) < 3 or len(seen_sources) < 3:
        raise ValueError("Host-disjoint, source-disjoint partitions are required")
    if any(all(row[field] is None for row in dataset.features["train"]) for field in NUMERIC):
        raise ValueError("Every numeric feature needs at least one measured training value")


def _frame(rows: list[dict[str, object]]) -> pd.DataFrame:
    # Fixed feature order; no UID/IP/timestamp/label/provenance enters the model.
    frame = pd.DataFrame([{key: row[key] for key in LAB_FEATURE_COLUMNS} for row in rows])
    for field in CATEGORICAL:
        frame[field] = frame[field].map(lambda value: "__MISSING__" if value is None else value)
    for field in NUMERIC:
        frame[field] = pd.to_numeric(frame[field], errors="raise")
    return frame.loc[:, list(LAB_FEATURE_COLUMNS)]


def _scores(labels: list[int], probabilities: np.ndarray, threshold: float) -> dict[str, object]:
    if len(labels) != len(probabilities) or not 0 < threshold < 1:
        raise ValueError("Invalid evaluation inputs")
    predictions = probabilities >= threshold
    truth = np.asarray(labels, dtype=int)
    tp = int(np.sum(predictions & (truth == 1)))
    fp = int(np.sum(predictions & (truth == 0)))
    tn = int(np.sum(~predictions & (truth == 0)))
    fn = int(np.sum(~predictions & (truth == 1)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall,
        "f1": f1, "false_positive_rate": fpr,
        "support": len(labels),
    }


def make_zeek_research_pipeline() -> Pipeline:
    """One shared train-only pipeline for evaluation and private JSON export."""
    preprocessing = ColumnTransformer(
        transformers=[
            ("categorical", OneHotEncoder(handle_unknown="ignore", max_categories=32), list(CATEGORICAL)),
            ("numeric", Pipeline([
                ("imputer", SimpleImputer(strategy="median")),
                ("scale", StandardScaler()),
            ]), list(NUMERIC)),
        ],
        sparse_threshold=1.0,
    )
    return Pipeline([
        ("preprocessing", preprocessing),
        ("classifier", LogisticRegression(class_weight="balanced", max_iter=2000, random_state=42)),
    ])


def evaluate_offline_zeek_baseline(
    dataset: LabeledLabDataset, *, include_private_test_trace: bool = False,
) -> dict[str, object]:
    """Fit a deterministic research baseline, select on validation, evaluate held-out test.

    Input labels/metadata are operator-supplied and NOT authenticated here.
    Do not treat synthetic test scores as research results or deploy this model.
    """
    if type(include_private_test_trace) is not bool:
        raise ValueError("Expected explicit boolean private trace option")
    _validate_dataset(dataset)
    train = _frame(dataset.features["train"])
    # The imputer's medians, scaler statistics and category vocabulary are fitted
    # only on TRAIN; unknown validation/test categories are safely ignored.
    model = make_zeek_research_pipeline()
    model.fit(train, dataset.labels["train"])
    classes = list(model.named_steps["classifier"].classes_)
    if classes != [0, 1]:
        raise ValueError("Expected binary Normal/Attack classifier")
    validation_probs = model.predict_proba(_frame(dataset.features["validation"]))[:, classes.index(1)]
    candidates = {threshold: _scores(dataset.labels["validation"], validation_probs, threshold) for threshold in THRESHOLDS}
    # Maximize validation F1, then minimize FP; ties prefer a higher threshold.
    selected = max(THRESHOLDS, key=lambda t: (candidates[t]["f1"], -candidates[t]["fp"], t))
    # The test set is first consulted after model fitting and threshold selection.
    test_probs = model.predict_proba(_frame(dataset.features["test"]))[:, classes.index(1)]
    test_metrics = _scores(dataset.labels["test"], test_probs, selected)
    # Descriptive only: never calibrate, refit or tune using held-out test.
    validation_quality = summarize_probability_quality(dataset.labels["validation"], validation_probs)
    test_quality = summarize_probability_quality(dataset.labels["test"], test_probs)
    sources = {
        split: {
            "flows": len(dataset.labels[split]),
            "source_sha256": sorted({p["source_sha256"] for p in dataset.provenance[split]}),
            "host_groups": len({p["host_group"] for p in dataset.provenance[split]}),
            "sessions": len({p["session_id"] for p in dataset.provenance[split]}),
        }
        for split in SPLITS
    }
    report = {
        "report_version": 5,
        "mode": "offline_labeled_zeek_research_only",
        "label_authenticity": "operator_supplied_not_verified",
        "feature_schema_version": LAB_FEATURE_SCHEMA_VERSION,
        "feature_columns": list(LAB_FEATURE_COLUMNS),
        "model": "LogisticRegression(class_weight=balanced,random_state=42)",
        "preprocessing": "train_only_median_imputation_standard_scaling_onehot_unknown_ignored",
        "threshold_selection": "validation_max_f1_tiebreak_min_fp_then_higher_threshold",
        "selected_threshold": selected,
        "validation_metrics": candidates[selected],
        "test_metrics": test_metrics,
        "validation_probability_diagnostics": validation_quality,
        "test_probability_diagnostics": test_quality,
        "validation_detection_uncertainty": summarize_detection_uncertainty(candidates[selected]),
        "test_detection_uncertainty": summarize_detection_uncertainty(test_metrics),
        "validation_host_variability": summarize_host_variability(
            dataset.labels["validation"], validation_probs,
            [meta["host_group"] for meta in dataset.provenance["validation"]],
            selected, suppress_small_groups=True,
        ),
        "test_host_variability": summarize_host_variability(
            dataset.labels["test"], test_probs,
            [meta["host_group"] for meta in dataset.provenance["test"]],
            selected, suppress_small_groups=True,
        ),
        "provenance": sources,
        "live_capture": False,
        "automated_alerts": False,
    }
    if include_private_test_trace:
        # Private, test-only event-level predictions for later manual analysis.
        # Never mix these UIDs and independently supplied labels into the
        # aggregate report or interpret them as authenticated ground truth.
        flows = []
        for meta, label, probability in zip(
            dataset.provenance["test"], dataset.labels["test"], test_probs,
            strict=True,
        ):
            attack_probability = float(probability)
            if not math.isfinite(attack_probability) or not 0 <= attack_probability <= 1:
                raise ValueError("Invalid model probability")
            predicted_attack = attack_probability >= selected
            outcome = (
                "true_positive" if label == 1 else "false_positive"
            ) if predicted_attack else (
                "false_negative" if label == 1 else "true_negative"
            )
            flows.append({
                "source_sha256": meta["source_sha256"],
                "uid": meta["uid"],
                "attack_probability": attack_probability,
                "predicted_attack": bool(predicted_attack),
                "operator_supplied_label": label,
                "outcome_against_supplied_label": outcome,
            })
        report["private_test_trace"] = {
            "trace_version": 1,
            "mode": "offline_zeek_heldout_test_predictions_only",
            "feature_schema_version": LAB_FEATURE_SCHEMA_VERSION,
            "selected_threshold": selected,
            "label_authenticity": "operator_supplied_not_verified",
            "live_capture": False,
            "automated_alerts": False,
            "flows": flows,
        }
    return report
