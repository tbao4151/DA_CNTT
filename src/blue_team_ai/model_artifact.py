"""Data-only, non-executable Zeek research model export and offline scorer.

The artifact contains fitted Logistic Regression parameters and TRAIN-only
preprocessing statistics, not pickle/joblib or arbitrary Python objects.
Only TRAIN fits; VALIDATION locks the threshold; TEST is never scored here.
No network access, alert generation, or model provenance authentication.
"""
from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence

import numpy as np
import pandas as pd

from .features import LAB_FEATURE_COLUMNS, LAB_FEATURE_SCHEMA_VERSION
from .labeled_dataset import LabeledLabDataset
from .offline_baseline import (
    CATEGORICAL, NUMERIC, THRESHOLDS, _frame, _scores,
    _validate_dataset, make_zeek_research_pipeline,
)

ARTIFACT_VERSION = 1
_MAX_CATEGORIES = 1024
_HEX = frozenset("0123456789abcdef")
_KEYS = frozenset({
    "artifact_version", "mode", "feature_schema_version", "feature_columns",
    "input_manifest_sha256", "train_source_sha256", "validation_source_sha256",
    "model_type", "selected_threshold", "intercept", "categorical_adjustments",
    "numeric_parameters", "label_authenticity", "test_scored", "live_capture",
    "automated_alerts", "executable_serialization",
})
_NUMERIC_KEYS = frozenset({"median", "mean", "scale", "weight"})


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in _HEX for ch in value)


def _finite(value: object) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _encoded(encoder: object, proto: str, service: str) -> np.ndarray:
    row = pd.DataFrame([{"proto": proto, "service": service}])
    result = encoder.transform(row.loc[:, list(CATEGORICAL)])
    return np.asarray(result.toarray() if hasattr(result, "toarray") else result)[0]


def build_zeek_research_artifact(
    dataset: LabeledLabDataset, *, input_manifest_sha256: str,
) -> dict[str, object]:
    """Export fitted parameters without scoring or using held-out TEST labels.

    The manifest digest binds the operator-supplied experiment declaration,
    not the physical VM, the truth of labels, or the identity of its author.
    """
    if not _digest(input_manifest_sha256):
        raise ValueError("Invalid private experiment manifest digest")
    _validate_dataset(dataset)
    model = make_zeek_research_pipeline()
    model.fit(_frame(dataset.features["train"]), dataset.labels["train"])
    classifier = model.named_steps["classifier"]
    if list(classifier.classes_) != [0, 1] or classifier.coef_.shape[0] != 1:
        raise ValueError("Expected binary Zeek research classifier")
    validation_probs = model.predict_proba(_frame(dataset.features["validation"]))[:, 1]
    candidates = {
        threshold: _scores(dataset.labels["validation"], validation_probs, threshold)
        for threshold in THRESHOLDS
    }
    selected = max(THRESHOLDS, key=lambda t: (candidates[t]["f1"], -candidates[t]["fp"], t))

    preprocessing = model.named_steps["preprocessing"]
    encoder = preprocessing.named_transformers_["categorical"]
    numeric_pipeline = preprocessing.named_transformers_["numeric"]
    imputer = numeric_pipeline.named_steps["imputer"]
    scaler = numeric_pipeline.named_steps["scale"]
    categorical_width = len(encoder.get_feature_names_out())
    weights = np.asarray(classifier.coef_[0], dtype=float)
    if len(weights) != categorical_width + len(NUMERIC):
        raise ValueError("Unexpected fitted Zeek coefficient layout")

    # An unknown category may map to the encoder's infrequent bucket.
    # Measure that baseline using the actual fitted encoder, rather than
    # assuming unknown values always produce an all-zero one-hot vector.
    sentinel = "__DA005_UNSEEN_CATEGORY__"
    while any(sentinel in categories for categories in encoder.categories_):
        sentinel += "_"
    baseline = _encoded(encoder, sentinel, sentinel)
    category_weights = weights[:categorical_width]
    adjustments: dict[str, dict[str, float]] = {}
    for index, field in enumerate(CATEGORICAL):
        categories = encoder.categories_[index]
        if len(categories) > _MAX_CATEGORIES:
            raise ValueError("Too many Zeek categories for bounded JSON export")
        deltas: dict[str, float] = {}
        for value in categories:
            if not isinstance(value, str) or len(value) > 256:
                raise ValueError("Unexpected Zeek category")
            encoded = _encoded(
                encoder, value if index == 0 else sentinel,
                value if index == 1 else sentinel,
            )
            deltas[value] = float(np.dot(encoded - baseline, category_weights))
        adjustments[field] = deltas

    numeric_parameters: dict[str, dict[str, float]] = {}
    for index, field in enumerate(NUMERIC):
        numeric_parameters[field] = {
            "median": float(imputer.statistics_[index]),
            "mean": float(scaler.mean_[index]),
            "scale": float(scaler.scale_[index]),
            "weight": float(weights[categorical_width + index]),
        }
    artifact = {
        "artifact_version": ARTIFACT_VERSION,
        "mode": "offline_zeek_research_model_only",
        "feature_schema_version": LAB_FEATURE_SCHEMA_VERSION,
        "feature_columns": list(LAB_FEATURE_COLUMNS),
        "input_manifest_sha256": input_manifest_sha256,
        "train_source_sha256": sorted({row["source_sha256"] for row in dataset.provenance["train"]}),
        "validation_source_sha256": sorted({row["source_sha256"] for row in dataset.provenance["validation"]}),
        "model_type": "LogisticRegression(class_weight=balanced,random_state=42)",
        "selected_threshold": float(selected),
        "intercept": float(classifier.intercept_[0] + np.dot(baseline, category_weights)),
        "categorical_adjustments": adjustments,
        "numeric_parameters": numeric_parameters,
        "label_authenticity": "operator_supplied_not_verified",
        "test_scored": False,
        "live_capture": False,
        "automated_alerts": False,
        "executable_serialization": False,
    }
    validate_zeek_research_artifact(artifact)
    return artifact


def validate_zeek_research_artifact(artifact: object) -> None:
    """Fail closed on incompatible or malformed JSON model parameters."""
    if not isinstance(artifact, Mapping) or set(artifact) != _KEYS:
        raise ValueError("Unexpected Zeek research artifact fields")
    if (
        type(artifact["artifact_version"]) is not int
        or artifact["artifact_version"] != ARTIFACT_VERSION
        or artifact["mode"] != "offline_zeek_research_model_only"
        or type(artifact["feature_schema_version"]) is not int
        or artifact["feature_schema_version"] != LAB_FEATURE_SCHEMA_VERSION
        or artifact["feature_columns"] != list(LAB_FEATURE_COLUMNS)
        or not _digest(artifact["input_manifest_sha256"])
        or artifact["model_type"] != "LogisticRegression(class_weight=balanced,random_state=42)"
        or artifact["label_authenticity"] != "operator_supplied_not_verified"
        or artifact["test_scored"] is not False
        or artifact["live_capture"] is not False
        or artifact["automated_alerts"] is not False
        or artifact["executable_serialization"] is not False
        or not _finite(artifact["selected_threshold"])
        or not 0 < artifact["selected_threshold"] < 1
        or not _finite(artifact["intercept"])
    ):
        raise ValueError("Unsupported or unsafe Zeek research artifact")
    for key in ("train_source_sha256", "validation_source_sha256"):
        sources = artifact[key]
        if (
            not isinstance(sources, list) or not 1 <= len(sources) <= 30
            or any(not _digest(source) for source in sources)
            or sources != sorted(set(sources))
        ):
            raise ValueError("Invalid Zeek model source provenance")
    if set(artifact["train_source_sha256"]) & set(artifact["validation_source_sha256"]):
        raise ValueError("Train/validation sources overlap")
    categorical = artifact["categorical_adjustments"]
    numeric = artifact["numeric_parameters"]
    if not isinstance(categorical, Mapping) or set(categorical) != set(CATEGORICAL):
        raise ValueError("Invalid categorical Zeek parameters")
    for field in CATEGORICAL:
        entries = categorical[field]
        if (
            not isinstance(entries, Mapping) or len(entries) > _MAX_CATEGORIES
            or any(not isinstance(key, str) or len(key) > 256 or not _finite(value)
                   for key, value in entries.items())
        ):
            raise ValueError("Invalid fitted Zeek category weights")
    if not isinstance(numeric, Mapping) or set(numeric) != set(NUMERIC):
        raise ValueError("Invalid numeric Zeek parameters")
    for field in NUMERIC:
        params = numeric[field]
        if (
            not isinstance(params, Mapping) or set(params) != _NUMERIC_KEYS
            or any(not _finite(value) for value in params.values())
            or params["median"] < 0 or params["mean"] < 0 or params["scale"] <= 0
        ):
            raise ValueError("Invalid fitted Zeek numeric parameters")


def score_zeek_research_rows(
    artifact: Mapping[str, object], rows: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Deterministic offline-only scores; never accepts UID/IP/labels as features.

    This low-level scorer does not establish model authenticity or authorize
    operational use. A future file loader must verify an independently
    recorded artifact digest before accepting any on-disk JSON.
    """
    validate_zeek_research_artifact(artifact)
    if (
        not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray))
        or not 1 <= len(rows) <= 30_000
    ):
        raise ValueError("Expected bounded Zeek feature rows")
    result: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != set(LAB_FEATURE_COLUMNS):
            raise ValueError("Unexpected Zeek research scoring feature schema")
        logit = float(artifact["intercept"])
        for field in CATEGORICAL:
            value = row[field]
            if value is not None and (not isinstance(value, str) or len(value) > 256):
                raise ValueError("Invalid categorical Zeek input")
            normalized = "__MISSING__" if value is None else value
            logit += artifact["categorical_adjustments"][field].get(normalized, 0.0)
        for field in NUMERIC:
            value = row[field]
            if value is not None and (
                not _finite(value) or value < 0 or value > 1e12
            ):
                raise ValueError("Invalid numeric Zeek input")
            params = artifact["numeric_parameters"][field]
            measurement = params["median"] if value is None else value
            logit += ((measurement - params["mean"]) / params["scale"]) * params["weight"]
        if not math.isfinite(logit):
            raise ValueError("Non-finite Zeek research score")
        probability = (
            1 / (1 + math.exp(-logit)) if logit >= 0
            else math.exp(logit) / (1 + math.exp(logit))
        )
        result.append({
            "attack_probability": probability,
            "predicted_attack": probability >= artifact["selected_threshold"],
        })
    return result
