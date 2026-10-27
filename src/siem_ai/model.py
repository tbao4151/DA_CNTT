"""Leakage-safe binary ML model for UNSW-NB15, with honest held-out metrics."""
from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from .core import NON_FEATURE_FIELDS, REQUIRED_FEATURES


def fit_and_evaluate(train: pd.DataFrame, test: pd.DataFrame):
    if "label" not in train or "label" not in test:
        raise ValueError("Train and test need binary label column")
    # A partial/missing target is not a valid supervised benchmark.  dropna()
    # previously allowed NaNs to pass this check, failing later in sklearn.
    if train["label"].isna().any() or not train["label"].isin([0, 1]).all():
        raise ValueError("Expected complete binary 0/1 labels in train")
    if test["label"].isna().any() or not test["label"].isin([0, 1]).all():
        raise ValueError("Expected complete binary 0/1 labels in test")
    if set(train["label"].unique()) != {0, 1}:
        raise ValueError("Training requires both Normal (0) and Attack (1) classes")
    if not REQUIRED_FEATURES.issubset(train.columns) or not REQUIRED_FEATURES.issubset(test.columns):
        raise ValueError("Required UNSW features missing")
    # Also exclude predictions and view-only fields when reusing a dashboard
    # dataframe as training input; they are not original network features.
    fields = [c for c in train.columns if c not in NON_FEATURE_FIELDS]
    if not set(fields).issubset(test.columns):
        raise ValueError("Test is missing training features")
    categories = [c for c in fields if train[c].dtype == "object"]
    numbers = [c for c in fields if c not in categories]
    preprocess = ColumnTransformer([
        ("numeric", SimpleImputer(strategy="median"), numbers),
        ("categorical", Pipeline([
            ("impute", SimpleImputer(strategy="most_frequent")),
            ("encode", OneHotEncoder(handle_unknown="ignore")),
        ]), categories),
    ])
    model = Pipeline([
        ("preprocess", preprocess),
        ("forest", RandomForestClassifier(
            n_estimators=100, min_samples_leaf=2,
            class_weight="balanced_subsample", random_state=42, n_jobs=-1
        )),
    ])
    model.fit(train[fields], train["label"])
    predictions = model.predict(test[fields])
    scores = model.predict_proba(test[fields])[:, 1]
    metrics = {
        "model": "RandomForestClassifier",
        "train_size": int(len(train)), "test_size": int(len(test)),
        "features": fields,
        "classification_report": classification_report(
            test["label"], predictions, labels=[0, 1], output_dict=True, zero_division=0
        ),
        "confusion_matrix_0_1": confusion_matrix(
            test["label"], predictions, labels=[0, 1]
        ).tolist(),
        "average_precision_attack": float(average_precision_score(test["label"], scores)),
        "note": "Official held-out test; preprocessing fitted on train only; no hyperparameter tuning on test.",
    }
    return model, metrics


def persist_model(model, metrics: dict, directory: str | Path) -> None:
    """Stage both artifacts before replacing existing local model/metrics files.

    Failed serialization leaves any prior artifacts untouched. The two final
    os.replace calls are individually atomic, not a two-file transaction.
    """
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".da005-artifacts-", dir=output) as temp_dir:
        staged = Path(temp_dir)
        model_file = staged / "unsw_binary_rf.joblib"
        metrics_file = staged / "metrics.json"
        joblib.dump(model, model_file, compress=3)
        metrics_file.write_text(
            json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        os.replace(model_file, output / model_file.name)
        os.replace(metrics_file, output / metrics_file.name)


def predict_batch(model, rows: pd.DataFrame) -> pd.DataFrame:
    # Drop labels even if user uploads already-labeled files; never leak ground truth.
    columns = [c for c in model.feature_names_in_] if hasattr(model, "feature_names_in_") else None
    if columns is None:
        columns = list(model.named_steps["preprocess"].feature_names_in_)
    if not set(columns).issubset(rows.columns):
        raise ValueError("Input is missing required trained features")
    # Never assume that predict_proba column 1 represents the Attack class.
    # Reject incompatible or single-class artifacts rather than silently
    # reporting Normal probabilities as Attack probabilities.
    classes = getattr(model, "classes_", None)
    if classes is None or len(classes) != 2 or set(classes) != {0, 1}:
        raise ValueError("Model must have exactly the binary classes 0 (Normal) and 1 (Attack)")
    attack_index = list(classes).index(1)
    safe = rows[columns].copy()
    probabilities = np.asarray(model.predict_proba(safe))
    if probabilities.shape != (len(rows), 2):
        raise ValueError("Model returned an invalid probability matrix")
    attack_probabilities = probabilities[:, attack_index]
    if not np.isfinite(attack_probabilities).all() or not ((attack_probabilities >= 0) & (attack_probabilities <= 1)).all():
        raise ValueError("Model returned invalid Attack probabilities")
    return pd.DataFrame({
        "verdict": np.where(attack_probabilities >= 0.5, "Attack", "Normal"),
        "attack_probability": attack_probabilities,
    }, index=rows.index)


def model_artifact_signature(path: str | Path) -> tuple[int, int]:
    """Cache key for a local model; changes when its mtime or size changes.

    Use metadata rather than hashing a potentially large joblib file on every
    Streamlit rerun. The file must exist; callers handle OSError on replacement.
    """
    stat = Path(path).stat()
    return stat.st_mtime_ns, stat.st_size


def load_local_model(path: str | Path):
    # joblib relies on pickle. Load ONLY artifacts that you generated and trust.
    return joblib.load(path)
