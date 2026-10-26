"""Leakage-safe binary ML model for UNSW-NB15, with honest held-out metrics."""
from __future__ import annotations

import json
from pathlib import Path

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
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output / "unsw_binary_rf.joblib", compress=3)
    (output / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def predict_batch(model, rows: pd.DataFrame) -> pd.DataFrame:
    # Drop labels even if user uploads already-labeled files; never leak ground truth.
    columns = [c for c in model.feature_names_in_] if hasattr(model, "feature_names_in_") else None
    if columns is None:
        columns = list(model.named_steps["preprocess"].feature_names_in_)
    if not set(columns).issubset(rows.columns):
        raise ValueError("Input is missing required trained features")
    safe = rows[columns].copy()
    probabilities = model.predict_proba(safe)[:, 1]
    return pd.DataFrame({
        "verdict": np.where(probabilities >= 0.5, "Attack", "Normal"),
        "attack_probability": probabilities,
    }, index=rows.index)


def load_local_model(path: str | Path):
    # joblib relies on pickle. Load ONLY artifacts that you generated and trust.
    return joblib.load(path)
