#!/usr/bin/env python3
"""Reproducible baseline: leakage-safe preprocessing and untouched official test split."""
from pathlib import Path
import json
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, average_precision_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/raw/unsw_nb15"
train = pd.read_csv(DATA / "UNSW_NB15_training-set.csv")
test = pd.read_csv(DATA / "UNSW_NB15_testing-set.csv")
for df in (train, test):
    assert {"id","attack_cat","label"}.issubset(df.columns)
    assert set(df["label"].dropna().unique()).issubset({0,1})
features = [c for c in train.columns if c not in ("id", "attack_cat", "label")]
categorical = [c for c in features if train[c].dtype == "object"]
numeric = [c for c in features if c not in categorical]
preprocessor = ColumnTransformer([
    ("num", SimpleImputer(strategy="median"), numeric),
    ("cat", Pipeline([("fill", SimpleImputer(strategy="most_frequent")), ("encode", OneHotEncoder(handle_unknown="ignore"))]), categorical),
])
model = Pipeline([("features", preprocessor), ("classifier", RandomForestClassifier(n_estimators=100, class_weight="balanced_subsample", random_state=42, n_jobs=-1))])
model.fit(train[features], train["label"])
pred = model.predict(test[features])
prob = model.predict_proba(test[features])[:, 1]
result = {
    "dataset": "UNSW-NB15",
    "task": "binary intrusion detection",
    "train_rows": len(train), "test_rows": len(test),
    "model": "RandomForestClassifier",
    "metrics": classification_report(test["label"], pred, output_dict=True, zero_division=0),
    "confusion_matrix_labels_0_1": confusion_matrix(test["label"], pred, labels=[0,1]).tolist(),
    "average_precision_attack": float(average_precision_score(test["label"], prob)),
}
out = ROOT / "reports"
out.mkdir(exist_ok=True)
(out / "baseline_metrics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(classification_report(test["label"], pred, zero_division=0))
print("Reports saved to reports/baseline_metrics.json")
