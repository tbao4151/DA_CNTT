#!/usr/bin/env python3
"""One-time held-out test evaluation for a validation-preselected alert threshold.

Requires the locally trained and trusted full-training model artifact.
Never fits a model, searches thresholds, or modifies the selection report.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from siem_ai.locked_evaluation import evaluate_locked_threshold
from siem_ai.model import load_local_model, predict_batch

DEFAULT_TEST = ROOT / "data/raw/unsw_nb15/UNSW_NB15_testing-set.csv"
DEFAULT_MODEL = ROOT / "artifacts/unsw_binary_rf.joblib"
DEFAULT_SELECTION = ROOT / "reports/validation_threshold_experiment.json"
DEFAULT_OUTPUT = ROOT / "artifacts/locked_threshold_official_test.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", type=Path, default=DEFAULT_TEST)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--selection", type=Path, default=DEFAULT_SELECTION)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not args.model.is_file():
        parser.error("Trusted locally trained model is missing; run python scripts/train_siem.py")
    selection = json.loads(args.selection.read_text(encoding="utf-8"))
    frame = pd.read_csv(args.test)
    if frame.empty or "label" not in frame or frame["label"].isna().any() or not frame["label"].isin([0, 1]).all():
        parser.error("Official testing CSV must contain complete binary ground-truth labels")
    if args.test.resolve() == (ROOT / "data/raw/unsw_nb15/UNSW_NB15_training-set.csv").resolve():
        parser.error("Do not evaluate the locked candidate on training data")

    # Ground truth is NEVER included among inference features.
    unlabeled = frame.drop(columns=["id", "label", "attack_cat"], errors="ignore")
    probabilities = predict_batch(load_local_model(args.model), unlabeled)["attack_probability"]
    metrics = evaluate_locked_threshold(frame["label"], probabilities, selection)
    metrics.update({
        "dataset_split": "UNSW-NB15 official testing partition",
        "test_rows": len(frame),
        "model_origin": "local trusted full-training RandomForest model",
        "disclaimer": "Never reselect threshold based on this test result. Results depend on the fitted full-training model.",
    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    print(f"Saved {args.output}")


if __name__ == "__main__":
    main()
