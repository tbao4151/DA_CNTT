#!/usr/bin/env python3
"""Choose an alert threshold on a stratified holdout from UNSW training ONLY.

Never reads the official test partition. This trains a *temporary* model on
80% of training; the selected threshold is a research candidate, not a claim
of performance for the full-training production/demo model.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from siem_ai.model import fit_and_evaluate, predict_batch
from siem_ai.threshold_selection import select_threshold

TRAIN = ROOT / "data/raw/unsw_nb15/UNSW_NB15_training-set.csv"
OUTPUT = ROOT / "artifacts/validation_threshold.json"


def main():
    if not TRAIN.is_file():
        raise SystemExit("Missing official training CSV; run python scripts/download_unsw_nb15.py")
    frame = pd.read_csv(TRAIN)
    if frame["label"].isna().any() or not frame["label"].isin([0, 1]).all():
        raise SystemExit("Training labels must be complete binary 0/1")
    fit_rows, validation_rows = train_test_split(
        frame, test_size=0.2, random_state=42, stratify=frame["label"]
    )
    model, _ = fit_and_evaluate(fit_rows, validation_rows)
    scores = predict_batch(model, validation_rows.drop(
        columns=["label", "attack_cat", "id"], errors="ignore"
    ))["attack_probability"]
    result = select_threshold(validation_rows["label"], scores, min_recall=0.95)
    result.update({
        "selection_source": "UNSW-NB15 official training split only",
        "training_rows_for_temporary_model": len(fit_rows),
        "validation_rows": len(validation_rows),
        "random_state": 42,
        "validation_fraction": 0.2,
        "warning": "Validation-only result, not official test performance. Do not compare directly to the full-training baseline."
    })
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"Saved {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
