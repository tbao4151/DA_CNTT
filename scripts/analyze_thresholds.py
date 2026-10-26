#!/usr/bin/env python3
"""Evaluate threshold tradeoffs on UNSW-NB15 test flows with a trusted local model.

Diagnostic only: do not optimize a threshold on the official test partition.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from siem_ai.model import load_local_model, predict_batch
from siem_ai.thresholds import threshold_diagnostics

DATA = ROOT / "data/raw/unsw_nb15/UNSW_NB15_testing-set.csv"
MODEL = ROOT / "artifacts/unsw_binary_rf.joblib"
OUTPUT = ROOT / "artifacts/threshold_diagnostics.csv"


def main():
    if not MODEL.is_file():
        raise SystemExit("Missing trusted local model; run python scripts/train_siem.py")
    if not DATA.is_file():
        raise SystemExit("Missing dataset; run python scripts/download_unsw_nb15.py")
    frame = pd.read_csv(DATA)
    if frame["label"].isna().any() or not frame["label"].isin([0, 1]).all():
        raise SystemExit("Invalid ground truth labels")
    # Never pass ground-truth label or attack category to the inference model.
    scores = predict_batch(load_local_model(MODEL), frame.drop(columns=["label", "attack_cat", "id"], errors="ignore"))
    diag = threshold_diagnostics(frame["label"], scores["attack_probability"])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    diag.to_csv(OUTPUT, index=False)
    print(diag.to_string(index=False))
    print(f"Diagnostic only; wrote {OUTPUT.relative_to(ROOT)}")
    print("Do not pick a threshold using official test performance; tune on held-out training validation.")


if __name__ == "__main__":
    main()
