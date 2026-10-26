#!/usr/bin/env python3
"""Train once on official split, evaluate honestly on untouched test data."""
from pathlib import Path
import argparse
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from siem_ai.model import fit_and_evaluate, persist_model


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts")
    args = parser.parse_args()
    data = ROOT / "data/raw/unsw_nb15"
    train = pd.read_csv(data / "UNSW_NB15_training-set.csv")
    test = pd.read_csv(data / "UNSW_NB15_testing-set.csv")
    pipeline, metrics = fit_and_evaluate(train, test)
    persist_model(pipeline, metrics, args.output)
    print("Saved verified test metrics and fitted model:", args.output)
    print("Attack recall:", metrics["classification_report"]["1"]["recall"])
    print("Attack F1:", metrics["classification_report"]["1"]["f1-score"])


if __name__ == "__main__":
    main()
