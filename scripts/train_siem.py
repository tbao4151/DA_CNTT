#!/usr/bin/env python3
"""Train once on official split, evaluate honestly on untouched test data."""
from pathlib import Path
from collections.abc import Mapping
import argparse
import hashlib
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.download_unsw_nb15 import FILES as OFFICIAL_FILES
from siem_ai.model import fit_and_evaluate, persist_model

 
def load_verified_split(
    data_dir: Path, *, expected_files: Mapping[str, tuple[int, str]] = OFFICIAL_FILES
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Fail closed on altered official CSVs before fitting or writing artifacts.

    The expected hashes are pinned in the downloader source, not read from a
    locally editable metadata.json. Tests can supply tiny synthetic fixtures.
    """
    frames = []
    for name in ("UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"):
        expected_rows, expected_digest = expected_files[name]
        path = data_dir / name
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != expected_digest:
            raise ValueError(f"{name}: SHA-256 mismatch; refusing to train on modified data")
        frame = pd.read_csv(path)
        if len(frame) != expected_rows:
            raise ValueError(f"{name}: expected {expected_rows} rows, got {len(frame)}")
        frames.append(frame)
    return frames[0], frames[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts")
    args = parser.parse_args()
    data = ROOT / "data/raw/unsw_nb15"
    train, test = load_verified_split(data)
    pipeline, metrics = fit_and_evaluate(train, test)
    persist_model(pipeline, metrics, args.output)
    print("Saved verified test metrics and fitted model:", args.output)
    print("Attack recall:", metrics["classification_report"]["1"]["recall"])
    print("Attack F1:", metrics["classification_report"]["1"]["f1-score"])


if __name__ == "__main__":
    main()
