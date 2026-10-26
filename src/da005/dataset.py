"""Validated access to the fixed UNSW-NB15 training/testing partitions.

The files contain labelled network-flow features, NOT real-time SOC events.
Never use the official test split for fitting models or tuning thresholds.
"""
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data" / "raw" / "unsw_nb15"
SPLITS = {
    "train": "UNSW_NB15_training-set.csv",
    "test": "UNSW_NB15_testing-set.csv",
}
REQUIRED_COLUMNS = frozenset({"id", "label", "attack_cat"})


class DatasetValidationError(ValueError):
    """Raised when a dataset does not match the expected label schema."""


def validate_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Check essential schema and label/category consistency without modifying data."""
    if frame.empty:
        raise DatasetValidationError("Dataset is empty.")
    missing = REQUIRED_COLUMNS.difference(frame.columns)
    if missing:
        raise DatasetValidationError(f"Missing columns: {sorted(missing)}")
    labels = pd.to_numeric(frame["label"], errors="coerce")
    if labels.isna().any() or not labels.isin([0, 1]).all():
        raise DatasetValidationError("label must contain only 0 (normal) and 1 (attack).")
    categories = frame["attack_cat"].astype("string").str.strip()
    if categories.isna().any() or categories.eq("").any():
        raise DatasetValidationError("attack_cat contains missing/blank values.")
    mismatched = (labels.eq(0) & categories.ne("Normal")) | (labels.eq(1) & categories.eq("Normal"))
    if mismatched.any():
        raise DatasetValidationError("label and attack_cat disagree.")
    return frame


def load_split(split: str, limit: int | None = None, data_dir: Path = DATA_DIR) -> pd.DataFrame:
    """Load only an allowlisted partition, optionally limiting rows for the UI."""
    if split not in SPLITS:
        raise ValueError(f"split must be one of {tuple(SPLITS)}")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
        raise ValueError("limit must be a positive integer or None")
    path = Path(data_dir) / SPLITS[split]
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}. See README download instructions.")
    return validate_frame(pd.read_csv(path, nrows=limit, low_memory=False))


def summarize(frame: pd.DataFrame) -> dict:
    """Ground-truth dataset profile; this is NOT model performance."""
    validate_frame(frame)
    counts = frame["label"].value_counts()
    categories = frame["attack_cat"].value_counts()
    return {
        "rows": int(len(frame)),
        "normal": int(counts.get(0, 0)),
        "attack": int(counts.get(1, 0)),
        "attack_categories": {str(k): int(v) for k, v in categories.items()},
    }
