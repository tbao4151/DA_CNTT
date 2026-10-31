"""Descriptive TRAIN-to-VALIDATION Zeek feature shift; held-out TEST stays sealed.

This is a read-only aggregate diagnostic on already validated offline feature
rows. It never fits a model, selects a threshold, reads test features, creates
alerts, authenticates labels or accesses a network.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from .features import (
    LAB_FEATURE_COLUMNS, LAB_FEATURE_SCHEMA_VERSION, validate_zeek_model_features,
)
from .labeled_dataset import LabeledLabDataset

CATEGORICAL = ("proto", "service")
NUMERIC = tuple(field for field in LAB_FEATURE_COLUMNS if field not in CATEGORICAL)


def summarize_train_validation_feature_shift(
    dataset: LabeledLabDataset,
) -> dict[str, object]:
    """Count missing, unseen-category and out-of-train-range validation values.

    All reference ranges/vocabularies come exclusively from TRAIN. No raw
    values, host identifiers, UIDs, IPs, timestamps or TEST data are emitted.
    Counts are descriptive and do not establish statistical distribution shift.
    """
    if (
        not isinstance(dataset, LabeledLabDataset)
        or dataset.feature_schema_version != LAB_FEATURE_SCHEMA_VERSION
        or tuple(dataset.feature_columns) != LAB_FEATURE_COLUMNS
        or not isinstance(dataset.features, Mapping)
    ):
        raise ValueError("Expected validated Zeek v1 feature dataset")

    partitions: dict[str, dict[str, object]] = {}
    rows_by_split: dict[str, Sequence[Mapping[str, object]]] = {}
    for split in ("train", "validation"):
        rows = dataset.features.get(split)
        if not isinstance(rows, (list, tuple)) or not rows:
            raise ValueError("TRAIN and VALIDATION feature rows must be nonempty")
        for row in rows:
            validate_zeek_model_features(row)
        rows_by_split[split] = rows
        partitions[split] = {
            "flows": len(rows),
            "missing_counts": {
                field: sum(row[field] is None for row in rows)
                for field in LAB_FEATURE_COLUMNS
            },
        }

    train = rows_by_split["train"]
    validation = rows_by_split["validation"]
    known_categories = {
        field: {row[field] for row in train if row[field] is not None}
        for field in CATEGORICAL
    }
    train_ranges: dict[str, tuple[int | float, int | float] | None] = {}
    for field in NUMERIC:
        observed = [row[field] for row in train if row[field] is not None]
        train_ranges[field] = (min(observed), max(observed)) if observed else None

    unseen = {
        field: sum(
            row[field] is not None and row[field] not in known_categories[field]
            for row in validation
        )
        for field in CATEGORICAL
    }
    out_of_range = {
        field: (
            sum(
                row[field] is not None
                and (row[field] < bounds[0] or row[field] > bounds[1])
                for row in validation
            )
            if (bounds := train_ranges[field]) is not None else None
        )
        for field in NUMERIC
    }
    partitions["validation"]["unseen_train_category_counts"] = unseen
    partitions["validation"]["outside_train_numeric_range_counts"] = out_of_range

    warnings: list[str] = []
    if len(train) < 100 or len(validation) < 100:
        warnings.append("small_train_or_validation_sample")
    if any(unseen.values()):
        warnings.append("validation_contains_unseen_train_categories")
    if any(count is not None and count > 0 for count in out_of_range.values()):
        warnings.append("validation_contains_values_outside_train_numeric_ranges")
    if any(
        partitions["train"]["missing_counts"][field] !=
        partitions["validation"]["missing_counts"][field]
        for field in LAB_FEATURE_COLUMNS
    ):
        warnings.append("missing_value_counts_differ_between_splits")
    if any(bounds is None for bounds in train_ranges.values()):
        warnings.append("some_numeric_features_unmeasured_in_train")

    return {
        "diagnostic_version": 1,
        "mode": "offline_zeek_train_validation_feature_shift_only",
        "reference_split": "train",
        "compared_split": "validation",
        "feature_schema_version": LAB_FEATURE_SCHEMA_VERSION,
        "partitions": partitions,
        "test_features_used_in_shift": False,
        "test_labels_used_in_shift": False,
        "model_fitted": False,
        "threshold_selected": False,
        "ground_truth_verified": False,
        "host_only_isolation_verified": False,
        "live_capture": False,
        "warnings": warnings,
        "interpretation": (
            "Train-referenced aggregate feature diagnostics only; no held-out "
            "test inspection, no hypothesis test or proof of attack detection. "
            "Operator-supplied capture independence and labels are not authenticated."
        ),
    }
