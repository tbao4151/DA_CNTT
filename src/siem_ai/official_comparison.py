"""Validate archived official threshold comparison before showing it in the SOC UI.

This module only reads and checks an existing held-out report; it never tunes
thresholds or recomputes predictions from official-test labels.
"""
from __future__ import annotations

import json
import math
from pathlib import Path


COUNTS = ("true_positive", "false_positive", "true_negative", "false_negative", "alerts")
METRICS = ("precision_attack", "recall_attack", "f1_attack", "false_positive_rate")


def validate_official_comparison(report: dict) -> dict:
    """Reject incomplete or arithmetically inconsistent archived benchmark data."""
    if not isinstance(report, dict):
        raise ValueError("Expected a JSON object")
    if report.get("validation_selection_source") != "UNSW-NB15 official training split only":
        raise ValueError("Threshold provenance must be training-only validation")
    if report.get("dataset_split") != "UNSW-NB15 official testing partition":
        raise ValueError("Expected official held-out test partition")
    n = report.get("test_rows")
    if type(n) is not int or n <= 0:
        raise ValueError("Invalid test row count")
    for key in ("validation_selection_run_id", "evaluation_run_id"):
        if type(report.get(key)) is not int or report[key] <= 0:
            raise ValueError(f"Missing valid {key}")
    candidate_threshold = report.get("candidate_threshold")
    if (type(candidate_threshold) not in (int, float)
            or not math.isfinite(candidate_threshold)
            or not 0 <= candidate_threshold <= 1):
        raise ValueError("Invalid candidate threshold")

    for name, expected_threshold in (("baseline", 0.5), ("candidate", candidate_threshold)):
        row = report.get(name)
        if not isinstance(row, dict):
            raise ValueError(f"Missing {name} metrics")
        threshold = row.get("threshold")
        if (type(threshold) not in (int, float)
                or not math.isfinite(threshold)
                or not math.isclose(threshold, expected_threshold, abs_tol=1e-12)):
            raise ValueError(f"Inconsistent {name} threshold")
        if any(type(row.get(key)) is not int or row[key] < 0 for key in COUNTS):
            raise ValueError(f"Invalid {name} confusion counts")
        tp, fp, tn, fn = (row[key] for key in COUNTS[:4])
        if tp + fp + tn + fn != n or row["alerts"] != tp + fp:
            raise ValueError(f"Inconsistent {name} sample/alert totals")
        expected = {
            "precision_attack": tp / (tp + fp) if tp + fp else 0.0,
            "recall_attack": tp / (tp + fn) if tp + fn else 0.0,
            "f1_attack": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        }
        for metric in METRICS:
            value = row.get(metric)
            if (type(value) not in (int, float) or not math.isfinite(value)
                    or not math.isclose(value, expected[metric], rel_tol=0, abs_tol=1e-9)):
                raise ValueError(f"Inconsistent {name} {metric}")

    baseline, candidate = report["baseline"], report["candidate"]
    deltas = {
        "delta_false_positive_candidate_minus_baseline": candidate["false_positive"] - baseline["false_positive"],
        "delta_false_negative_candidate_minus_baseline": candidate["false_negative"] - baseline["false_negative"],
        "delta_recall_attack_candidate_minus_baseline": candidate["recall_attack"] - baseline["recall_attack"],
    }
    for key, expected in deltas.items():
        value = report.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or not math.isclose(value, expected, abs_tol=1e-9):
            raise ValueError(f"Inconsistent {key}")
    return report


def load_official_comparison(path: str | Path) -> dict:
    """Load a local JSON report; no network access or model deserialization."""
    return validate_official_comparison(json.loads(Path(path).read_text(encoding="utf-8")))
