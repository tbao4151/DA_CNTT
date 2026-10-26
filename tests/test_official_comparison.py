"""Regression checks for displayed, archived official-test threshold evidence."""
import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from siem_ai.official_comparison import load_official_comparison, validate_official_comparison


def test_real_archived_report_is_consistent():
    report = load_official_comparison(ROOT / "reports/official_locked_threshold_comparison.json")
    assert report["test_rows"] == 82332
    assert report["baseline"]["false_positive"] == 8400
    assert report["candidate"]["false_positive"] == 7135
    assert report["delta_false_negative_candidate_minus_baseline"] == 342


@pytest.mark.parametrize("field,value", [
    ("test_rows", 82333),
    ("candidate_threshold", 0.75),
    ("delta_false_positive_candidate_minus_baseline", -1264),
    ("validation_selection_source", "official test"),
])
def test_rejects_tampered_top_level_fields(field, value):
    report = load_official_comparison(ROOT / "reports/official_locked_threshold_comparison.json")
    modified = copy.deepcopy(report)
    modified[field] = value
    with pytest.raises(ValueError):
        validate_official_comparison(modified)


def test_rejects_tampered_confusion_and_precision():
    report = load_official_comparison(ROOT / "reports/official_locked_threshold_comparison.json")
    for field, value in [("false_negative", 1), ("precision_attack", 0.99), ("alerts", 1)]:
        modified = copy.deepcopy(report)
        modified["candidate"][field] = value
        with pytest.raises(ValueError):
            validate_official_comparison(modified)
