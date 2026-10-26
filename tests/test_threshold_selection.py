"""Regression tests for validation-only threshold policy."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.threshold_selection import select_threshold


def test_minimizes_false_positives_with_recall_constraint():
    # At 0.5: TP=2, FP=1; at 0.8: TP=1, FP=0.
    labels = [1, 1, 0, 0]
    scores = [0.95, 0.65, 0.7, 0.1]
    selected = select_threshold(labels, scores, min_recall=0.5, candidates=[0.5, 0.8])
    assert selected["threshold"] == 0.8
    assert selected["validation_metrics"]["false_positive"] == 0
    assert selected["validation_metrics"]["recall_attack"] == 0.5


def test_recall_constraint_rejects_high_threshold():
    selected = select_threshold([1, 1, 0, 0], [0.95, 0.65, 0.7, 0.1],
                                min_recall=1.0, candidates=[0.5, 0.8])
    assert selected["threshold"] == 0.5


def test_infeasible_recall_raises():
    with pytest.raises(ValueError, match="No candidate"):
        select_threshold([1, 0], [0.1, 0.9], min_recall=1.0, candidates=[0.5, 0.8])


@pytest.mark.parametrize("labels, scores, recall", [
    ([0, 0], [0.1, 0.2], 0.95),
    ([1, 1], [0.8, 0.9], 0.95),
    ([1, 0], [0.8, 0.1], 0),
    ([1, 0], [0.8, 0.1], float("nan")),
    ([1, 0], [float("inf"), 0.1], 0.95),
])
def test_invalid_validation_inputs(labels, scores, recall):
    with pytest.raises(ValueError):
        select_threshold(labels, scores, min_recall=recall)
