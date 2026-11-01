"""Synthetic-only threshold-free ranking metrics; no VMware or verified labels."""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.ranking_metrics import summarize_binary_ranking


def test_tied_score_groups_are_not_broken_by_input_order():
    scores = [0.9, 0.8, 0.8, 0.1]
    labels = [1, 0, 1, 0]
    result = summarize_binary_ranking(scores, labels)
    assert math.isclose(result["roc_auc"], 0.875)
    assert math.isclose(result["average_precision"], (1 + 2 / 3) / 2)
    assert result["positive_prevalence"] == 0.5
    assert result["tied_score_groups"] == 1
    assert result["threshold_selection_performed"] is False
    assert result == summarize_binary_ranking(
        list(reversed(scores)), list(reversed(labels))
    )


def test_all_equal_scores_have_chance_auc_and_prevalence_average_precision():
    result = summarize_binary_ranking([0.5] * 5, [1, 0, 0, 1, 0])
    assert result["roc_auc"] == 0.5
    assert result["average_precision"] == 2 / 5
    assert result["positive_prevalence"] == 2 / 5
    assert result["tied_score_groups"] == 1


@pytest.mark.parametrize(("labels", "expected_ap"), [
    ([0, 0], None),
    ([1, 1], 1.0),
    ([0], None),
    ([1], 1.0),
])
def test_single_class_has_undefined_auc(labels, expected_ap):
    result = summarize_binary_ranking([0.5] * len(labels), labels)
    assert result["roc_auc"] is None
    assert result["average_precision"] == expected_ap
    assert result["positive_support"] == sum(labels)
    assert result["negative_support"] == len(labels) - sum(labels)


def test_perfect_and_reversed_ranking():
    assert summarize_binary_ranking(
        [0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0],
    )["roc_auc"] == 1.0
    reversed_result = summarize_binary_ranking(
        [0.1, 0.2, 0.8, 0.9], [1, 1, 0, 0],
    )
    assert reversed_result["roc_auc"] == 0.0
    assert math.isclose(reversed_result["average_precision"], (1 / 3 + 2 / 4) / 2)


@pytest.mark.parametrize(("scores", "labels"), [
    ([], []),
    ([0.1], []),
    ([True], [1]),
    ([float("nan")], [1]),
    ([float("inf")], [1]),
    ([-0.1], [0]),
    ([1.1], [0]),
    (["0.5"], [1]),
    ([0.5], [True]),
    ([0.5], [2]),
    ([0.5], [0.0]),
])
def test_malformed_inputs_fail_closed(scores, labels):
    with pytest.raises(ValueError):
        summarize_binary_ranking(scores, labels)
