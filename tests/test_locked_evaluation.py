"""Ensure threshold evaluation is fixed before test labels are inspected."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from siem_ai.locked_evaluation import evaluate_locked_threshold


def selection(threshold=0.55):
    return {
        "selection_source": "UNSW-NB15 official training split only",
        "source_run_id": 40366465257,
        "threshold": threshold,
    }


def test_locked_threshold_comparison():
    # Candidate 0.55 removes one false alarm but misses one extra attack.
    labels = [1, 1, 0, 0]
    probabilities = [0.9, 0.52, 0.53, 0.1]
    result = evaluate_locked_threshold(labels, probabilities, selection())
    assert result["baseline"]["false_positive"] == 1
    assert result["candidate"]["false_positive"] == 0
    assert result["baseline"]["false_negative"] == 0
    assert result["candidate"]["false_negative"] == 1
    assert result["delta_false_positive_candidate_minus_baseline"] == -1
    assert result["delta_false_negative_candidate_minus_baseline"] == 1
    assert result["candidate_threshold"] == 0.55
    assert result["validation_selection_run_id"] == 40366465257


@pytest.mark.parametrize("bad", [
    {},
    {"threshold": 0.55, "source_run_id": 40366465257, "selection_source": "test"},
    selection(float("nan")),
    selection(-0.1),
    selection(True),
    {"threshold": 0.55, "selection_source": "UNSW-NB15 official training split only"},
])
def test_invalid_selection_rejected(bad):
    with pytest.raises(ValueError):
        evaluate_locked_threshold([1, 0], [0.9, 0.1], bad)


def test_invalid_probabilities_rejected():
    with pytest.raises(ValueError):
        evaluate_locked_threshold([1, 0], [1.1, 0.2], selection())
