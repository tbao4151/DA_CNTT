import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.thresholds import threshold_diagnostics


def test_threshold_tradeoffs_and_counts():
    labels = [1, 1, 0, 0]
    probabilities = [0.9, 0.6, 0.7, 0.2]
    result = threshold_diagnostics(labels, probabilities, [0.5, 0.8])
    low, high = result.to_dict("records")
    assert (low["true_positive"], low["false_positive"], low["true_negative"], low["false_negative"]) == (2, 1, 1, 0)
    assert (high["true_positive"], high["false_positive"], high["true_negative"], high["false_negative"]) == (1, 0, 2, 1)
    assert high["false_positive_rate"] == 0
    assert low["recall_attack"] == 1
    assert high["alerts"] == 1


@pytest.mark.parametrize("labels, scores, levels", [
    ([], [], [0.5]),
    ([0, 2], [0.2, 0.3], [0.5]),
    ([0], [float("nan")], [0.5]),
    ([0], [1.2], [0.5]),
    ([0], [0.2], []),
    ([0], [0.2], [-0.1]),
    ([0, 1], [0.2], [0.5]),
])
def test_invalid_inputs_are_rejected(labels, scores, levels):
    with pytest.raises(ValueError):
        threshold_diagnostics(labels, scores, levels)


def test_zero_positive_and_zero_negative_cases():
    no_attacks = threshold_diagnostics([0, 0], [0.1, 0.2])
    assert no_attacks.iloc[0]["recall_attack"] == 0
    all_attacks = threshold_diagnostics([1, 1], [0.8, 0.9])
    assert all_attacks.iloc[0]["false_positive_rate"] == 0
