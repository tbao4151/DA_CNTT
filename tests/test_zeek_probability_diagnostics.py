"""Synthetic-only probability diagnostics; not genuine Zeek performance."""
import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from blue_team_ai.probability_diagnostics import summarize_probability_quality


def test_perfect_probabilities_have_zero_brier_and_ece():
    report = summarize_probability_quality([0, 0, 1, 1], [0.0, 0.0, 1.0, 1.0])
    assert report["brier_score"] == 0.0
    assert report["expected_calibration_error"] == 0.0
    assert report["attack_prevalence"] == 0.5
    assert [b["count"] for b in report["reliability_bins"]] == [2, 0, 0, 0, 2]
    assert report["reliability_bins"][1]["observed_attack_rate"] is None
    assert report["reliability_bins"][-1]["upper_inclusive"] is True
    assert report["small_sample_warning"] is True


def test_known_brier_and_ece_values_and_bin_boundaries():
    report = summarize_probability_quality([0, 1], [0.2, 0.8])
    assert report["brier_score"] == pytest.approx(0.04)
    assert report["expected_calibration_error"] == pytest.approx(0.2)
    assert [b["count"] for b in report["reliability_bins"]] == [0, 1, 0, 0, 1]
    assert report["reliability_bins"][1]["mean_predicted_probability"] == pytest.approx(0.2)
    assert report["reliability_bins"][4]["observed_attack_rate"] == 1.0


def test_worst_possible_probabilities_have_unit_brier_and_ece():
    report = summarize_probability_quality([1, 0], [0.0, 1.0])
    assert report["brier_score"] == 1.0
    assert report["expected_calibration_error"] == 1.0


@pytest.mark.parametrize("labels,scores", [
    ([], []),
    ([0], []),
    ([True], [0.2]),
    ([2], [0.2]),
    ([0], [float("nan")]),
    ([1], [float("inf")]),
    ([0], [-0.01]),
    ([1], [1.01]),
    ([1], [True]),
    ([1], [[0.5]]),
])
def test_rejects_invalid_probability_inputs(labels, scores):
    with pytest.raises(ValueError):
        summarize_probability_quality(labels, scores)


@pytest.mark.parametrize("bins", [True, 1, 21, 3.0])
def test_rejects_invalid_bin_configuration(bins):
    with pytest.raises(ValueError, match="bin count"):
        summarize_probability_quality([0, 1], [0.1, 0.9], bins=bins)


def test_output_is_json_safe_and_does_not_expose_individual_scores():
    import json
    report = summarize_probability_quality([0, 1], [0.23456789, 0.76543211])
    serialized = json.dumps(report, allow_nan=False)
    assert "0.23456789" not in serialized
    assert len(report["reliability_bins"]) == 5
