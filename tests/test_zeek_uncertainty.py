"""Synthetic-only Wilson interval tests; not measured Cyber Lab detection."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from blue_team_ai.uncertainty import summarize_detection_uncertainty, wilson_interval


def test_wilson_known_half_successes():
    result = wilson_interval(5, 10)
    assert result["estimate"] == 0.5
    assert result["lower"] == pytest.approx(0.2365930905, abs=1e-8)
    assert result["upper"] == pytest.approx(0.7634069095, abs=1e-8)


def test_wilson_extreme_counts_have_nonzero_uncertainty():
    none = wilson_interval(0, 10)
    all_ = wilson_interval(10, 10)
    assert none["estimate"] == 0
    assert none["lower"] == 0
    assert 0 < none["upper"] < 1
    assert all_["estimate"] == 1
    assert 0 < all_["lower"] < 1
    assert all_["upper"] == 1


def test_zero_denominator_is_null_not_false_precision():
    result = wilson_interval(0, 0)
    assert result["estimate"] is None
    assert result["lower"] is None
    assert result["upper"] is None
    assert json.dumps(result, allow_nan=False)


def test_confusion_counts_map_to_correct_denominators():
    result = summarize_detection_uncertainty({
        "tp": 8, "fp": 2, "tn": 18, "fn": 2, "support": 30,
    })
    assert result["attack_precision"]["trials"] == 10
    assert result["attack_precision"]["estimate"] == 0.8
    assert result["attack_recall"]["trials"] == 10
    assert result["attack_recall"]["estimate"] == 0.8
    assert result["false_positive_rate"]["trials"] == 20
    assert result["false_positive_rate"]["estimate"] == 0.1
    assert result["small_denominator_warning"] is True
    assert "no_host_cluster_adjustment" in result["interpretation"]
    assert json.dumps(result, allow_nan=False)


def test_no_alerts_precision_is_undefined():
    result = summarize_detection_uncertainty({
        "tp": 0, "fp": 0, "tn": 40, "fn": 10, "support": 50,
    })
    assert result["attack_precision"]["estimate"] is None
    assert result["attack_recall"]["estimate"] == 0
    assert result["false_positive_rate"]["estimate"] == 0


@pytest.mark.parametrize("successes,trials", [
    (-1, 2), (3, 2), (0, -1), (True, 1), (0, True), (1.0, 2),
])
def test_invalid_binomial_counts_rejected(successes, trials):
    with pytest.raises(ValueError):
        wilson_interval(successes, trials)


@pytest.mark.parametrize("metrics", [
    {"tp": 1, "fp": 0, "tn": 0, "fn": 0, "support": 0},
    {"tp": 1, "fp": 0, "tn": 0, "fn": 0, "support": 2},
    {"tp": True, "fp": 0, "tn": 0, "fn": 0, "support": 1},
    {"tp": -1, "fp": 0, "tn": 0, "fn": 0, "support": -1},
    {"tp": 0, "fp": 0, "tn": 0, "support": 0},
])
def test_invalid_confusion_matrix_rejected(metrics):
    with pytest.raises(ValueError):
        summarize_detection_uncertainty(metrics)


def test_large_count_intervals_remain_finite_and_bounded():
    result = wilson_interval(500_000, 1_000_000)
    assert 0 < result["lower"] < 0.5 < result["upper"] < 1
