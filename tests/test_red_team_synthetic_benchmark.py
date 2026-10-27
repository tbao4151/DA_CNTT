"""Synthetic-only policy-comparison regression checks; no real attacks."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from red_team_ai.synthetic_benchmark import compare_synthetic_policies


def test_reproducible_and_json_safe():
    first = compare_synthetic_policies(rounds=20, trials=3, seed=17)
    second = compare_synthetic_policies(rounds=20, trials=3, seed=17)
    assert first == second
    assert json.loads(json.dumps(first, allow_nan=False)) == first
    assert first["origin"] == "synthetic_bernoulli_not_blue_team_evidence"
    assert first["execution_enabled"] is False and first["network_access"] is False
    assert first["common_random_numbers"] is True
    assert "not observed attacks" in first["interpretation_warning"]


def test_counts_regret_and_paired_trial_shape():
    result = compare_synthetic_policies(rounds=25, trials=4, seed=4)
    for name in ("ucb1", "random"):
        policy = result["policies"][name]
        assert len(policy["trials"]) == 4
        assert sum(policy["selection_counts"].values()) == 100
        assert 0 <= policy["mean_synthetic_unflagged_fraction"] <= 1
        assert 0 <= policy["mean_expected_pseudo_regret"] <= 25
        assert all(0 <= row["synthetic_unflagged"] <= 25 for row in policy["trials"])
    assert result["synthetic_unflagged_probabilities"]["connection_shift"] == 0.70


@pytest.mark.parametrize("kwargs", [
    {"rounds": 2}, {"rounds": 501}, {"rounds": True}, {"rounds": 3.0},
    {"trials": 1}, {"trials": 41}, {"trials": False},
    {"seed": -1}, {"seed": 1_000_001}, {"seed": True},
])
def test_invalid_limits_fail_closed(kwargs):
    with pytest.raises(ValueError):
        compare_synthetic_policies(**kwargs)


def test_policies_can_differ_without_claiming_real_outcomes():
    report = compare_synthetic_policies(rounds=150, trials=8, seed=42)
    assert report["policies"]["ucb1"]["mean_expected_pseudo_regret"] < report["policies"]["random"]["mean_expected_pseudo_regret"]
