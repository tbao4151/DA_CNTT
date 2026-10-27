"""Synthetic-only host-group diagnostics, not measured lab performance."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from blue_team_ai.host_variability import summarize_host_variability


def test_host_group_confusion_and_macro_range():
    result = summarize_host_variability(
        [1, 0, 1, 0, 1, 0],
        [0.9, 0.7, 0.2, 0.1, 0.8, 0.3],
        ["B", "B", "B", "B", "A", "A"],
        0.5,
    )
    assert result["group_count"] == 2
    assert result["single_group_warning"] is False
    assert result["groups"][0]["support"] == 2
    assert result["groups"][0]["tp"] == 1
    assert result["groups"][0]["tn"] == 1
    assert result["groups"][1]["tp"] == 1
    assert result["groups"][1]["fp"] == 1
    assert result["groups"][1]["tn"] == 1
    assert result["groups"][1]["fn"] == 1
    assert result["rate_ranges"]["attack_recall"]["min"] == 0.5
    assert result["rate_ranges"]["attack_recall"]["max"] == 1.0
    assert result["rate_ranges"]["false_positive_rate"]["macro_mean"] == 0.25
    assert {key: sum(row[key] for row in result["groups"]) for key in ("tp", "fp", "tn", "fn")} == {
        "tp": 2, "fp": 1, "tn": 2, "fn": 1,
    }
    serialized = json.dumps(result, allow_nan=False)
    assert '"A"' not in serialized and '"B"' not in serialized


def test_undefined_denominators_are_null_and_single_group_warns():
    result = summarize_host_variability([1, 1], [0.1, 0.2], ["host-private"] * 2, 0.5)
    row = result["groups"][0]
    assert row["attack_precision"] is None
    assert row["attack_recall"] == 0
    assert row["false_positive_rate"] is None
    assert result["rate_ranges"]["false_positive_rate"]["defined_groups"] == 0
    assert result["rate_ranges"]["false_positive_rate"]["macro_mean"] is None
    assert result["single_group_warning"] is True
    assert "host-private" not in json.dumps(result, allow_nan=False)


def test_threshold_is_fixed_and_boundary_inclusive():
    result = summarize_host_variability([1, 0], [0.5, 0.5], ["one", "one"], 0.5)
    assert result["groups"][0]["tp"] == 1
    assert result["groups"][0]["fp"] == 1


@pytest.mark.parametrize("labels,probs,groups,threshold", [
    ([], [], [], 0.5),
    ([0], [], ["host"], 0.5),
    ([0], [0.5], [], 0.5),
    ([True], [0.5], ["host"], 0.5),
    ([2], [0.5], ["host"], 0.5),
    ([0], [float("nan")], ["host"], 0.5),
    ([0], [float("inf")], ["host"], 0.5),
    ([0], [1.1], ["host"], 0.5),
    ([0], [True], ["host"], 0.5),
    ([0], [0.5], [""], 0.5),
    ([0], [0.5], [" host"], 0.5),
    ([0], [0.5], ["host\nnewline"], 0.5),
    ([0], [0.5], ["host"], 0),
    ([0], [0.5], ["host"], 1),
    ([0], [0.5], ["host"], True),
])
def test_invalid_inputs_fail_closed(labels, probs, groups, threshold):
    with pytest.raises(ValueError):
        summarize_host_variability(labels, probs, groups, threshold)
