"""Regression checks for read-only multi-dimensional SOC hunting filters."""
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.hunting import filter_hunting_flows


def flows():
    return pd.DataFrame(
        {
            "proto": ["tcp", "udp", "tcp", "tcp", "udp"],
            "service": ["http", "dns", "http", None, "dns"],
            "state": ["FIN", "CON", "INT", "FIN", "CON"],
            "AI_verdict": ["Attack", "Normal", "Attack", "Normal", "Attack"],
            "AI_attack_probability": [0.94, 0.10, 0.83, 0.40, float("nan")],
        },
        index=[20, 21, 22, 23, 24],
    )


def test_filters_combine_and_across_dimensions_and_or_within():
    data = flows()
    original = data.copy(deep=True)
    result = filter_hunting_flows(
        data, protocols=["tcp", "udp"], services=["http", "dns"],
        states=["FIN", "INT"], only_ai_attacks=True,
        min_attack_probability=0.85,
    )
    assert result.index.tolist() == [20]
    pd.testing.assert_frame_equal(data, original)


def test_no_filters_preserve_all_rows_and_index_without_aliasing():
    data = flows()
    result = filter_hunting_flows(data)
    pd.testing.assert_frame_equal(data, result)
    result.loc[20, "proto"] = "changed"
    assert data.loc[20, "proto"] == "tcp"


def test_null_categories_and_nan_scores_do_not_match():
    data = flows()
    assert filter_hunting_flows(data, services=["http"]).index.tolist() == [20, 22]
    assert filter_hunting_flows(data, min_attack_probability=0.8).index.tolist() == [20, 22]
    assert filter_hunting_flows(data, protocols=["icmp"]).empty


def test_unlabeled_csv_without_ai_columns_can_still_be_hunted():
    data = flows().drop(columns=["AI_verdict", "AI_attack_probability"])
    assert filter_hunting_flows(data, states=["CON"]).index.tolist() == [21, 24]
    with pytest.raises(ValueError, match="AI predictions"):
        filter_hunting_flows(data, only_ai_attacks=True)
    with pytest.raises(ValueError, match="AI probabilities"):
        filter_hunting_flows(data, min_attack_probability=0.7)


@pytest.mark.parametrize("invalid", [-0.1, 1.1, float("nan"), float("inf"), "0.8"])
def test_invalid_probability_threshold_is_rejected(invalid):
    with pytest.raises(ValueError, match="probability"):
        filter_hunting_flows(flows(), min_attack_probability=invalid)


def test_missing_selected_category_is_rejected():
    with pytest.raises(ValueError, match="Missing filter column"):
        filter_hunting_flows(flows().drop(columns=["state"]), states=["FIN"])
