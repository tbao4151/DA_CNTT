"""Synthetic-only Red Team offline planner regression tests."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from red_team_ai.scenario_policy import SCENARIOS, choose_scenario, summarize_feedback


def test_catalog_is_immutable_and_non_executable():
    assert len(SCENARIOS) == 3
    assert len({s.scenario_id for s in SCENARIOS}) == len(SCENARIOS)
    assert all(s.objective and s.category for s in SCENARIOS)
    with pytest.raises(Exception):
        SCENARIOS[0].title = "changed"


def test_ucb1_explores_all_catalog_items_before_exploitation():
    history = []
    selected = []
    for _ in SCENARIOS:
        plan = choose_scenario(history)
        selected.append(plan["scenario_id"])
        history.append({"scenario_id": plan["scenario_id"], "blue_flagged": True})
        assert plan["execution_enabled"] is False
        assert plan["network_access"] is False
    assert selected == [s.scenario_id for s in SCENARIOS]


def test_ucb1_prefers_unflagged_after_balanced_observations():
    history = [
        {"scenario_id": "baseline_web", "blue_flagged": True},
        {"scenario_id": "dns_variation", "blue_flagged": False},
        {"scenario_id": "connection_shift", "blue_flagged": True},
    ]
    assert choose_scenario(history)["scenario_id"] == "dns_variation"
    summary = summarize_feedback(history)
    assert summary["origin"] == "operator_entered_unverified"
    assert summary["scenarios"][1]["unflagged_fraction"] == 1.0
    assert json.loads(json.dumps(summary)) == summary


def test_seeded_random_is_reproducible_and_non_executing():
    p1 = choose_scenario([], strategy="random", seed=123)
    p2 = choose_scenario([], strategy="random", seed=123)
    assert p1 == p2
    assert p1["execution_enabled"] is False
    assert p1["feedback_origin"] == "operator_entered_unverified"


@pytest.mark.parametrize("history", [
    None, "bad", {}, [{"scenario_id": "baseline_web"}],
    [{"scenario_id": "baseline_web", "blue_flagged": 1}],
    [{"scenario_id": "other", "blue_flagged": False}],
    [{"scenario_id": "baseline_web", "blue_flagged": True, "command": "ping"}],
    [{"scenario_id": "baseline_web", "blue_flagged": "false"}],
])
def test_bad_feedback_fails_closed(history):
    with pytest.raises(ValueError):
        choose_scenario(history)


@pytest.mark.parametrize("strategy,seed", [("other", 42), ("ucb1", -1), ("random", True), ("random", 1_000_001)])
def test_invalid_strategy_and_seed_fail_closed(strategy, seed):
    with pytest.raises(ValueError):
        choose_scenario([], strategy=strategy, seed=seed)


def test_red_team_page_starts_with_execution_disabled():
    from streamlit.testing.v1 import AppTest

    page = Path(__file__).resolve().parents[1] / "pages/2_Red_Team_Lab.py"
    app = AppTest.from_file(str(page), default_timeout=45).run()
    assert not app.exception, [str(e.message) for e in app.exception]
    assert any("Red Team Lab" in t.value for t in app.title)
    assert any("TẮT" in str(metric.value) for metric in app.metric)
    assert not app.session_state["red_team_feedback"]
