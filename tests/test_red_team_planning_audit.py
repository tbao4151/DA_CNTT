"""Offline-only Red Team policy chronology contract, no traffic or real labels."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from red_team_ai.planning_audit import (
    append_manual_feedback, append_proposal, export_planning_audit,
    extract_manual_feedback,
)
from red_team_ai.scenario_policy import choose_scenario

T0 = "2026-10-29T02:00:00+00:00"
T1 = "2026-10-29T02:01:00+00:00"
T2 = "2026-10-29T02:02:00+00:00"


def _propose(events=None, *, strategy="ucb1", seed=42, timestamp=T0):
    events = [] if events is None else events
    plan = choose_scenario(extract_manual_feedback(events), strategy=strategy, seed=seed)
    return append_proposal(events, plan, seed=seed, recorded_at_utc=timestamp)


def test_linked_feedback_drives_reproducible_next_policy_and_safe_export():
    events = _propose()
    assert events[0]["scenario_id"] == "baseline_web"
    events = append_manual_feedback(events, proposal_id=1, blue_flagged=True, recorded_at_utc=T1)
    assert extract_manual_feedback(events) == [{"scenario_id": "baseline_web", "blue_flagged": True}]
    events = _propose(events, strategy="ucb1", timestamp=T2)
    assert events[-1]["scenario_id"] == "dns_variation"
    report = export_planning_audit(events)
    assert report["proposals"] == 2
    assert report["manual_feedback_count"] == 1
    assert report["pending_proposal_id"] == 2
    assert report["execution_enabled"] is False
    assert report["network_access"] is False
    assert report["blue_team_outcomes_verified"] is False
    assert json.loads(json.dumps(report)) == report
    assert "192.168." not in json.dumps(report)


def test_random_proposal_seed_is_audited_and_replayable():
    events = _propose(strategy="random", seed=987)
    assert events[0]["seed"] == 987
    assert events[0]["scenario_id"] == choose_scenario([], strategy="random", seed=987)["scenario_id"]
    assert export_planning_audit(events)["events"] == events


def test_cannot_propose_twice_without_linked_feedback():
    events = _propose()
    with pytest.raises(ValueError, match="pending"):
        _propose(events)
    with pytest.raises(ValueError, match="pending"):
        append_manual_feedback(events, proposal_id=2, blue_flagged=True, recorded_at_utc=T1)


@pytest.mark.parametrize("bad", [1, "true", None])
def test_non_boolean_feedback_refused(bad):
    with pytest.raises(ValueError, match="boolean"):
        append_manual_feedback(_propose(), proposal_id=1, blue_flagged=bad, recorded_at_utc=T1)


def test_duplicate_feedback_and_unlinked_observation_refused():
    events = append_manual_feedback(_propose(), proposal_id=1, blue_flagged=False, recorded_at_utc=T1)
    with pytest.raises(ValueError):
        append_manual_feedback(events, proposal_id=1, blue_flagged=True, recorded_at_utc=T2)
    forged = [*events, dict(events[-1], sequence=3)]
    with pytest.raises(ValueError):
        export_planning_audit(forged)


def test_rejects_forged_policy_decision_or_executable_plan():
    plan = choose_scenario([])
    with pytest.raises(ValueError, match="Plan differs"):
        append_proposal([], dict(plan, scenario_id="dns_variation"), seed=42, recorded_at_utc=T0)
    with pytest.raises(ValueError, match="non-executing"):
        append_proposal([], dict(plan, network_access=True), seed=42, recorded_at_utc=T0)
    events = _propose()
    forged = [dict(events[0], scenario_id="dns_variation")]
    with pytest.raises(ValueError, match="policy"):
        export_planning_audit(forged)


def test_rejects_forged_verified_feedback_and_untrusted_fields():
    events = append_manual_feedback(_propose(), proposal_id=1, blue_flagged=True, recorded_at_utc=T1)
    with pytest.raises(ValueError, match="unverified"):
        export_planning_audit([events[0], dict(events[1], verified=True)])
    with pytest.raises(ValueError):
        export_planning_audit([dict(events[0], command="curl example.com"), events[1]])
    with pytest.raises(ValueError):
        export_planning_audit([dict(events[0], network_access=True), events[1]])


def test_utc_order_and_sequence_are_required():
    with pytest.raises(ValueError, match="UTC"):
        _propose(timestamp="2026-10-29T09:00:00")
    events = _propose()
    with pytest.raises(ValueError, match="out of order"):
        append_manual_feedback(events, proposal_id=1, blue_flagged=False, recorded_at_utc="2026-10-29T01:59:00+00:00")
    with pytest.raises(ValueError, match="sequence"):
        export_planning_audit([dict(events[0], sequence=True)])


def test_history_is_not_mutated_by_append():
    initial = _propose()
    snapshot = json.dumps(initial)
    later = append_manual_feedback(initial, proposal_id=1, blue_flagged=False, recorded_at_utc=T1)
    assert json.dumps(initial) == snapshot
    assert len(later) == 2
