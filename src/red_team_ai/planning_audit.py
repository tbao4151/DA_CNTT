"""Bounded in-memory audit of non-executing Red Team scenario proposals.

Records reproducible policy decisions and unverified operator observations.
No traffic, subprocess, VMware control, labels or SOC writes.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta

from .scenario_policy import MAX_FEEDBACK, SCENARIOS, choose_scenario

MAX_PROPOSALS = min(MAX_FEEDBACK, 1000)
_IDS = frozenset(s.scenario_id for s in SCENARIOS)
_PROPOSAL_KEYS = frozenset({
    "sequence", "kind", "proposal_id", "scenario_id", "strategy", "seed",
    "recorded_at_utc", "execution_enabled", "network_access",
})
_FEEDBACK_KEYS = frozenset({
    "sequence", "kind", "proposal_id", "scenario_id", "blue_flagged",
    "recorded_at_utc", "verified",
})


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Expected bounded UTC event timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("Invalid UTC event timestamp") from exc
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("Event timestamp must include UTC offset")
    return parsed


def _replay(events: Sequence[Mapping[str, object]]) -> tuple[list[dict[str, object]], int | None]:
    if not isinstance(events, (list, tuple)) or len(events) > 2 * MAX_PROPOSALS:
        raise ValueError("Offline audit must be a bounded list")
    feedback: list[dict[str, object]] = []
    pending: int | None = None
    last_time: datetime | None = None
    proposal_count = 0
    proposal_scenario = ""
    for sequence, event in enumerate(events, start=1):
        if not isinstance(event, Mapping) or event.get("sequence") != sequence or type(event.get("sequence")) is not int:
            raise ValueError("Invalid offline audit sequence")
        stamp = _timestamp(event.get("recorded_at_utc"))
        if last_time is not None and stamp < last_time:
            raise ValueError("Offline audit timestamps are out of order")
        last_time = stamp
        if event.get("kind") == "proposal":
            if set(event) != _PROPOSAL_KEYS or pending is not None:
                raise ValueError("Invalid or overlapping offline proposal")
            if proposal_count >= MAX_PROPOSALS or type(event["proposal_id"]) is not int or event["proposal_id"] != proposal_count + 1:
                raise ValueError("Invalid proposal ID")
            if event["scenario_id"] not in _IDS or event["execution_enabled"] is not False or event["network_access"] is not False:
                raise ValueError("Executable or unknown proposal refused")
            if event["strategy"] not in ("ucb1", "random") or type(event["seed"]) is not int or not 0 <= event["seed"] <= 1_000_000:
                raise ValueError("Invalid offline policy configuration")
            expected = choose_scenario(feedback, strategy=event["strategy"], seed=event["seed"])
            if event["scenario_id"] != expected["scenario_id"]:
                raise ValueError("Proposal does not match reproducible policy")
            proposal_count += 1
            pending = proposal_count
            proposal_scenario = event["scenario_id"]
        elif event.get("kind") == "manual_feedback":
            if set(event) != _FEEDBACK_KEYS or pending is None:
                raise ValueError("Unlinked or duplicate operator feedback")
            if type(event["proposal_id"]) is not int or event["proposal_id"] != pending or event["scenario_id"] != proposal_scenario:
                raise ValueError("Feedback does not match pending proposal")
            if type(event["blue_flagged"]) is not bool or event["verified"] is not False:
                raise ValueError("Feedback must remain unverified binary observation")
            feedback.append({"scenario_id": proposal_scenario, "blue_flagged": event["blue_flagged"]})
            pending = None
        else:
            raise ValueError("Unsupported offline audit event")
    return feedback, pending


def extract_manual_feedback(events: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    """Derive the exact operator-feedback sequence used by UCB1/random."""
    return _replay(events)[0]


def append_proposal(
    events: Sequence[Mapping[str, object]], plan: Mapping[str, object],
    *, seed: int, recorded_at_utc: str,
) -> list[dict[str, object]]:
    """Append a reproducible non-executing proposal, never an executed action."""
    feedback, pending = _replay(events)
    if pending is not None:
        raise ValueError("Resolve the pending proposal before selecting another")
    if not isinstance(plan, Mapping) or plan.get("execution_enabled") is not False or plan.get("network_access") is not False:
        raise ValueError("Only non-executing offline plans are accepted")
    strategy = plan.get("strategy")
    expected = choose_scenario(feedback, strategy=strategy, seed=seed)
    if dict(plan) != expected:
        raise ValueError("Plan differs from the reproducible policy decision")
    proposals = sum(event["kind"] == "proposal" for event in events)
    if proposals >= MAX_PROPOSALS:
        raise ValueError("Offline proposal limit reached")
    result = [dict(event) for event in events]
    result.append({
        "sequence": len(result) + 1, "kind": "proposal",
        "proposal_id": proposals + 1, "scenario_id": expected["scenario_id"],
        "strategy": strategy, "seed": seed,
        "recorded_at_utc": recorded_at_utc,
        "execution_enabled": False, "network_access": False,
    })
    _replay(result)
    return result


def append_manual_feedback(
    events: Sequence[Mapping[str, object]], *, proposal_id: int,
    blue_flagged: bool, recorded_at_utc: str,
) -> list[dict[str, object]]:
    """Link a single explicitly unverified observation to its proposed plan."""
    _, pending = _replay(events)
    if pending is None or type(proposal_id) is not int or proposal_id != pending:
        raise ValueError("No matching pending offline proposal")
    if type(blue_flagged) is not bool:
        raise ValueError("Operator feedback must be a boolean")
    result = [dict(event) for event in events]
    result.append({
        "sequence": len(result) + 1, "kind": "manual_feedback",
        "proposal_id": pending, "scenario_id": result[-1]["scenario_id"],
        "blue_flagged": blue_flagged, "recorded_at_utc": recorded_at_utc,
        "verified": False,
    })
    _replay(result)
    return result


def export_planning_audit(events: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Export bounded in-memory chronology without private network metadata."""
    feedback, pending = _replay(events)
    return {
        "audit_version": 1,
        "mode": "offline_red_team_scenario_planning_only",
        "feedback_origin": "operator_entered_unverified",
        "proposals": sum(event["kind"] == "proposal" for event in events),
        "manual_feedback_count": len(feedback),
        "pending_proposal_id": pending,
        "execution_enabled": False,
        "network_access": False,
        "blue_team_outcomes_verified": False,
        "attack_detection_measured": False,
        "events": [dict(event) for event in events],
    }
