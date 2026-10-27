"""Bounded offline scenario selector; never generates traffic or runs commands.

A scenario is a planning label, NOT an executable attack. The feedback here is
operator-entered and cannot be used as verified detection ground truth.
"""
from __future__ import annotations

import math
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

MAX_FEEDBACK = 10000


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    objective: str
    category: str


# Immutable catalog: all choices are non-executable, offline-only plans.
SCENARIOS = (
    Scenario("baseline_web", "Web baseline", "Inspect ordinary web-flow patterns from authorized offline fixtures.", "baseline"),
    Scenario("dns_variation", "DNS variation", "Review changes in DNS-flow distribution in a synthetic or authorized replay.", "variation"),
    Scenario("connection_shift", "Connection pattern shift", "Compare bounded connection-pattern changes in offline flow fixtures.", "variation"),
)
_BY_ID = {scenario.scenario_id: scenario for scenario in SCENARIOS}


def _validated_feedback(feedback: Sequence[Mapping[str, object]]) -> list[tuple[str, bool]]:
    if isinstance(feedback, (str, bytes, Mapping)) or not isinstance(feedback, (list, tuple)):
        raise ValueError("Feedback must be a list or tuple")
    if len(feedback) > MAX_FEEDBACK:
        raise ValueError("Feedback exceeds offline planning limit")
    validated = []
    for item in feedback:
        if not isinstance(item, Mapping) or set(item) != {"scenario_id", "blue_flagged"}:
            raise ValueError("Feedback schema must contain scenario_id and blue_flagged only")
        scenario_id, blue_flagged = item["scenario_id"], item["blue_flagged"]
        if not isinstance(scenario_id, str) or scenario_id not in _BY_ID or type(blue_flagged) is not bool:
            raise ValueError("Unknown scenario or invalid binary feedback")
        validated.append((scenario_id, blue_flagged))
    return validated


def summarize_feedback(feedback: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Summarize operator-entered feedback; not validated AI performance."""
    rows = _validated_feedback(feedback)
    counts = {scenario.scenario_id: 0 for scenario in SCENARIOS}
    unflagged = {scenario.scenario_id: 0 for scenario in SCENARIOS}
    for scenario_id, blue_flagged in rows:
        counts[scenario_id] += 1
        unflagged[scenario_id] += int(not blue_flagged)
    return {
        "origin": "operator_entered_unverified",
        "total": len(rows),
        "scenarios": [
            {
                "scenario_id": scenario.scenario_id,
                "observations": counts[scenario.scenario_id],
                "unflagged": unflagged[scenario.scenario_id],
                "unflagged_fraction": (
                    unflagged[scenario.scenario_id] / counts[scenario.scenario_id]
                    if counts[scenario.scenario_id] else None
                ),
            }
            for scenario in SCENARIOS
        ],
    }


def choose_scenario(
    feedback: Sequence[Mapping[str, object]], *, strategy: str = "ucb1", seed: int = 42
) -> dict[str, object]:
    """Choose a label using UCB1 or seeded random baseline; never execute it.

    UCB1 reward is the operator's 'Blue Team did not flag' observation. This is
    an exploration aid only; no genuine attack, detection, or outcome is implied.
    """
    if strategy not in ("ucb1", "random"):
        raise ValueError("Unsupported offline planning strategy")
    if type(seed) is not int or not 0 <= seed <= 1_000_000:
        raise ValueError("Invalid random seed")
    rows = _validated_feedback(feedback)
    counts = {s.scenario_id: 0 for s in SCENARIOS}
    rewards = {s.scenario_id: 0 for s in SCENARIOS}
    for scenario_id, flagged in rows:
        counts[scenario_id] += 1
        rewards[scenario_id] += int(not flagged)
    if strategy == "random":
        selected = random.Random(seed).choice(SCENARIOS)
        rationale = "Seeded random baseline (not an attack or network operation)."
    else:
        untried = [s for s in SCENARIOS if counts[s.scenario_id] == 0]
        if untried:
            selected = untried[0]
            rationale = "UCB1 exploration: first unobserved catalog scenario."
        else:
            total = len(rows)
            selected = max(
                SCENARIOS,
                key=lambda s: (
                    rewards[s.scenario_id] / counts[s.scenario_id]
                    + math.sqrt(2.0 * math.log(total) / counts[s.scenario_id]),
                    -SCENARIOS.index(s),
                ),
            )
            rationale = "UCB1 exploration/exploitation on unverified operator feedback."
    return {
        "scenario_id": selected.scenario_id,
        "title": selected.title,
        "objective": selected.objective,
        "strategy": strategy,
        "rationale": rationale,
        "feedback_count": len(rows),
        "execution_enabled": False,
        "network_access": False,
        "feedback_origin": "operator_entered_unverified",
    }
