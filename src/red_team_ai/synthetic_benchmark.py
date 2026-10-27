"""Paired synthetic-only UCB1/random comparison; no attack or network operations.

All counterfactual outcomes are generated from declared Bernoulli probabilities,
not measured Blue Team events. This benchmark is for policy software regression
and teaching only, never an AI detection or adversarial success measurement.
"""
from __future__ import annotations

import random

from .scenario_policy import SCENARIOS, choose_scenario

BENCHMARK_VERSION = 1
# Synthetic assumptions, NOT real attack/detection rates. Immutable catalog IDs.
SYNTHETIC_UNFLAGGED_PROBABILITIES = {
    "baseline_web": 0.10,
    "dns_variation": 0.35,
    "connection_shift": 0.70,
}


def compare_synthetic_policies(*, rounds: int = 120, trials: int = 12, seed: int = 42) -> dict[str, object]:
    """Compare policies on identical pre-sampled per-round potential outcomes.

    For each trial/round/scenario, the same Bernoulli draw is available to both
    policies. A policy observes only the outcome of its selected scenario.
    Expected pseudo-regret uses declared probabilities, never observed test data.
    """
    if type(rounds) is not int or not 3 <= rounds <= 500:
        raise ValueError("rounds must be an integer in [3, 500]")
    if type(trials) is not int or not 2 <= trials <= 40:
        raise ValueError("trials must be an integer in [2, 40]")
    if type(seed) is not int or not 0 <= seed <= 1_000_000:
        raise ValueError("seed must be an integer in [0, 1000000]")
    ids = tuple(s.scenario_id for s in SCENARIOS)
    if set(ids) != set(SYNTHETIC_UNFLAGGED_PROBABILITIES):
        raise ValueError("Synthetic assumptions do not match immutable scenario catalog")
    if any(type(p) is not float or not 0.0 <= p <= 1.0 for p in SYNTHETIC_UNFLAGGED_PROBABILITIES.values()):
        raise ValueError("Invalid synthetic probability")

    best_p = max(SYNTHETIC_UNFLAGGED_PROBABILITIES.values())
    summaries: dict[str, dict[str, object]] = {}
    for strategy in ("ucb1", "random"):
        trial_rows: list[dict[str, object]] = []
        total_selected = {scenario_id: 0 for scenario_id in ids}
        for trial in range(trials):
            # Common random numbers: both strategies see the same hidden
            # potential outcomes for each (trial, round, scenario).
            draws = [
                {
                    scenario_id: random.Random(f"{seed}:{trial}:{round_index}:{scenario_id}").random()
                    < SYNTHETIC_UNFLAGGED_PROBABILITIES[scenario_id]
                    for scenario_id in ids
                }
                for round_index in range(rounds)
            ]
            feedback: list[dict[str, object]] = []
            observed_unflagged = 0
            expected_regret = 0.0
            for round_index in range(rounds):
                plan = choose_scenario(feedback, strategy=strategy, seed=(seed + trial) % 1_000_001)
                if plan["execution_enabled"] is not False or plan["network_access"] is not False:
                    raise ValueError("Refusing benchmark: scenario policy is not offline-only")
                chosen = plan["scenario_id"]
                if chosen not in total_selected:
                    raise ValueError("Scenario policy returned an unknown catalog ID")
                unflagged = draws[round_index][chosen]
                observed_unflagged += int(unflagged)
                expected_regret += best_p - SYNTHETIC_UNFLAGGED_PROBABILITIES[chosen]
                total_selected[chosen] += 1
                feedback.append({"scenario_id": chosen, "blue_flagged": not unflagged})
            trial_rows.append({
                "trial": trial + 1,
                "synthetic_unflagged": observed_unflagged,
                "synthetic_unflagged_fraction": observed_unflagged / rounds,
                "expected_pseudo_regret": round(expected_regret, 10),
            })
        summaries[strategy] = {
            "trials": trial_rows,
            "mean_synthetic_unflagged_fraction": sum(row["synthetic_unflagged_fraction"] for row in trial_rows) / trials,
            "mean_expected_pseudo_regret": sum(row["expected_pseudo_regret"] for row in trial_rows) / trials,
            "selection_counts": total_selected,
        }

    return {
        "benchmark_version": BENCHMARK_VERSION,
        "origin": "synthetic_bernoulli_not_blue_team_evidence",
        "execution_enabled": False,
        "network_access": False,
        "rounds_per_trial": rounds,
        "trials_per_strategy": trials,
        "seed": seed,
        "synthetic_unflagged_probabilities": dict(SYNTHETIC_UNFLAGGED_PROBABILITIES),
        "common_random_numbers": True,
        "policies": summaries,
        "interpretation_warning": (
            "All outcomes are synthetic and assumed, not observed attacks, "
            "Blue Team predictions, lab detections or real-world success rates. "
            "Do not use this benchmark to claim AI-vs-AI detection performance."
        ),
    }
