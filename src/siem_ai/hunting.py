"""Deterministic, read-only filters for the historical network-flow hunting view."""
from __future__ import annotations

import math
from collections.abc import Iterable

import pandas as pd


def filter_hunting_flows(
    flows: pd.DataFrame,
    *,
    protocols: Iterable[str] = (),
    services: Iterable[str] = (),
    states: Iterable[str] = (),
    only_ai_attacks: bool = False,
    min_attack_probability: float | None = None,
) -> pd.DataFrame:
    """AND across dimensions, OR within each selected category.

    An empty selection means no restriction for that dimension. Filters only
    affect the currently loaded historical sample, never the full dataset.
    The original frame (including its index) is not modified.
    """
    if not isinstance(flows, pd.DataFrame):
        raise TypeError("flows must be a pandas DataFrame")
    selected = flows
    for column, values in (
        ("proto", protocols), ("service", services), ("state", states)
    ):
        choices = tuple(values)
        if choices:
            if column not in selected:
                raise ValueError(f"Missing filter column: {column}")
            selected = selected.loc[
                selected[column].astype("string").isin(choices).fillna(False)
            ]

    if only_ai_attacks:
        if "AI_verdict" not in selected:
            raise ValueError("AI predictions are unavailable")
        selected = selected.loc[selected["AI_verdict"].eq("Attack").fillna(False)]

    if min_attack_probability is not None:
        if (not isinstance(min_attack_probability, (int, float))
                or not math.isfinite(min_attack_probability)
                or not 0 <= min_attack_probability <= 1):
            raise ValueError("Minimum AI attack probability must be in [0, 1]")
        if "AI_attack_probability" not in selected:
            raise ValueError("AI probabilities are unavailable")
        probabilities = pd.to_numeric(selected["AI_attack_probability"], errors="coerce")
        selected = selected.loc[probabilities.ge(min_attack_probability).fillna(False)]

    return selected.copy()
