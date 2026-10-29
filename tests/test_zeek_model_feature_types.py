"""Synthetic-only regression: Zeek model feature types at fit and score gates.

No VMware capture, independent labels, live alert or detection metric is tested.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from blue_team_ai.features import validate_zeek_model_features
from blue_team_ai.model_artifact import (
    build_zeek_research_artifact, score_zeek_research_rows,
)
from blue_team_ai.offline_baseline import evaluate_offline_zeek_baseline
from test_zeek_offline_baseline import _dataset


@pytest.mark.parametrize("field,value", [
    ("src_port", 443.0),
    ("src_port", None),
    ("dst_port", 65536),
    ("dst_port", -1),
    ("src_port", True),
    ("orig_bytes", 1.5),
    ("resp_bytes", 2.0),
    ("orig_pkts", True),
    ("resp_pkts", -1),
    ("orig_bytes", 1_000_000_000_001),
    ("duration_s", float("nan")),
    ("duration_s", 1e13),
])
def test_forged_feature_types_refused_by_both_training_and_scoring(field, value):
    dataset = _dataset()
    artifact = build_zeek_research_artifact(
        dataset, input_manifest_sha256="a" * 64,
    )
    tampered = copy.deepcopy(dataset)
    tampered.features["test"][0][field] = value
    with pytest.raises(ValueError, match="Invalid numeric Zeek"):
        evaluate_offline_zeek_baseline(tampered)
    with pytest.raises(ValueError, match="Invalid numeric Zeek"):
        score_zeek_research_rows(artifact, tampered.features["test"])
    with pytest.raises(ValueError, match="Invalid numeric Zeek"):
        validate_zeek_model_features(tampered.features["test"][0])


def test_training_partition_forged_count_refused_before_model_export():
    dataset = _dataset()
    dataset.features["train"][0]["orig_pkts"] = 2.5
    with pytest.raises(ValueError, match="Invalid numeric Zeek"):
        build_zeek_research_artifact(
            dataset, input_manifest_sha256="a" * 64,
        )


def test_valid_zeek_integer_counts_missing_optionals_and_fractional_duration():
    dataset = _dataset()
    row = dataset.features["test"][0]
    row["src_port"] = 0
    row["dst_port"] = 65535
    row["orig_bytes"] = 0
    row["resp_bytes"] = None
    row["orig_pkts"] = 1_000_000_000_000
    row["resp_pkts"] = None
    row["duration_s"] = 1.25
    validate_zeek_model_features(row)
    artifact = build_zeek_research_artifact(
        _dataset(), input_manifest_sha256="a" * 64,
    )
    scored = score_zeek_research_rows(artifact, [row])
    assert len(scored) == 1
    assert 0 <= scored[0]["attack_probability"] <= 1
