"""Synthetic-only CI research scoring contract tests; no Zeek binary required."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_real_zeek_scoring import validate_research_only_report


def _report():
    return {
        "mode": "offline_new_zeek_research_inference_only",
        "origin": "offline_zeek_log",
        "source_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "flow_count": 1,
        "research_candidate_count": 0,
        "predictions": [{"attack_probability": 0.25, "research_candidate": False}],
        "labels_used": False,
        "test_partition_exclusion_verified": False,
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "model_authorship_verified": False,
        "operational_attack_detection_verified": False,
        "automated_alerts": False,
        "soc_cases_created": False,
        "live_capture": False,
    }


def test_synthetic_only_contract_accepts_unverified_research_score():
    validate_research_only_report(_report(), log_sha="a" * 64, model_sha="b" * 64)


@pytest.mark.parametrize("field,value", [
    ("flow_count", 2),
    ("research_candidate_count", 1),
    ("labels_used", True),
    ("host_only_isolation_verified", True),
    ("operational_attack_detection_verified", True),
    ("automated_alerts", True),
    ("soc_cases_created", True),
    ("model_sha256", "c" * 64),
    ("predictions", [{"attack_probability": 0.25, "research_candidate": 1}]),
    ("predictions", [{"attack_probability": float("nan"), "research_candidate": False}]),
])
def test_synthetic_only_contract_rejects_fabricated_claims(field, value):
    report = copy.deepcopy(_report())
    report[field] = value
    with pytest.raises(ValueError, match="contract"):
        validate_research_only_report(report, log_sha="a" * 64, model_sha="b" * 64)
