"""Synthetic-only NEW-log research candidate workload diagnostics.

No real VMware capture, independent ground truth, live alerts or SOC writes.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from test_zeek_new_log_evaluation import _command, _evaluate, inputs

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.alert_burden import summarize_research_candidate_burden as summarize


def test_mixed_confusion_denominators():
    result = summarize({"tp": 8, "fp": 2, "tn": 18, "fn": 12, "support": 40})
    assert result["research_candidate_flows"] == 10
    assert result["operator_labeled_attack_prevalence"] == 0.5
    assert result["research_candidate_fraction"] == 0.25
    assert result["research_candidates_per_1000_observed_flows"] == 250
    assert result["false_candidates_per_1000_observed_flows"] == 50
    assert result["false_candidates_per_1000_operator_labeled_normal_flows"] == 100
    assert result["missed_attacks_per_1000_operator_labeled_attack_flows"] == 600
    assert result["false_discovery_fraction_among_candidates"] == 0.2
    assert result["operational_alerts_created"] is False


@pytest.mark.parametrize("counts,undefined", [
    ({"tp": 0, "fp": 0, "tn": 10, "fn": 0, "support": 10},
     "missed_attacks_per_1000_operator_labeled_attack_flows"),
    ({"tp": 3, "fp": 0, "tn": 0, "fn": 2, "support": 5},
     "false_candidates_per_1000_operator_labeled_normal_flows"),
    ({"tp": 0, "fp": 0, "tn": 8, "fn": 2, "support": 10},
     "false_discovery_fraction_among_candidates"),
])
def test_undefined_denominator_is_null(counts, undefined):
    assert summarize(counts)[undefined] is None


@pytest.mark.parametrize("counts", [
    {"tp": True, "fp": 0, "tn": 0, "fn": 0, "support": 1},
    {"tp": -1, "fp": 1, "tn": 1, "fn": 0, "support": 1},
    {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "support": 0},
    {"tp": 1, "fp": 0, "tn": 0, "fn": 0, "support": 2},
    {"tp": 1, "fp": 0, "tn": 0, "fn": 0},
])
def test_refuse_invalid_counts(counts):
    with pytest.raises(ValueError):
        summarize(counts)


def test_new_log_evaluation_reconciles_burden_with_confusion(inputs):
    result = _evaluate(inputs)
    confusion = result["confusion_matrix"]
    burden = result["research_candidate_burden"]
    assert burden == summarize(confusion)
    assert burden["research_candidate_flows"] == confusion["tp"] + confusion["fp"]
    assert burden["false_candidate_flows"] == confusion["fp"]
    assert burden["missed_operator_labeled_attack_flows"] == confusion["fn"]
    assert burden["small_class_support_warning"] is True
    serialized = json.dumps(burden)
    assert "NEW1" not in serialized and "192.168.56." not in serialized
    assert burden["independent_ground_truth_verified"] is False


def test_cli_reports_only_aggregate_burden_and_does_not_modify_private_files(inputs):
    files = [path for path in inputs["manifest"].parent.iterdir() if path.is_file()]
    before = {path: path.read_bytes() for path in files}
    run = subprocess.run(_command(inputs), capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    output = json.loads(run.stdout)
    assert output["research_candidate_burden"] == summarize(output["confusion_matrix"])
    assert output["research_candidate_burden"]["operational_alerts_created"] is False
    assert before == {path: path.read_bytes() for path in files}
    assert not list(inputs["manifest"].parent.glob("*.sqlite3"))
