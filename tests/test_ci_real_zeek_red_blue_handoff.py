"""Synthetic unit tests for the CI real-Zeek handoff *summary contract*.

These tests DO NOT execute Zeek. The Docker workflow exercises actual Zeek
against a synthetic benign PCAP before running the separate CI handoff script.
"""
from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_real_zeek_red_blue_handoff import (
    validate_ci_handoff_summary, validate_ci_manual_soc_bridge,
)
from test_red_team_offline_fixture_binding import evidence  # pytest fixture dependency
from test_red_blue_offline_handoff import joint, _verify


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check(item, summary):
    validate_ci_handoff_summary(
        summary,
        log_sha=item["source_sha"],
        model_sha=item["model_sha"],
        blue_sha=_sha(item["blue"].read_bytes()),
        audit_sha=_sha(item["audit"].read_bytes()),
        import_sha=_sha(item["report"].read_bytes()),
        pcap_sha=_sha(item["pcap"].read_bytes()),
    )


def test_synthetic_red_blue_summary_preserves_nonoperational_boundary(joint):
    _check(joint, _verify(joint))


@pytest.mark.parametrize("field", [
    "scenario_traffic_match_verified",
    "ground_truth_verified",
    "blue_team_detection_verified",
    "operational_alerts_created",
    "soc_cases_created",
    "network_access",
    "physical_host_only_isolation_verified",
])
def test_synthetic_ci_handoff_refuses_fabricated_operational_claims(joint, field):
    summary = copy.deepcopy(_verify(joint))
    summary[field] = True
    with pytest.raises(ValueError, match="research-only"):
        _check(joint, summary)


@pytest.mark.parametrize("field", [
    "zeek_conn_sha256", "blue_model_sha256", "blue_report_sha256",
    "red_audit_sha256", "offline_import_report_sha256", "pcap_sha256",
])
def test_synthetic_ci_handoff_refuses_mismatched_source_pins(joint, field):
    summary = copy.deepcopy(_verify(joint))
    summary[field] = "0" * 64
    with pytest.raises(ValueError, match="research-only"):
        _check(joint, summary)


def test_synthetic_ci_handoff_refuses_missing_recomputation(joint):
    summary = copy.deepcopy(_verify(joint))
    summary["blue_report_recomputed"] = False
    with pytest.raises(ValueError, match="research-only"):
        _check(joint, summary)


def _synthetic_soc_link(item):
    # Contract fixture only: no database or Zeek executable in these unit tests.
    return {
        "mode": "offline_new_log_soc_evidence_link_check_only",
        "case_id": 1,
        "record_index": 0,
        "source_sha256": item["source_sha"],
        "model_sha256": "0" * 64,
        "report_sha256": "1" * 64,
        "stored_flow_snapshot_matches_original": True,
        "initial_audit_matches_recomputed_inference": True,
        "sqlite_read_only": True,
        "independent_labels_verified": False,
        "declared_partition_history_verified": False,
        "host_only_isolation_verified": False,
        "operational_alert_verified": False,
        "detection_latency_measured": False,
    }


def _check_soc_bridge(item, handoff, soc, **overrides):
    args = dict(
        log_sha=item["source_sha"],
        import_sha=_sha(item["report"].read_bytes()),
        pcap_sha=_sha(item["pcap"].read_bytes()),
        fitted_model_sha=item["model_sha"],
        manual_model_sha="0" * 64,
        manual_report_sha="1" * 64,
        case_id=1,
    )
    args.update(overrides)
    validate_ci_manual_soc_bridge(handoff, soc, **args)


def test_synthetic_red_blue_to_manual_soc_bridge_contract(joint):
    _check_soc_bridge(joint, _verify(joint), _synthetic_soc_link(joint))


@pytest.mark.parametrize("field,value", [
    ("source_sha256", "f" * 64),
    ("model_sha256", "e" * 64),
    ("report_sha256", "d" * 64),
    ("case_id", 999),
    ("record_index", 1),
    ("stored_flow_snapshot_matches_original", False),
    ("initial_audit_matches_recomputed_inference", False),
    ("sqlite_read_only", False),
    ("operational_alert_verified", True),
    ("independent_labels_verified", True),
    ("host_only_isolation_verified", True),
])
def test_synthetic_soc_bridge_refuses_false_links_and_operational_claims(joint, field, value):
    soc = _synthetic_soc_link(joint)
    soc[field] = value
    with pytest.raises(ValueError, match="manual SOC bridge"):
        _check_soc_bridge(joint, _verify(joint), soc)


def test_synthetic_soc_bridge_requires_distinct_manual_fixture_model(joint):
    with pytest.raises(ValueError, match="manual SOC bridge"):
        _check_soc_bridge(
            joint, _verify(joint), _synthetic_soc_link(joint),
            manual_model_sha=joint["model_sha"],
        )


def test_synthetic_soc_bridge_refuses_mismatched_red_blue_import(joint):
    handoff = _verify(joint)
    handoff["offline_import_report_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="manual SOC bridge"):
        _check_soc_bridge(joint, handoff, _synthetic_soc_link(joint))
