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
from ci_real_zeek_red_blue_handoff import validate_ci_handoff_summary
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
