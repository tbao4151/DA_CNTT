"""Synthetic-only checks for the real-Zeek pinned queue CI acceptance contract."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_real_zeek_queue_handoff import (
    validate_ci_queue_bundle, validate_ci_empty_queue_bundle,
)


def _bundle() -> dict[str, object]:
    return {
        "mode": "offline_zeek_research_alert_candidates_only",
        "origin": "offline_zeek_log",
        "source_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "manifest_sha256": "c" * 64,
        "flow_count": 1,
        "research_alert_candidates_exported": 1,
        "research_candidate_count_total": 1,
        "declared_partition_and_flow_identity_nonreuse_checked": True,
        "research_alerts": [{
            "record_index": 0,
            "research_alert_ref": "d" * 64,
            "status": "pending_manual_research_review",
            "confirmed_attack": False,
            "soc_case_id": None,
        }],
        "independent_partition_history_verified": False,
        "independent_ground_truth_verified": False,
        "vmware_isolation_verified": False,
        "capture_authenticity_verified": False,
        "operational_alerts_created": False,
        "soc_cases_created": False,
        "live_capture": False,
    }


def _validate(bundle):
    return validate_ci_queue_bundle(
        bundle, log_sha="a" * 64, model_sha="b" * 64,
        manifest_sha="c" * 64,
    )


def test_ci_queue_accepts_only_unverified_pending_candidate():
    selected = _validate(_bundle())
    assert selected["record_index"] == 0
    assert selected["confirmed_attack"] is False


@pytest.mark.parametrize("field,value", [
    ("mode", "live_attack_alerts"),
    ("origin", "live_capture"),
    ("flow_count", 2),
    ("research_alert_candidates_exported", 0),
    ("independent_ground_truth_verified", True),
    ("vmware_isolation_verified", True),
    ("operational_alerts_created", True),
    ("soc_cases_created", True),
    ("live_capture", True),
    ("manifest_sha256", "0" * 64),
])
def test_ci_queue_refuses_fabricated_claims(field, value):
    bundle = _bundle()
    bundle[field] = value
    with pytest.raises(ValueError, match="CI synthetic research queue"):
        _validate(bundle)


@pytest.mark.parametrize("field,value", [
    ("record_index", True),
    ("record_index", 1),
    ("research_alert_ref", "0" * 63),
    ("research_alert_ref", "Z" * 64),
    ("status", "confirmed_attack"),
    ("confirmed_attack", True),
    ("soc_case_id", 1),
])
def test_ci_queue_refuses_invalid_candidate_identity_or_status(field, value):
    bundle = copy.deepcopy(_bundle())
    bundle["research_alerts"][0][field] = value
    with pytest.raises(ValueError, match="CI synthetic research queue"):
        _validate(bundle)


def test_ci_queue_refuses_missing_or_duplicate_candidate():
    for rows in ([], [_bundle()["research_alerts"][0]] * 2, None):
        bundle = _bundle()
        bundle["research_alerts"] = rows
        with pytest.raises(ValueError, match="CI synthetic research queue"):
            _validate(bundle)


def _empty_bundle() -> dict[str, object]:
    bundle = _bundle()
    bundle["research_alerts"] = []
    bundle["research_alert_candidates_exported"] = 0
    bundle["research_candidate_count_total"] = 0
    return bundle


def _validate_empty(bundle: dict[str, object]) -> None:
    validate_ci_empty_queue_bundle(
        bundle, log_sha="a" * 64, model_sha="b" * 64,
        manifest_sha="c" * 64,
    )


def test_ci_empty_queue_accepts_no_candidates_and_no_operational_claims():
    assert _validate_empty(_empty_bundle()) is None


@pytest.mark.parametrize("field,value", [
    ("research_alerts", [_bundle()["research_alerts"][0]]),
    ("research_alert_candidates_exported", 1),
    ("research_candidate_count_total", 1),
    ("flow_count", True),
    ("model_sha256", "0" * 64),
    ("declared_partition_and_flow_identity_nonreuse_checked", False),
    ("independent_ground_truth_verified", True),
    ("operational_alerts_created", True),
    ("soc_cases_created", True),
    ("live_capture", True),
])
def test_ci_empty_queue_refuses_candidate_or_fabricated_claim(field, value):
    bundle = _empty_bundle()
    bundle[field] = value
    with pytest.raises(ValueError, match="CI synthetic empty research queue"):
        _validate_empty(bundle)
