"""Read-only Red/Blue research handoff over ONE independently pinned offline Zeek source.

The join checks exact source/report/model consistency, not scenario semantics,
attack ground truth, physical VMware isolation or operational detection.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from blue_team_ai.new_log_review import (
    MAX_NEW_LOG_REPORT_BYTES, review_pinned_new_log_report,
)
from blue_team_ai.zeek import MAX_LOG_BYTES
from red_team_ai.offline_fixture_binding import bind_pending_offline_fixture


def _pinned_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def verify_red_blue_offline_handoff(
    *,
    audit_data: bytes,
    expected_audit_sha256: str,
    import_report_path: str | Path,
    expected_import_report_sha256: str,
    pcap_path: str | Path,
    conn_log_path: str | Path,
    source_data: bytes,
    expected_log_sha256: str,
    model: Mapping[str, object],
    model_sha256: str,
    blue_report_data: bytes,
    expected_blue_report_sha256: str,
    lab_cidrs: Sequence[str],
    operator_confirmed_authorized: bool,
    operator_confirmed_offline: bool,
    operator_confirmed_fixture_reviewed: bool,
) -> dict[str, object]:
    """Re-verify Red planning + PCAP import and Blue scores without writes.

    The model must be loaded by a separately pinned trusted-model loader.
    The original Zeek bytes must be read from the same private conn_log_path;
    comparing digests detects disagreement between the supplied bytes and
    the original re-read by the Red/PCAP verifier.
    """
    if (
        type(source_data) is not bytes or not 0 < len(source_data) <= MAX_LOG_BYTES
        or type(blue_report_data) is not bytes
        or not 0 < len(blue_report_data) <= MAX_NEW_LOG_REPORT_BYTES
    ):
        raise ValueError("Expected bounded original Zeek and Blue report bytes")
    if not all(_pinned_sha256(digest) for digest in (
        expected_log_sha256, model_sha256, expected_blue_report_sha256,
    )):
        raise ValueError("Independently pinned lowercase SHA-256 required")
    if not hmac.compare_digest(
        hashlib.sha256(blue_report_data).hexdigest(), expected_blue_report_sha256
    ):
        raise ValueError("Blue research report SHA-256 differs from independent pin")
    if not hmac.compare_digest(
        hashlib.sha256(source_data).hexdigest(), expected_log_sha256
    ):
        raise ValueError("Blue Zeek source bytes differ from independent pin")

    # Replays UCB1/random history and verifies the original PCAP, conn.log,
    # import report, CIDR and strict classic-PCAP framing. No replay occurs.
    red = bind_pending_offline_fixture(
        audit_data,
        expected_audit_sha256=expected_audit_sha256,
        import_report_path=import_report_path,
        expected_import_report_sha256=expected_import_report_sha256,
        pcap_path=pcap_path,
        conn_log_path=conn_log_path,
        lab_cidrs=lab_cidrs,
        operator_confirmed_authorized=operator_confirmed_authorized,
        operator_confirmed_offline=operator_confirmed_offline,
        operator_confirmed_fixture_reviewed=operator_confirmed_fixture_reviewed,
    )
    if not hmac.compare_digest(red["zeek_conn_sha256"], expected_log_sha256):
        raise ValueError("Red/Blue original Zeek source SHA-256 mismatch")

    # Re-score every original flow; a report pin alone is insufficient.
    blue = review_pinned_new_log_report(
        source_data,
        model,
        blue_report_data,
        expected_log_sha256=expected_log_sha256,
        lab_cidrs=lab_cidrs,
        model_sha256=model_sha256,
    )
    if (
        blue["source_sha256"] != red["zeek_conn_sha256"]
        or blue["flow_count"] != red["zeek_flow_count"]
        or blue["report_sha256"] != expected_blue_report_sha256
    ):
        raise ValueError("Red/Blue research evidence does not describe the same Zeek source")
    return {
        "handoff_version": 1,
        "mode": "offline_red_blue_research_evidence_consistency_only",
        "red_proposal_id": red["proposal_id"],
        "red_scenario_id": red["scenario_id"],
        "red_strategy": red["strategy"],
        "red_audit_sha256": red["audit_sha256"],
        "offline_import_report_sha256": red["import_report_sha256"],
        "pcap_sha256": red["pcap_sha256"],
        "zeek_conn_sha256": red["zeek_conn_sha256"],
        "blue_model_sha256": model_sha256,
        "blue_report_sha256": blue["report_sha256"],
        "zeek_flow_count": blue["flow_count"],
        "pcap_packet_count": red["pcap_packet_count"],
        "blue_research_candidate_count": blue["research_candidate_count"],
        "same_pinned_zeek_source_verified": True,
        "red_planning_history_replayed": True,
        "blue_report_recomputed": True,
        "pcap_framing_verified": True,
        "independent_authorization_verified": False,
        "physical_host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "scenario_traffic_match_verified": False,
        "ground_truth_verified": False,
        "held_out_test_exclusion_verified": False,
        "blue_team_detection_verified": False,
        "operational_alerts_created": False,
        "soc_cases_created": False,
        "red_team_execution_enabled": False,
        "network_access": False,
        "interpretation": (
            "A non-executed Red scenario label and recomputed Blue research "
            "scores refer to the same pinned offline Zeek source. Neither "
            "scenario-specific traffic nor attack detection is established."
        ),
    }
