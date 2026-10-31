"""Bind a pending, audited Red Team label to pinned OFFLINE PCAP/Zeek evidence.

Read-only research provenance: no replay, packets, attack execution or SOC writes.
A scenario label does NOT prove the PCAP contains that scenario's traffic.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import
from .planning_audit import export_planning_audit

MAX_AUDIT_BYTES = 1_000_000


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Red Team audit JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("Non-finite Red Team audit JSON value")


def bind_pending_offline_fixture(
    audit_data: bytes,
    *,
    expected_audit_sha256: str,
    import_report_path: str | Path,
    expected_import_report_sha256: str,
    pcap_path: str | Path,
    conn_log_path: str | Path,
    lab_cidrs: Sequence[str],
    operator_confirmed_authorized: bool,
    operator_confirmed_offline: bool,
    operator_confirmed_fixture_reviewed: bool,
) -> dict[str, object]:
    """Recheck an exported pending proposal and existing offline evidence.

    Requires independently recorded pins and three explicit operator statements.
    The existing PCAP/Zeek verifier checks bytes, framing and declared CIDR.
    Neither verifier authenticates authorization, physical isolation or traffic
    semantics. This function never executes a proposed scenario.
    """
    if (
        operator_confirmed_authorized is not True
        or operator_confirmed_offline is not True
        or operator_confirmed_fixture_reviewed is not True
    ):
        raise ValueError("Explicit offline, authorization and fixture review confirmations required")
    if type(audit_data) is not bytes or not 0 < len(audit_data) <= MAX_AUDIT_BYTES:
        raise ValueError("Expected bounded exported Red Team audit bytes")
    if (
        not isinstance(expected_audit_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_audit_sha256) is None
        or not hmac.compare_digest(hashlib.sha256(audit_data).hexdigest(), expected_audit_sha256)
    ):
        raise ValueError("Independent Red Team audit SHA-256 mismatch")
    try:
        saved = json.loads(
            audit_data.decode("utf-8"),
            object_pairs_hook=_unique_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Invalid exported Red Team audit JSON") from exc
    if not isinstance(saved, dict) or not isinstance(saved.get("events"), list):
        raise ValueError("Expected an exported Red Team planning audit")
    # Replaying every proposal/feedback verifies policy, chronology, and OFF flags.
    expected = export_planning_audit(saved["events"])
    canonical = lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    if canonical(saved) != canonical(expected):
        raise ValueError("Exported Red Team audit differs from verified chronology")
    if expected["pending_proposal_id"] is None:
        raise ValueError("An outstanding, non-executing proposal is required")
    pending = expected["events"][-1]
    if pending["kind"] != "proposal" or pending["execution_enabled"] is not False:
        raise ValueError("Expected a pending non-executing proposal")

    evidence = verify_offline_pcap_import(
        import_report_path,
        expected_report_sha256=expected_import_report_sha256,
        pcap_path=pcap_path,
        log_path=conn_log_path,
        lab_cidrs=lab_cidrs,
        require_pcap_framing=True,
    )
    return {
        "binding_version": 1,
        "mode": "red_team_pending_proposal_offline_evidence_binding_only",
        "origin": "operator_supplied_offline_pcap",
        "audit_sha256": expected_audit_sha256,
        "proposal_id": pending["proposal_id"],
        "scenario_id": pending["scenario_id"],
        "strategy": pending["strategy"],
        "seed": pending["seed"],
        "policy_feedback_origin": "operator_entered_unverified",
        "import_report_sha256": evidence["report_sha256"],
        "pcap_sha256": evidence["pcap_sha256"],
        "zeek_conn_sha256": evidence["zeek_conn_sha256"],
        "pcap_packet_count": evidence["pcap_packet_count"],
        "zeek_flow_count": evidence["flow_count"],
        "declared_cidr_consistency_checked": True,
        "pcap_framing_verified": True,
        "operator_authorization_declared": True,
        "independent_authorization_verified": False,
        "physical_host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "scenario_traffic_match_verified": False,
        "ground_truth_verified": False,
        "blue_team_detection_verified": False,
        "replay_executed": False,
        "execution_enabled": False,
        "network_access": False,
        "soc_cases_created": False,
        "interpretation": (
            "Read-only link between an audited OFFLINE scenario label and existing "
            "pinned PCAP/Zeek files. No scenario-specific packet matching, replay, "
            "attack, independent authorization or AI detection is established."
        ),
    }
