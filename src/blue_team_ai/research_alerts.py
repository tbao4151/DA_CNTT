"""Verified offline Zeek research alert queue for manual SOC review.

A research alert is a *candidate*, never an operational detection. This module
does not touch SQLite, send traffic, or authenticate a VMware capture. All
input bytes and declared experiment partitions are rechecked at this boundary.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence

from .labeled_dataset import LabeledLabDataset
from .new_log_inference import score_new_zeek_log
from .new_log_review import review_pinned_new_log_report
from .partition_guard import verify_declared_partition_exclusion

# The existing explicit SOC triage API accepts only original indices 0..499.
MAX_MANUAL_TRIAGE_ROWS = 500


def build_verified_research_alert_bundle(
    source_data: bytes,
    model: Mapping[str, object],
    report_data: bytes,
    *,
    expected_log_sha256: str,
    model_sha256: str,
    lab_cidrs: Sequence[str],
    manifest_sha256: str,
    declared_dataset: LabeledLabDataset,
    declared_captures: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Produce a deterministic private queue from recomputed, pinned scores.

    The pinned manifest and every original declared TRAIN/VALIDATION/TEST
    capture/annotation must be supplied. Only the first 500 original rows are
    eligible for existing explicit manual SOC triage; never silently renumber
    sorted candidates or imply that a candidate is a confirmed attack.
    """
    partition = verify_declared_partition_exclusion(
        model, declared_dataset,
        manifest_sha256=manifest_sha256,
        new_capture_sha256=expected_log_sha256,
        declared_captures=declared_captures,
        new_source_data=source_data,
    )
    if partition["declared_flow_identity_nonreuse_checked"] is not True:
        raise ValueError("Original declared flow identity check required")

    review = review_pinned_new_log_report(
        source_data, model, report_data,
        expected_log_sha256=expected_log_sha256,
        lab_cidrs=lab_cidrs,
        model_sha256=model_sha256,
    )
    # Never use unverified report JSON as a candidate source. Recompute from
    # immutable bytes and the separately pinned data-only Zeek model instead.
    scored = score_new_zeek_log(
        source_data, model,
        expected_log_sha256=expected_log_sha256,
        lab_cidrs=lab_cidrs,
        model_sha256=model_sha256,
    )
    candidates = []
    for index, row in enumerate(scored["predictions"][:MAX_MANUAL_TRIAGE_ROWS]):
        if row["research_candidate"] is not True:
            continue
        # Matches the existing manual Zeek SOC case deduplication namespace;
        # an alert reference is not a case ID or evidence of case creation.
        reference = hashlib.sha256(
            f"zeek-research-v1:{expected_log_sha256}:{row['uid']}".encode("utf-8")
        ).hexdigest()
        candidates.append({
            "research_alert_ref": reference,
            "record_index": index,
            "uid": row["uid"],
            "event_time_utc": row["event_time_utc"],
            "src_ip": row["src_ip"],
            "src_port": row["src_port"],
            "dst_ip": row["dst_ip"],
            "dst_port": row["dst_port"],
            "attack_probability": row["attack_probability"],
            "validation_threshold": scored["selected_validation_threshold"],
            "status": "pending_manual_research_review",
            "confirmed_attack": False,
            "soc_case_id": None,
        })
    candidates.sort(key=lambda item: (-item["attack_probability"], item["record_index"]))
    return {
        "bundle_version": 1,
        "mode": "offline_zeek_research_alert_candidates_only",
        "origin": "offline_zeek_log",
        "source_sha256": expected_log_sha256,
        "model_sha256": model_sha256,
        "report_sha256": review["report_sha256"],
        "manifest_sha256": manifest_sha256,
        "declared_scope_sha256": scored["declared_scope_sha256"],
        "flow_count": scored["flow_count"],
        "research_candidate_count_total": scored["research_candidate_count"],
        "manual_triage_window_rows": min(MAX_MANUAL_TRIAGE_ROWS, scored["flow_count"]),
        "research_alert_candidates_exported": len(candidates),
        "candidates_outside_manual_triage_window": (
            scored["research_candidate_count"] - len(candidates)
        ),
        "research_alerts": candidates,
        "declared_partition_and_flow_identity_nonreuse_checked": True,
        "independent_partition_history_verified": False,
        "independent_ground_truth_verified": False,
        "vmware_isolation_verified": False,
        "capture_authenticity_verified": False,
        "operational_alerts_created": False,
        "soc_cases_created": False,
        "live_capture": False,
        "interpretation": (
            "Offline, independently pinned software-consistency research queue. "
            "Candidates are not verified attacks or operational alerts. "
            "Only original row indices below 500 can be passed to the existing "
            "explicit analyst-confirmed manual SOC triage. Declared partition "
            "checks cannot establish complete capture history, authentic labels, "
            "physical Host-only isolation, or live detection latency."
        ),
    }
