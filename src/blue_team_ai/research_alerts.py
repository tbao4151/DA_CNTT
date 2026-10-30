"""Verified offline Zeek research alert queue for manual SOC review.

A research alert is a *candidate*, never an operational detection. This module
does not touch SQLite, send traffic, or authenticate a VMware capture. All
input bytes and declared experiment partitions are rechecked at this boundary.
"""
from __future__ import annotations

import hashlib
import hmac
import json
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


# Bounded private JSON, not an executable instruction or a source of labels.
MAX_RESEARCH_ALERT_BUNDLE_BYTES = 2_000_000


def verify_pinned_research_alert_selection(
    bundle_data: bytes, *,
    expected_bundle_sha256: str,
    research_alert_ref: str,
    record_index: int,
    source_data: bytes,
    model: Mapping[str, object],
    report_data: bytes,
    expected_log_sha256: str,
    model_sha256: str,
    lab_cidrs: Sequence[str],
    manifest_sha256: str,
    declared_dataset: LabeledLabDataset,
    declared_captures: Sequence[Mapping[str, object]],
) -> str:
    """Verify the ENTIRE saved queue before one explicit manual SOC write.

    The caller must supply an independently recorded SHA-256 for the private
    bundle. Rebuild from original log/model/report and pinned declared splits;
    a matching digest alone is not proof that the queue is scientifically
    consistent. No SOC writes or external network operations happen here.
    """
    if type(bundle_data) is not bytes or not 0 < len(bundle_data) <= MAX_RESEARCH_ALERT_BUNDLE_BYTES:
        raise ValueError("Expected bounded private research alert bundle bytes")
    if (not isinstance(expected_bundle_sha256, str)
            or len(expected_bundle_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_bundle_sha256)
            or not hmac.compare_digest(
                hashlib.sha256(bundle_data).hexdigest(), expected_bundle_sha256
            )):
        raise ValueError("Independent research bundle SHA-256 mismatch")
    if (not isinstance(research_alert_ref, str)
            or len(research_alert_ref) != 64
            or any(c not in "0123456789abcdef" for c in research_alert_ref)):
        raise ValueError("Invalid research alert reference")
    if type(record_index) is not int or not 0 <= record_index < MAX_MANUAL_TRIAGE_ROWS:
        raise ValueError("Invalid original research alert record index")

    def unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate research alert JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError("Non-finite research alert JSON value")

    try:
        saved = json.loads(
            bundle_data.decode("utf-8"), object_pairs_hook=unique_keys,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Invalid research alert bundle JSON") from exc
    expected = build_verified_research_alert_bundle(
        source_data, model, report_data,
        expected_log_sha256=expected_log_sha256,
        model_sha256=model_sha256,
        lab_cidrs=lab_cidrs,
        manifest_sha256=manifest_sha256,
        declared_dataset=declared_dataset,
        declared_captures=declared_captures,
    )
    # Canonical JSON comparison preserves distinctions such as bool vs int
    # that Python dictionary equality would otherwise silently collapse.
    canonical = lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    )
    if canonical(saved) != canonical(expected):
        raise ValueError("Research bundle differs from recomputed original evidence")
    selected = [
        row for row in expected["research_alerts"]
        if row["record_index"] == record_index
        and row["research_alert_ref"] == research_alert_ref
    ]
    if len(selected) != 1:
        raise ValueError("Selected original index/reference not in verified research queue")
    return expected_bundle_sha256
