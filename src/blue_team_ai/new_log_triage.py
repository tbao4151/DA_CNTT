"""Explicit manual SOC triage of a separately pinned NEW Zeek research report.

Only analyst-selected candidates may become Unclassified research cases. Every
write re-verifies the complete report against the original bytes and model.
No automatic alerts, attack labels, sockets, or model fitting.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path

from .labeled_dataset import LabeledLabDataset
from .new_log_inference import score_new_zeek_log
from .partition_guard import verify_declared_partition_exclusion
from .new_log_review import review_pinned_new_log_report
from .offline_pcap_verify import verify_offline_pcap_import
from .triage import create_offline_review_case
from .zeek import parse_zeek_conn_log

MAX_VISIBLE_NEW_LOG_FLOWS = 500


def create_new_log_candidate_case(
    db_path: str | Path, *,
    source_data: bytes,
    model: Mapping[str, object],
    report_data: bytes,
    expected_log_sha256: str,
    model_sha256: str,
    lab_cidrs: Sequence[str],
    record_index: int,
    analyst_confirmed: bool,
    operator_confirmed_authorized: bool,
    operator_confirmed_new_capture: bool,
    declared_dataset: LabeledLabDataset | None = None,
    declared_manifest_sha256: str | None = None,
    declared_captures: Sequence[Mapping[str, object]] | None = None,
    offline_import_report_path: str | Path | None = None,
    offline_import_report_sha256: str | None = None,
    offline_import_pcap_path: str | Path | None = None,
    offline_import_log_path: str | Path | None = None,
) -> int:
    """Create/reuse one manual Unclassified case for a verified candidate.

    Operator attestations are NOT cryptographic or independent evidence of
    authorization, physical isolation, or exclusion from the held-out TEST.
    The caller must load the model using the separately pinned loader.
    """
    if (
        analyst_confirmed is not True
        or operator_confirmed_authorized is not True
        or operator_confirmed_new_capture is not True
    ):
        raise ValueError("Explicit analyst, authorization and partition confirmations required")
    if type(record_index) is not int or not 0 <= record_index < MAX_VISIBLE_NEW_LOG_FLOWS:
        raise ValueError("Select a valid visible record index (0..499)")

    provenance_options = (
        offline_import_report_path, offline_import_report_sha256,
        offline_import_pcap_path, offline_import_log_path,
    )
    if any(option is not None for option in provenance_options) and not all(
        option is not None for option in provenance_options
    ):
        raise ValueError("All four pinned offline PCAP provenance inputs are required")
    verified_import = None
    if all(option is not None for option in provenance_options):
        # Re-read ORIGINAL PCAP/import report/conn.log at the SOC write boundary.
        # Earlier successful listing or scoring cannot replace this verification.
        verified_import = verify_offline_pcap_import(
            offline_import_report_path,
            expected_report_sha256=offline_import_report_sha256,
            pcap_path=offline_import_pcap_path,
            log_path=offline_import_log_path,
            lab_cidrs=lab_cidrs,
        )
        if (verified_import["zeek_conn_sha256"] != expected_log_sha256
                or hashlib.sha256(source_data).hexdigest() != expected_log_sha256):
            raise ValueError("SOC source bytes differ from verified offline PCAP import")

    if (declared_dataset is None) != (declared_manifest_sha256 is None):
        raise ValueError("Declared dataset and pinned manifest SHA must be supplied together")
    if declared_captures is not None and declared_dataset is None:
        raise ValueError("Declared flow captures require pinned partition evidence")
    if declared_dataset is not None:
        # Verify again inside the write boundary: caller-provided preflight
        # success cannot be substituted for checked partition evidence.
        verify_declared_partition_exclusion(
            model, declared_dataset,
            manifest_sha256=declared_manifest_sha256,
            new_capture_sha256=expected_log_sha256,
            declared_captures=declared_captures,
            new_source_data=source_data if declared_captures is not None else None,
        )

    review = review_pinned_new_log_report(
        source_data, model, report_data,
        expected_log_sha256=expected_log_sha256,
        lab_cidrs=lab_cidrs, model_sha256=model_sha256,
    )
    if record_index >= review["flow_count"]:
        raise ValueError("Record index outside verified new-log report")

    # The verifier already recomputes and compares every report field. Re-score
    # here instead of trusting a caller-provided parsed candidate dictionary.
    recomputed = score_new_zeek_log(
        source_data, model,
        expected_log_sha256=expected_log_sha256,
        lab_cidrs=lab_cidrs, model_sha256=model_sha256,
    )
    prediction = recomputed["predictions"][record_index]
    if prediction["research_candidate"] is not True:
        raise ValueError("Only verified research candidates may be selected")
    events = parse_zeek_conn_log(source_data)
    if prediction["uid"] != events[record_index]["uid"]:
        raise ValueError("Selected UID does not match the original Zeek flow")

    note = (
        "Analyst-selected NEW-log OFFLINE research candidate; NOT a verified "
        "attack or operational AI alert. "
        f"source_sha256={expected_log_sha256}; "
        f"model_sha256={model_sha256}; "
        f"report_sha256={review['report_sha256']}; "
        f"scope_sha256={recomputed['declared_scope_sha256']}; "
        f"zeek_uid={prediction['uid']}; "
        f"research_attack_probability={prediction['attack_probability']:.8f}; "
        f"validation_threshold={recomputed['selected_validation_threshold']:.8f}. "
        + (
            "Declared exact-byte TRAIN/VALIDATION/TEST exclusion checked against "
            f"pinned manifest_sha256={declared_manifest_sha256}; "
            + ("Normalized UID/time/five-tuple identity overlap also checked; "
               if declared_captures is not None else
               "Normalized flow identity overlap NOT checked; ")
            + "historical completeness and semantic flow non-reuse unverified. "
            if declared_dataset is not None else
            "TRAIN/VALIDATION/TEST exclusion is an operator attestation only. "
        )
        + (
            "Pinned original PCAP/import report/Zeek byte integrity and declared "
            f"scope rechecked: import_report_sha256={verified_import['report_sha256']}; "
            f"pcap_sha256={verified_import['pcap_sha256']}. "
            if verified_import is not None else
            "Original PCAP provenance NOT software-checked. "
        )
        + "Authorization, Host-only isolation and ground truth are unverified."
    )
    # Share the existing research idempotency namespace: one source+UID should
    # never produce two research cases, even across held-out/new-log workflows.
    key = hashlib.sha256(
        f"zeek-research-v1:{expected_log_sha256}:{prediction['uid']}".encode("utf-8")
    ).hexdigest()
    return create_offline_review_case(
        db_path, source_data=source_data, record_index=record_index,
        research_note=note, deduplication_key=key,
    )
