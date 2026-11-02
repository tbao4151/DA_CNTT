"""Read-only, offline evidence-link check for a manually opened NEW-log SOC case.

Recomputes a pinned Zeek research prediction and compares the original flow
with the stored SQLite snapshot and initial audit note. This is NOT an alert,
attack confirmation, forensic signature or event-to-SOC latency measurement.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path

from siem_ai.core import NON_FEATURE_FIELDS, flow_id

from .new_log_inference import score_new_zeek_log
from .new_log_review import review_pinned_new_log_report
from .zeek import parse_zeek_conn_log

MAX_VISIBLE_FLOWS = 500


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key in stored SOC evidence")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError("Non-finite stored SOC evidence")



def _verify_creation_note(
    note: object, *,
    prefix: str,
    expected_manifest_sha256: str | None,
    expected_import_report_sha256: str | None,
    expected_pcap_sha256: str | None,
    expected_research_bundle_sha256: str | None,
    expected_research_alert_ref: str | None,
) -> bool:
    """Require the complete canonical creation note, not scattered substrings.

    The optional digest pins bind the stored operator-declared manifest/PCAP
    claims to the independently supplied evidence checked by the CLI.
    """
    ending = "Authorization, Host-only isolation and ground truth are unverified."
    if not isinstance(note, str) or not note.startswith(prefix) or not note.endswith(ending):
        raise ValueError("Initial SOC audit does not match pinned research inference")
    remaining = note[len(prefix):-len(ending)]
    if ((expected_research_bundle_sha256 is None)
            != (expected_research_alert_ref is None)):
        raise ValueError("Research queue audit pins must be supplied together")

    attestation = "TRAIN/VALIDATION/TEST exclusion is an operator attestation only. "
    if remaining.startswith(attestation):
        manifest_digest = None
        remaining = remaining[len(attestation):]
    else:
        declared = re.match(
            r"Declared exact-byte TRAIN/VALIDATION/TEST exclusion checked against "
            r"pinned manifest_sha256=([0-9a-f]{64}); "
            r"(?:Normalized UID/time/five-tuple identity overlap also checked; |"
            r"Normalized flow identity overlap NOT checked; )"
            r"historical completeness and semantic flow non-reuse unverified\. ",
            remaining,
        )
        if declared is None:
            raise ValueError("Invalid declared partition claim in SOC audit")
        manifest_digest = declared.group(1)
        remaining = remaining[declared.end():]
    if expected_manifest_sha256 is not None and manifest_digest != expected_manifest_sha256:
        raise ValueError("SOC audit manifest pin differs from verified manifest")

    # The queue claim is optional for legacy cases. When independently pinned
    # queue inputs are supplied, the ORIGINAL creation audit must contain the
    # exact verified bundle digest and selected reference. A reused legacy
    # source+UID case must not acquire provenance retroactively.
    queue = re.fullmatch(
        r"(.+?)(?:Pinned research queue selection rechecked: "
        r"bundle_sha256=([0-9a-f]{64}); "
        r"research_alert_ref=([0-9a-f]{64})\. )",
        remaining,
    )
    if queue is not None:
        remaining, queue_digest, queue_ref = queue.groups()
    else:
        queue_digest = queue_ref = None
    if expected_research_bundle_sha256 is not None and (
        queue_digest != expected_research_bundle_sha256
        or queue_ref != expected_research_alert_ref
    ):
        raise ValueError("SOC creation audit lacks matching pinned research queue")

    if remaining == "Original PCAP provenance NOT software-checked. ":
        import_digest = pcap_digest = None
    else:
        imported = re.fullmatch(
            r"Pinned original PCAP/import report/Zeek byte integrity and "
            r"(?:classic PCAP packet framing checked \(NOT packet-to-flow correlation\); )?"
            r"declared scope rechecked: import_report_sha256=([0-9a-f]{64}); "
            r"pcap_sha256=([0-9a-f]{64})\. ",
            remaining,
        )
        if imported is None:
            raise ValueError("Invalid PCAP provenance claim in SOC audit")
        import_digest, pcap_digest = imported.groups()
    if ((expected_import_report_sha256 is None) != (expected_pcap_sha256 is None)
            or (expected_import_report_sha256 is not None
                and import_digest != expected_import_report_sha256)
            or (expected_pcap_sha256 is not None
                and pcap_digest != expected_pcap_sha256)):
        raise ValueError("SOC audit PCAP pins differ from verified import")
    return (expected_research_bundle_sha256 is not None
            and queue_digest == expected_research_bundle_sha256)


def verify_new_log_soc_case_link(
    db_path: str | Path, *,
    source_data: bytes,
    model: Mapping[str, object],
    report_data: bytes,
    expected_log_sha256: str,
    model_sha256: str,
    lab_cidrs: Sequence[str],
    record_index: int,
    case_id: int,
    expected_manifest_sha256: str | None = None,
    expected_import_report_sha256: str | None = None,
    expected_pcap_sha256: str | None = None,
    expected_research_bundle_sha256: str | None = None,
    expected_research_alert_ref: str | None = None,
) -> dict[str, object]:
    """Verify one existing case against original NEW-log bytes without writes.

    The initial SOC event is checked, rather than mutable analyst notes, so
    legitimate subsequent case-state changes do not invalidate the link.
    This does not validate independent labels or declared partition history.
    """
    if type(case_id) is not int or case_id <= 0:
        raise ValueError("Case ID must be a positive integer")
    if type(record_index) is not int or not 0 <= record_index < MAX_VISIBLE_FLOWS:
        raise ValueError("Record index must be in the visible 0..499 range")

    review = review_pinned_new_log_report(
        source_data, model, report_data,
        expected_log_sha256=expected_log_sha256,
        model_sha256=model_sha256,
        lab_cidrs=lab_cidrs,
    )
    recomputed = score_new_zeek_log(
        source_data, model,
        expected_log_sha256=expected_log_sha256,
        model_sha256=model_sha256,
        lab_cidrs=lab_cidrs,
    )
    events = parse_zeek_conn_log(source_data)
    if record_index >= len(events):
        raise ValueError("Record index outside verified original capture")
    prediction = recomputed["predictions"][record_index]
    if prediction["research_candidate"] is not True:
        raise ValueError("Selected record is not a verified research candidate")
    event = events[record_index]
    if prediction["uid"] != event["uid"]:
        raise ValueError("Prediction does not identify the original Zeek flow")

    db = Path(db_path)
    if db.is_symlink() or not db.is_file():
        raise ValueError("Existing regular SQLite database required")
    # Read-only SQLite URI: never create/migrate a database or modify cases.
    uri = db.resolve(strict=True).as_uri() + "?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True) as conn:
            conn.execute("PRAGMA query_only=ON")
            case = conn.execute(
                "SELECT flow_id, verdict, confidence, evidence_json "
                "FROM cases WHERE case_id=?", (case_id,),
            ).fetchone()
            initial = conn.execute(
                "SELECT old_state, new_state, note FROM case_events "
                "WHERE case_id=? ORDER BY event_id LIMIT 1", (case_id,),
            ).fetchone()
    except sqlite3.Error as exc:
        raise ValueError("Unable to read existing SOC case evidence") from exc
    if case is None or initial is None:
        raise ValueError("SOC case or initial audit event not found")
    stored_flow_id, verdict, confidence, evidence_json = case
    if stored_flow_id != flow_id(event) or verdict != "Unclassified" or confidence is not None:
        raise ValueError("SOC case identity or unclassified verdict mismatch")
    try:
        stored_evidence = json.loads(
            evidence_json, object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid stored SOC evidence JSON") from exc
    expected_evidence = {
        str(key): str(value)[:256]
        for key, value in event.items() if key not in NON_FEATURE_FIELDS
    }
    if stored_evidence != expected_evidence:
        raise ValueError("SOC evidence snapshot differs from original Zeek flow")

    old_state, new_state, initial_note = initial
    if old_state is not None or new_state != "New":
        raise ValueError("Initial SOC audit state does not match case creation")
    note_prefix = (
        "Analyst-selected NEW-log OFFLINE research candidate; NOT a verified "
        "attack or operational AI alert. "
        f"source_sha256={expected_log_sha256}; "
        f"model_sha256={model_sha256}; "
        f"report_sha256={review['report_sha256']}; "
        f"scope_sha256={recomputed['declared_scope_sha256']}; "
        f"zeek_uid={prediction['uid']}; "
        f"research_attack_probability={prediction['attack_probability']:.8f}; "
        f"validation_threshold={recomputed['selected_validation_threshold']:.8f}. "
    )
    queue_creation_audit_verified = _verify_creation_note(
        initial_note, prefix=note_prefix,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_import_report_sha256=expected_import_report_sha256,
        expected_pcap_sha256=expected_pcap_sha256,
        expected_research_bundle_sha256=expected_research_bundle_sha256,
        expected_research_alert_ref=expected_research_alert_ref,
    )

    return {
        "report_version": 1,
        "mode": "offline_new_log_soc_evidence_link_check_only",
        "case_id": case_id,
        "record_index": record_index,
        "source_sha256": expected_log_sha256,
        "model_sha256": model_sha256,
        "report_sha256": review["report_sha256"],
        "stored_flow_snapshot_matches_original": True,
        "initial_audit_matches_recomputed_inference": True,
        "pinned_research_queue_creation_audit_verified": queue_creation_audit_verified,
        "sqlite_read_only": True,
        "independent_labels_verified": False,
        "declared_partition_history_verified": False,
        "host_only_isolation_verified": False,
        "operational_alert_verified": False,
        "detection_latency_measured": False,
        "interpretation": (
            "Offline software consistency of an analyst-created unclassified "
            "case, not independent attack evidence, a live alert or SOC latency."
        ),
    }
