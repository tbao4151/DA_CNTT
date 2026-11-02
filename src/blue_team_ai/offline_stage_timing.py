"""Validate an operator-recorded offline SOC stage timeline; no live latency claim.

Only UTC timestamps from one declared clock are compared. This module does
not authenticate clocks, PCAP, Zeek, labels, model, SOC case or operator.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone

MAX_TIMING_RECORD_BYTES = 32 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
_STAGES = (
    "capture_completed", "zeek_log_ready", "inference_started",
    "inference_finished", "research_queue_ready", "soc_case_created",
)
_EVIDENCE = ("pcap", "zeek_conn", "model", "research_report", "soc_case_export")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate timeline JSON key")
        obj[key] = value
    return obj


def _bad_constant(_value: str) -> None:
    raise ValueError("Nonfinite timeline value")


def review_offline_soc_stage_timing(
    record_data: bytes, *, expected_record_sha256: str,
) -> dict[str, object]:
    """Return only aggregate stage durations; never infer packet-event latency."""
    if (type(record_data) is not bytes or not 0 < len(record_data) <= MAX_TIMING_RECORD_BYTES
            or type(expected_record_sha256) is not str
            or _SHA.fullmatch(expected_record_sha256) is None
            or not hmac.compare_digest(hashlib.sha256(record_data).hexdigest(),
                                       expected_record_sha256)):
        raise ValueError("Expected bounded independently pinned timeline JSON")
    try:
        record = json.loads(record_data.decode("utf-8", errors="strict"),
                            object_pairs_hook=_unique_pairs, parse_constant=_bad_constant)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise ValueError("Malformed timing record") from exc
    if (type(record) is not dict
            or set(record) != {"record_version", "clock_basis", "timestamps_utc",
                                  "declared_evidence_sha256"}
            or type(record["record_version"]) is not int
            or record["record_version"] != 1
            or record["clock_basis"] != "single_operator_host_utc"):
        raise ValueError("Unsupported operator timing record")
    pins = record["declared_evidence_sha256"]
    if (type(pins) is not dict or set(pins) != set(_EVIDENCE)
            or any(type(pins[key]) is not str or _SHA.fullmatch(pins[key]) is None
                   for key in _EVIDENCE)):
        raise ValueError("Expected five declared evidence SHA-256 references")
    timestamps = record["timestamps_utc"]
    if type(timestamps) is not dict or set(timestamps) != set(_STAGES):
        raise ValueError("Expected exact ordered stage timestamp fields")
    parsed = []
    for stage in _STAGES:
        value = timestamps[stage]
        if type(value) is not str or _UTC.fullmatch(value) is None:
            raise ValueError("Expected explicit UTC timestamp with Z suffix")
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Invalid UTC timestamp") from exc
        if dt.utcoffset().total_seconds() != 0:
            raise ValueError("UTC timestamp required")
        parsed.append(dt)
    if any(later < earlier for earlier, later in zip(parsed, parsed[1:])):
        raise ValueError("Offline stage timestamps are out of order")
    if (parsed[-1] - parsed[0]).total_seconds() > 7 * 24 * 3600:
        raise ValueError("Offline stage record exceeds seven days")
    milliseconds = [
        round((later - earlier).total_seconds() * 1000, 3)
        for earlier, later in zip(parsed, parsed[1:])
    ]
    return {
        "report_version": 1,
        "mode": "operator_recorded_offline_soc_stage_timing_only",
        "record_sha256": expected_record_sha256,
        "stage_order": list(_STAGES),
        "stage_duration_ms": dict(zip(
            ("capture_complete_to_zeek_ready",
             "zeek_ready_to_inference_start",
             "inference_processing",
             "inference_end_to_queue_ready",
             "queue_ready_to_manual_soc_case"), milliseconds,
        )),
        "capture_complete_to_manual_soc_case_ms": round(
            (parsed[-1] - parsed[0]).total_seconds() * 1000, 3
        ),
        "declared_evidence_pin_count": len(_EVIDENCE),
        "evidence_file_bytes_verified": False,
        "operator_clock_verified": False,
        "physical_host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "operational_alert_latency_measured": False,
        "packet_event_to_detection_latency_measured": False,
        "independent_attack_truth_verified": False,
        "interpretation": (
            "Descriptive elapsed times from operator-entered UTC timestamps "
            "for offline stages only. This is NOT packet-event-to-alert latency. "
            "The record's SHA-256 checks only its own bytes; declared evidence "
            "hashes, clock basis, case creation and capture origin are not "
            "independently verified. Keep original evidence and clock notes private."
        ),
    }
