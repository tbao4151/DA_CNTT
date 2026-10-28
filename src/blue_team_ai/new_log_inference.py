"""Bounded, offline inference on a NEW operator-owned Zeek conn.log.

Research-only: not a live detector, automatic alert, or SOC case writer.
The caller must first load a data-only model with an independently pinned hash.
No labels or UNSW-NB15 model features are used.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence

from .features import extract_zeek_feature_rows
from .lab_scope import inspect_zeek_lab_scope
from .model_artifact import score_zeek_research_rows, validate_zeek_research_artifact
from .zeek import parse_zeek_conn_log


def score_new_zeek_log(
    raw: bytes,
    model: Mapping[str, object],
    *,
    expected_log_sha256: str,
    lab_cidrs: Sequence[str],
    model_sha256: str,
) -> dict[str, object]:
    """Score only a pinned, scope-screened new capture; fail closed.

    A different hash from TRAIN/VALIDATION does NOT prove this is not the
    preregistered held-out TEST set. The operator must verify that separately.
    """
    if not isinstance(raw, bytes):
        raise ValueError("Expected raw Zeek bytes")
    for digest in (expected_log_sha256, model_sha256):
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ValueError("Expected independently recorded lowercase SHA-256")
    if hashlib.sha256(raw).hexdigest() != expected_log_sha256:
        raise ValueError("New Zeek capture differs from pinned bytes")
    validate_zeek_research_artifact(model)
    if expected_log_sha256 in (
        set(model["train_source_sha256"]) | set(model["validation_source_sha256"])
    ):
        raise ValueError("Cannot score a training or validation capture as new")
    scope = inspect_zeek_lab_scope(raw, lab_cidrs)
    events = parse_zeek_conn_log(raw)
    uids = [event["uid"] for event in events]
    if len(set(uids)) != len(uids):
        raise ValueError("Duplicate Zeek UIDs in one new capture")
    features = extract_zeek_feature_rows(events)
    scores = score_zeek_research_rows(model, features)
    predictions = [
        {
            "uid": event["uid"],
            "event_time_utc": event["event_time_utc"],
            "src_ip": event["src_ip"],
            "src_port": event["src_port"],
            "dst_ip": event["dst_ip"],
            "dst_port": event["dst_port"],
            "attack_probability": result["attack_probability"],
            "research_candidate": result["predicted_attack"],
        }
        for event, result in zip(events, scores, strict=True)
    ]
    return {
        "report_version": 1,
        "mode": "offline_new_zeek_research_inference_only",
        "origin": "offline_zeek_log",
        "model_sha256": model_sha256,
        "source_sha256": expected_log_sha256,
        "declared_scope_sha256": scope["declared_scope_sha256"],
        "feature_schema_version": model["feature_schema_version"],
        "selected_validation_threshold": model["selected_threshold"],
        "flow_count": len(predictions),
        "research_candidate_count": sum(row["research_candidate"] for row in predictions),
        "predictions": predictions,
        "labels_used": False,
        "test_partition_exclusion_verified": False,
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "model_authorship_verified": False,
        "operational_attack_detection_verified": False,
        "automated_alerts": False,
        "soc_cases_created": False,
        "live_capture": False,
        "interpretation": (
            "Offline research scores only. The operator must independently confirm "
            "this log was never used for TRAIN, VALIDATION or held-out TEST, and "
            "verify physical Host-only isolation, authorization and model validity. "
            "Predicted candidates are not confirmed attacks or operational alerts."
        ),
    }
