"""Versioned, leakage-resistant feature projection for OFFLINE Zeek conn.log.

No model is trained or invoked here. These fields are NOT UNSW-NB15 features.
Only validated Zeek parser events are accepted; provenance/identity/timestamps
must never be passed to a future lab-specific classifier as model features.
"""
from __future__ import annotations

import ipaddress
import math
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta

LAB_FEATURE_SCHEMA_VERSION = 1
LAB_FEATURE_COLUMNS = (
    "proto", "service", "src_port", "dst_port", "duration_s",
    "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
)
_ZEEK_EVENT_FIELDS = frozenset({
    "origin", "source_sha256", "event_time_utc", "uid",
    "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service",
    "duration_s", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
})
_COUNT_COLUMNS = ("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")

# Model boundaries are stricter than raw Zeek parsing: do not let a manually
# constructed dataset or direct scorer call turn fractional packet counts or
# ports into continuous model features. Keep the v1 feature order unchanged.
_MODEL_NUMERIC_MAX = 1_000_000_000_000


def validate_zeek_model_features(row: Mapping[str, object]) -> None:
    """Validate one projected Zeek v1 row at BOTH fit and scoring boundaries.

    Raw parser/extractor output already has these types. This additional gate
    rejects forged LabeledLabDataset rows and direct scorer inputs, without
    converting missing optional measurements into zeros or floats.
    """
    if not isinstance(row, Mapping) or set(row) != set(LAB_FEATURE_COLUMNS):
        raise ValueError("Unexpected Zeek feature columns")
    for field in ("proto", "service"):
        value = row[field]
        if value is not None and (not isinstance(value, str) or len(value) > 256):
            raise ValueError(f"Invalid categorical Zeek {field}")
    for field in ("src_port", "dst_port"):
        value = row[field]
        if type(value) is not int or not 0 <= value <= 65535:
            raise ValueError(f"Invalid numeric Zeek {field}: expected integer port")
    for field in _COUNT_COLUMNS:
        value = row[field]
        if value is not None and (
            type(value) is not int or not 0 <= value <= _MODEL_NUMERIC_MAX
        ):
            raise ValueError(f"Invalid numeric Zeek {field}: expected integer count")
    duration = row["duration_s"]
    if duration is not None and (
        type(duration) not in (int, float)
        or not math.isfinite(duration)
        or not 0 <= duration <= _MODEL_NUMERIC_MAX
    ):
        raise ValueError("Invalid numeric Zeek duration_s")



def extract_zeek_features(event: Mapping[str, object]) -> dict[str, object]:
    """Project one validated offline Zeek event onto an explicit v1 feature set.

    Missing optional measurements remain None, not zero. This is an extraction
    contract, not imputation, labeling, prediction or source authentication.
    """
    if not isinstance(event, Mapping) or set(event) != _ZEEK_EVENT_FIELDS:
        raise ValueError("Expected exact Zeek offline event v1 fields")
    if event["origin"] != "offline_zeek_log":
        raise ValueError("Only offline Zeek events are supported")
    digest = event["source_sha256"]
    if (
        not isinstance(digest, str) or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
    ):
        raise ValueError("Invalid Zeek source SHA-256")
    uid = event["uid"]
    if not isinstance(uid, str) or not 0 < len(uid) <= 256:
        raise ValueError("Invalid Zeek UID")
    for name in ("src_ip", "dst_ip"):
        try:
            if not isinstance(event[name], str):
                raise ValueError
            ipaddress.ip_address(event[name])
        except ValueError as exc:
            raise ValueError(f"Invalid Zeek {name}") from exc
    timestamp = event["event_time_utc"]
    try:
        if not isinstance(timestamp, str):
            raise ValueError
        parsed = datetime.fromisoformat(timestamp)
        if parsed.utcoffset() != timedelta(0):
            raise ValueError
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("Invalid Zeek UTC event timestamp") from exc

    proto = event["proto"]
    if not isinstance(proto, str) or not 0 < len(proto) <= 32:
        raise ValueError("Invalid Zeek protocol")
    service = event["service"]
    if service is not None and (not isinstance(service, str) or len(service) > 256):
        raise ValueError("Invalid Zeek service")
    for name in ("src_port", "dst_port"):
        value = event[name]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
            raise ValueError(f"Invalid Zeek {name}")
    duration = event["duration_s"]
    if duration is not None and (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or duration < 0
    ):
        raise ValueError("Invalid Zeek duration_s")
    for name in _COUNT_COLUMNS:
        value = event[name]
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise ValueError(f"Invalid Zeek {name}")
    return {name: event[name] for name in LAB_FEATURE_COLUMNS}


def extract_zeek_feature_rows(
    events: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Project a nonempty, single-source ordered batch without dropping rows.

    Output row i corresponds to parsed Zeek event i. No labels, IP addresses,
    UIDs, timestamps, source digests or AI/UI fields enter the feature rows.
    Do not fit a model until independent labels and split protocol are defined.
    """
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)) or not events:
        raise ValueError("Expected a nonempty ordered Zeek event sequence")
    source = events[0].get("source_sha256") if isinstance(events[0], Mapping) else None
    rows = []
    for event in events:
        if not isinstance(event, Mapping) or event.get("source_sha256") != source:
            raise ValueError("Mixed or invalid Zeek source provenance")
        rows.append(extract_zeek_features(event))
    return rows
