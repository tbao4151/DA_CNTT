"""Aggregate, read-only quality screening for independently pinned offline Zeek logs.

Not a capture authenticity, physical isolation, labeling or detection test.
No raw IPs, UIDs, ports, paths or free-text protocol/service values are exported.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Sequence

from .features import LAB_FEATURE_COLUMNS, LAB_FEATURE_SCHEMA_VERSION, extract_zeek_feature_rows
from .lab_scope import inspect_zeek_lab_scope
from .zeek import MAX_LOG_BYTES, parse_zeek_conn_log

OPTIONAL_FIELDS = ("service", "duration_s", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")
PROTOCOL_BUCKETS = ("tcp", "udp", "icmp", "other")

# Real Zeek ASCII conn.log type declarations, separate from UNSW-NB15.
# Extra columns are allowed; only parser/model-relevant columns are checked.
ZEEK_EXPECTED_TYPES = {
    "ts": "time", "uid": "string",
    "id.orig_h": "addr", "id.orig_p": "port",
    "id.resp_h": "addr", "id.resp_p": "port",
    "proto": "enum", "service": "string", "duration": "interval",
    "orig_bytes": "count", "resp_bytes": "count",
    "orig_pkts": "count", "resp_pkts": "count",
}
ZEEK_REQUIRED_TYPES = frozenset((
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
))


def inspect_zeek_declared_types(raw: bytes) -> dict[str, object]:
    """Check #fields/#types before flow rows; does not authenticate provenance.

    This opt-in check preserves legacy minimal synthetic fixtures by default.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_LOG_BYTES or b"\\x00" in raw:
        raise ValueError("Invalid bounded Zeek type-contract input")
    lines = raw.decode("utf-8", errors="strict").splitlines()
    if not lines or lines[0] != "#separator \\x09":
        raise ValueError("Expected Zeek ASCII tab separator")
    fields = None
    declared = None
    saw_data = False
    for line in lines[1:]:
        if line.startswith("#fields\\t"):
            if fields is not None or saw_data:
                raise ValueError("Duplicate or late Zeek fields declaration")
            fields = line.split("\\t")[1:]
            if not fields or len(fields) != len(set(fields)):
                raise ValueError("Invalid Zeek fields declaration")
        elif line.startswith("#types\\t"):
            if fields is None or declared is not None or saw_data:
                raise ValueError("Missing fields or duplicate/late Zeek types")
            declared = line.split("\\t")[1:]
            if len(declared) != len(fields):
                raise ValueError("Zeek declared type count differs from fields")
        elif line and not line.startswith("#"):
            saw_data = True
            if declared is None:
                raise ValueError("Zeek types must precede flow records")
    if fields is None or declared is None:
        raise ValueError("Zeek #fields and #types declarations are required")
    mapping = dict(zip(fields, declared, strict=True))
    if not ZEEK_REQUIRED_TYPES.issubset(mapping):
        raise ValueError("Missing required Zeek type declarations")
    for field, expected in ZEEK_EXPECTED_TYPES.items():
        if field in mapping and mapping[field] != expected:
            raise ValueError("Zeek declared field type conflicts with feature contract")
    return {
        "declared_types_checked": True,
        "required_type_fields_checked": len(ZEEK_REQUIRED_TYPES),
        "optional_type_fields_checked": sum(
            key in mapping for key in ZEEK_EXPECTED_TYPES if key not in ZEEK_REQUIRED_TYPES
        ),
        "capture_authenticity_verified": False,
        "host_only_isolation_verified": False,
    }



def inspect_zeek_telemetry_quality(
    raw: bytes, *, expected_sha256: str, lab_cidrs: Sequence[str],
    require_zeek_types: bool = False,
) -> dict[str, object]:
    """Fail closed on byte mismatch, out-of-scope endpoints and repeated UIDs.

    Aggregate missingness is descriptive: absent Zeek counters are NOT zeros.
    Source and timestamps originate in the supplied file, not from a sensor.
    """
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_sha256)
    ):
        raise ValueError("Expected an independently recorded lowercase SHA-256")
    if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Original Zeek bytes differ from pinned reference")

    if type(require_zeek_types) is not bool:
        raise ValueError("Require Zeek types must be boolean")
    declared_types = inspect_zeek_declared_types(raw) if require_zeek_types else None
    scope = inspect_zeek_lab_scope(raw, lab_cidrs)
    events = parse_zeek_conn_log(raw)
    uids = [event["uid"] for event in events]
    if len(set(uids)) != len(uids):
        raise ValueError("Duplicate Zeek UID in source capture")
    features = extract_zeek_feature_rows(events)
    if len(features) != scope["flow_count"]:
        raise ValueError("Feature projection changed flow count")

    missing = {field: sum(row[field] is None for row in features) for field in OPTIONAL_FIELDS}
    buckets = Counter(
        row["proto"].lower() if row["proto"].lower() in PROTOCOL_BUCKETS[:-1] else "other"
        for row in features
    )
    out_of_order = sum(
        events[i]["event_time_utc"] < events[i - 1]["event_time_utc"]
        for i in range(1, len(events))
    )
    warnings: list[str] = []
    if len(events) < 30:
        warnings.append("fewer_than_30_flows")
    if any(missing.values()):
        warnings.append("optional_feature_measurements_missing")
    if out_of_order:
        warnings.append("events_not_in_timestamp_order")
    if len(set(event["event_time_utc"] for event in events)) == 1:
        warnings.append("single_observed_event_timestamp")
    return {
        "report_version": 1,
        "mode": "offline_zeek_telemetry_quality_only",
        "source_sha256": expected_sha256,
        "declared_scope_sha256": scope["declared_scope_sha256"],
        "feature_schema_version": LAB_FEATURE_SCHEMA_VERSION,
        "feature_columns": list(LAB_FEATURE_COLUMNS),
        "flow_count": len(events),
        "first_event_utc": scope["first_event_utc"],
        "last_event_utc": scope["last_event_utc"],
        "unique_source_ip_count": scope["unique_source_ip_count"],
        "unique_destination_ip_count": scope["unique_destination_ip_count"],
        "protocol_bucket_counts": {key: buckets[key] for key in PROTOCOL_BUCKETS},
        "missing_optional_feature_counts": missing,
        "out_of_order_timestamp_pairs": out_of_order,
        "warnings": warnings,
        **({"zeek_declared_types": declared_types} if declared_types is not None else {}),
        "declared_cidr_membership_checked": True,
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "independent_ground_truth_verified": False,
        "model_fitted": False,
        "attack_detection_performed": False,
        "operational_alerts": False,
        "live_capture": False,
        "interpretation": (
            "Descriptive quality screen of operator-supplied offline Zeek bytes only. "
            "A valid SHA-256, CIDR match or complete feature row cannot establish "
            "genuine VMware Host-only capture, independent labels or detection accuracy."
        ),
    }
