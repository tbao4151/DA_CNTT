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
from .zeek import parse_zeek_conn_log

OPTIONAL_FIELDS = ("service", "duration_s", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")
PROTOCOL_BUCKETS = ("tcp", "udp", "icmp", "other")


def inspect_zeek_telemetry_quality(
    raw: bytes, *, expected_sha256: str, lab_cidrs: Sequence[str],
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
