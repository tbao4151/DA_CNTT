"""Read-only verification of a separately pinned private Zeek capture inventory.

Re-checks all five original evidence files and declared log scope. This does
NOT establish capture authenticity, authorized use or VMware isolation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Sequence

from .capture_evidence import (
    MAX_NOTES_BYTES, MAX_SCREENSHOT_BYTES, MAX_VERSION_BYTES,
    ORIGINS, REPO_ROOT, _plain_text, _private_file, _screenshot,
)
from .lab_scope import inspect_zeek_lab_scope
from .zeek import MAX_LOG_BYTES

MAX_INVENTORY_BYTES = 64 * 1024
LIMITS = {
    "zeek_conn_log": MAX_LOG_BYTES,
    "vmware_network_screenshot": MAX_SCREENSHOT_BYTES,
    "host_adapter_screenshot": MAX_SCREENSHOT_BYTES,
    "zeek_version_output": MAX_VERSION_BYTES,
    "scenario_notes": MAX_NOTES_BYTES,
}
SAFETY_FLAGS = (
    "host_only_isolation_verified", "capture_authenticity_verified",
    "authorization_verified", "scenario_truth_verified",
    "attack_detection_performed",
)
REPORT_KEYS = {
    "report_version", "mode", "recorded_at_utc", "origin",
    "origin_operator_declared", "files", "scope_screening",
    "interpretation", *SAFETY_FLAGS,
}
SCOPE_KEYS = {
    "declared_scope_sha256", "flow_count", "first_event_utc",
    "last_event_utc", "all_endpoints_within_declared_scope",
}


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate inventory JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("Non-finite inventory JSON value")


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def verify_capture_inventory(
    report_path: Path,
    *,
    expected_report_sha256: str,
    log_path: Path,
    vmware_screenshot: Path,
    host_adapter_screenshot: Path,
    zeek_version_file: Path,
    scenario_notes: Path,
    cidrs: Sequence[str],
) -> dict[str, object]:
    """Check pinned report, originals and CIDR-derived aggregates without writes."""
    if not _digest(expected_report_sha256):
        raise ValueError("Require independent lowercase report SHA-256")
    if report_path.suffix.lower() != ".json":
        raise ValueError("Expected private JSON inventory")
    original_paths = {
        "zeek_conn_log": log_path,
        "vmware_network_screenshot": vmware_screenshot,
        "host_adapter_screenshot": host_adapter_screenshot,
        "zeek_version_output": zeek_version_file,
        "scenario_notes": scenario_notes,
    }
    if len({p.resolve() for p in (report_path, *original_paths.values())}) != 6:
        raise ValueError("Inventory and original evidence paths must be distinct")
    raw_report = _private_file(report_path, role="capture inventory", limit=MAX_INVENTORY_BYTES)
    report_sha256 = hashlib.sha256(raw_report).hexdigest()
    if not hmac.compare_digest(report_sha256, expected_report_sha256):
        raise ValueError("Pinned capture inventory SHA-256 mismatch")
    try:
        report = json.loads(
            raw_report.decode("utf-8"), object_pairs_hook=_unique_keys,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid UTF-8 capture inventory JSON") from exc
    if not isinstance(report, dict) or set(report) != REPORT_KEYS:
        raise ValueError("Unsupported capture inventory structure")
    if (type(report["report_version"]) is not int or report["report_version"] != 1
            or report["mode"] != "private_offline_capture_evidence_inventory"
            or report["origin"] not in ORIGINS
            or report["origin_operator_declared"] is not True
            or any(report[flag] is not False for flag in SAFETY_FLAGS)
            or not isinstance(report["interpretation"], str)
            or not report["interpretation"].strip()):
        raise ValueError("Unsupported capture inventory provenance or safety flags")
    try:
        stamp = datetime.fromisoformat(report["recorded_at_utc"])
        if stamp.utcoffset() != timedelta(0):
            raise ValueError("Expected UTC timestamp")
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("Invalid inventory timestamp") from exc

    files = report["files"]
    if not isinstance(files, dict) or set(files) != set(LIMITS):
        raise ValueError("Unexpected evidence roles")
    originals: dict[str, bytes] = {}
    for role, limit in LIMITS.items():
        entry = files[role]
        if not isinstance(entry, dict) or set(entry) != {"sha256", "byte_size"}:
            raise ValueError("Invalid evidence metadata")
        if not _digest(entry["sha256"]):
            raise ValueError("Invalid original SHA-256")
        size = entry["byte_size"]
        if type(size) is not int or not 0 < size <= limit:
            raise ValueError("Invalid original byte size")
        raw = _private_file(original_paths[role], role=role, limit=limit)
        if len(raw) != size or not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest(), entry["sha256"]
        ):
            raise ValueError("Original capture evidence integrity mismatch")
        originals[role] = raw

    for role in ("vmware_network_screenshot", "host_adapter_screenshot"):
        _screenshot(originals[role], role=role)
    for role in ("zeek_version_output", "scenario_notes"):
        _plain_text(originals[role], role=role)
    scope = inspect_zeek_lab_scope(originals["zeek_conn_log"], cidrs)
    recorded_scope = report["scope_screening"]
    if not isinstance(recorded_scope, dict) or set(recorded_scope) != SCOPE_KEYS:
        raise ValueError("Invalid recorded scope")
    if (not _digest(recorded_scope["declared_scope_sha256"])
            or type(recorded_scope["flow_count"]) is not int
            or recorded_scope["all_endpoints_within_declared_scope"] is not True):
        raise ValueError("Invalid recorded scope fields")
    for field in SCOPE_KEYS:
        if recorded_scope[field] != scope[field]:
            raise ValueError("Capture scope evidence mismatch")

    return {
        "mode": "offline_pinned_zeek_capture_inventory_verification",
        "origin_operator_declared": report["origin"],
        "report_sha256": report_sha256,
        "original_files_verified": len(LIMITS),
        "flow_count": scope["flow_count"],
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "authorization_verified": False,
        "scenario_truth_verified": False,
        "attack_detection_performed": False,
    }
