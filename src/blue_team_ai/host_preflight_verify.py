"""Offline integrity verification of private Windows host preflight originals.

Only checks a separately pinned inventory and its three original files.
Does not parse host routes or certify VMware isolation. No subprocess/network.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

from .windows_host_preflight import (
    COMMANDS,
    MAX_COMMAND_BYTES,
    REPORT_NAME,
    REPO_ROOT,
)

MAX_REPORT_BYTES = 32 * 1024
_FALSE_FLAGS = (
    "host_only_isolation_verified",
    "guest_adapters_verified",
    "guest_routes_verified",
    "network_traffic_generated",
    "attack_detection_performed",
)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate inventory JSON key")
        result[key] = value
    return result


def _private_regular_file(path: Path, limit: int) -> bytes:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.resolve().is_relative_to(REPO_ROOT)):
        raise ValueError("Evidence must be a private regular file outside Git")
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("Evidence missing, empty or oversized")
    return data


def verify_host_preflight(
    report_path: Path, *, expected_report_sha256: str,
) -> dict[str, object]:
    """Verify pinned JSON and the exact original files without writing anything."""
    if (not isinstance(expected_report_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_report_sha256) is None):
        raise ValueError("Require independently recorded lowercase report SHA-256")
    if report_path.name != REPORT_NAME:
        raise ValueError("Expected the original host-network-preflight.json")
    raw = _private_regular_file(report_path, MAX_REPORT_BYTES)
    report_digest = hashlib.sha256(raw).hexdigest()
    if report_digest != expected_report_sha256:
        raise ValueError("Pinned report SHA-256 mismatch")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid UTF-8 JSON inventory") from exc
    if not isinstance(report, dict):
        raise ValueError("Invalid inventory structure")
    if (type(report.get("schema_version")) is not int
            or report["schema_version"] != 1
            or report.get("mode") != "windows_host_read_only_network_preflight"
            or report.get("platform") != "Windows"):
        raise ValueError("Unsupported host preflight inventory")
    if any(report.get(flag) is not False for flag in _FALSE_FLAGS):
        raise ValueError("Unexpected host preflight safety flags")
    if not isinstance(report.get("interpretation"), str):
        raise ValueError("Missing inventory interpretation")
    try:
        stamp = datetime.fromisoformat(report["captured_at_utc"])
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError("Missing timezone")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid capture timestamp") from exc

    files = report.get("files")
    expected_roles = {role for role, _, _ in COMMANDS}
    if not isinstance(files, dict) or set(files) != expected_roles:
        raise ValueError("Unexpected inventory file roles")
    for role, _, filename in COMMANDS:
        item = files[role]
        if not isinstance(item, dict) or set(item) != {"filename", "sha256", "byte_size"}:
            raise ValueError("Invalid file inventory entry")
        if item["filename"] != filename:
            raise ValueError("Original filename mismatch")
        if (not isinstance(item["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None):
            raise ValueError("Invalid original SHA-256")
        size = item["byte_size"]
        if type(size) is not int or not 0 < size <= MAX_COMMAND_BYTES:
            raise ValueError("Invalid original byte size")
        original = _private_regular_file(report_path.parent / filename, MAX_COMMAND_BYTES)
        if len(original) != size or hashlib.sha256(original).hexdigest() != item["sha256"]:
            raise ValueError("Original host evidence integrity mismatch")
    return {
        "mode": "offline_pinned_host_preflight_integrity_check",
        "report_sha256": report_digest,
        "original_files_verified": len(COMMANDS),
        "host_only_isolation_verified": False,
        "guest_adapters_verified": False,
        "guest_routes_verified": False,
        "attack_detection_performed": False,
    }
