"""Private offline evidence inventory for an operator-owned VMware/Zeek experiment.

This records hashes and bounded metadata, not proof of isolation, provenance,
authorization, label correctness or attack detection. Never sends network traffic.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .lab_scope import inspect_zeek_lab_scope
from .zeek import MAX_LOG_BYTES

REPO_ROOT = Path(__file__).resolve().parents[2]
MAX_SCREENSHOT_BYTES = 10 * 1024 * 1024
MAX_NOTES_BYTES = 1024 * 1024
MAX_VERSION_BYTES = 16 * 1024
ORIGINS = frozenset({"lab_capture", "offline_replay", "synthetic"})


def _private_file(path: Path, *, role: str, limit: int) -> bytes:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError(f"{role} must be an existing private regular file")
    if path.resolve().is_relative_to(REPO_ROOT):
        raise ValueError(f"{role} must be outside the Git repository")
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ValueError(f"{role} is empty or exceeds the size limit")
    return raw


def _inventory(raw: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "byte_size": len(raw)}


def _plain_text(raw: bytes, *, role: str) -> None:
    try:
        value = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError(f"{role} must be UTF-8 text") from exc
    if not value.strip() or any(ord(char) < 32 and char not in "\r\n\t" for char in value):
        raise ValueError(f"{role} must contain nonempty plain text")


def _screenshot(raw: bytes, *, role: str) -> None:
    if not (raw.startswith(b"\x89PNG\r\n\x1a\n") or raw.startswith(b"\xff\xd8\xff")):
        raise ValueError(f"{role} must have a PNG or JPEG signature")


def build_capture_inventory(
    *,
    log_path: Path,
    expected_log_sha256: str,
    cidrs: Sequence[str],
    origin: str,
    vmware_screenshot: Path,
    host_adapter_screenshot: Path,
    zeek_version_file: Path,
    scenario_notes: Path,
) -> dict[str, object]:
    """Inventory source and supporting evidence without copying private contents."""
    if origin not in ORIGINS:
        raise ValueError("Declare lab_capture, offline_replay or synthetic origin")
    if not isinstance(expected_log_sha256, str) or re.fullmatch(
        r"[0-9a-f]{64}", expected_log_sha256
    ) is None:
        raise ValueError("Expected log SHA-256 must be 64 lowercase hex characters")
    paths = {
        "zeek_conn_log": log_path,
        "vmware_network_screenshot": vmware_screenshot,
        "host_adapter_screenshot": host_adapter_screenshot,
        "zeek_version_output": zeek_version_file,
        "scenario_notes": scenario_notes,
    }
    if len({path.resolve() for path in paths.values()}) != len(paths):
        raise ValueError("Each evidence role must use a distinct original file")
    limits = {
        "zeek_conn_log": MAX_LOG_BYTES,
        "vmware_network_screenshot": MAX_SCREENSHOT_BYTES,
        "host_adapter_screenshot": MAX_SCREENSHOT_BYTES,
        "zeek_version_output": MAX_VERSION_BYTES,
        "scenario_notes": MAX_NOTES_BYTES,
    }
    raw = {
        role: _private_file(path, role=role, limit=limits[role])
        for role, path in paths.items()
    }
    if hashlib.sha256(raw["zeek_conn_log"]).hexdigest() != expected_log_sha256:
        raise ValueError("Original Zeek log does not match the independently recorded SHA-256")
    for role in ("vmware_network_screenshot", "host_adapter_screenshot"):
        _screenshot(raw[role], role=role)
    for role in ("zeek_version_output", "scenario_notes"):
        _plain_text(raw[role], role=role)
    scope = inspect_zeek_lab_scope(raw["zeek_conn_log"], cidrs)
    return {
        "report_version": 1,
        "mode": "private_offline_capture_evidence_inventory",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "origin": origin,
        "origin_operator_declared": True,
        "files": {role: _inventory(value) for role, value in raw.items()},
        "scope_screening": {
            "declared_scope_sha256": scope["declared_scope_sha256"],
            "flow_count": scope["flow_count"],
            "first_event_utc": scope["first_event_utc"],
            "last_event_utc": scope["last_event_utc"],
            "all_endpoints_within_declared_scope": True,
        },
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "authorization_verified": False,
        "scenario_truth_verified": False,
        "attack_detection_performed": False,
        "interpretation": (
            "Hashes and supplied-file structure only. Screenshots, Zeek version "
            "and scenario notes are operator supplied; review original private "
            "evidence manually. CIDR membership does not prove VMware isolation."
        ),
    }


def validate_private_output(output: Path, inputs: Sequence[Path]) -> None:
    """Refuse public, aliased, preexisting or non-JSON destinations."""
    if (
        not output.is_absolute()
        or output.suffix.lower() != ".json"
        or not output.parent.is_dir()
        or output.exists()
        or output.is_symlink()
        or output.resolve().is_relative_to(REPO_ROOT)
        or output.resolve() in {path.resolve() for path in inputs}
    ):
        raise ValueError("Output must be a new private JSON file outside Git")
