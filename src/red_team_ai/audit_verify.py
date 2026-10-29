"""Read-only verification of an exported offline Red Team planning chronology.

This checks reproducibility and optional independently recorded byte integrity.
It cannot authenticate the operator, feedback, actual Blue Team outcomes or lab.
No network, file writes, scenario execution, or SOC operations.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from .planning_audit import export_planning_audit

MAX_AUDIT_BYTES = 1_048_576
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key in offline planning audit")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise ValueError("Non-finite JSON values are not accepted")


def verify_planning_audit_bytes(
    raw: bytes, *, expected_sha256: str | None = None,
) -> dict[str, object]:
    """Recompute the entire export from the ordered event history.

    A supplied SHA-256 must be recorded independently BEFORE verification.
    Without a pin, this only validates internal structure/reproducibility.
    """
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_AUDIT_BYTES:
        raise ValueError("Offline audit must be bounded nonempty JSON bytes")
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str) or _SHA256.fullmatch(expected_sha256) is None
    ):
        raise ValueError("Expected independent SHA-256 must be lowercase hex")
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError("Offline audit SHA-256 does not match independent pin")
    try:
        decoded = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid UTF-8 offline planning audit JSON") from exc
    if not isinstance(decoded, Mapping) or not isinstance(decoded.get("events"), list):
        raise ValueError("Expected offline audit object with event list")
    canonical = export_planning_audit(decoded["events"])
    # Compare serialized types, not Python dict equality (True == 1).
    encoded = lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    )
    if encoded(decoded) != encoded(canonical):
        raise ValueError("Export metadata differs from recomputed offline history")
    return {
        "mode": "offline_red_team_planning_audit_verification_only",
        "audit_sha256": digest,
        "independent_pin_verified": expected_sha256 is not None,
        "proposal_count": canonical["proposals"],
        "manual_feedback_count": canonical["manual_feedback_count"],
        "pending_proposal": canonical["pending_proposal_id"] is not None,
        "policy_replay_consistent": True,
        "feedback_origin": "operator_entered_unverified",
        "network_access": False,
        "execution_performed": False,
        "blue_team_outcomes_verified": False,
        "attack_detection_measured": False,
        "capture_to_soc_latency_measured": False,
    }
