"""Read-only SHA-256-pinned audit of PRIVATE VMware stepwise JSONL telemetry.

No VMware/SSH/packet/model/SOC operations. A PASS means a file is internally
consistent with a strict software stage contract, NOT that the VM produced it
or that traffic, attack, AI inference or SOC action occurred.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 1024 * 1024
MAX_LINES = 128
PIN = re.compile(r"[0-9a-f]{64}\Z")
KIND = "da005_vmware_stepwise_progress_v1"
TERM_KIND = "da005_vmware_stepwise_terminal_v1"
MODE = "operator_assisted_benign_hostonly_experiment"
STAGE_EVIDENCE = "program_execution_only_not_independently_verified"
FLAGS = (
    "vmware_isolation_verified", "attack_executed",
    "ai_attack_planning_executed", "operational_ai_detection_verified",
    "soc_alerts_created",
)
STEPS = (
    ("preflight", "completed", ()),
    ("red", "running", ()),
    ("red", "completed", ("attempted_probes",)),
    ("zeek", "running", ()),
    ("zeek", "completed", ("snapshot_flow_count",)),
    ("blue", "skipped_or_completed", None),
    ("audit", "running", ()),
    ("audit", "completed", ("candidate_matches", "unmatched_attempts")),
    ("soc", "skipped", ()),
)
TERMINAL_FIELDS = {
    "mode", "network_attempts", "captured_log_flow_count",
    "research_candidate_count", "ssh_fetch_performed",
    "blue_research_scoring_performed", "vmware_isolation_verified",
    "attack_executed", "operational_ai_detection_verified",
    "soc_alerts_created",
}


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON property")
        obj[key] = value
    return obj


def _json(raw: str) -> dict:
    data = json.loads(
        raw, object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")),
    )
    if not isinstance(data, dict):
        raise ValueError("JSON line must be an object")
    return data


def _count(value) -> bool:
    return type(value) is int and 0 <= value <= 10000


def _event(obj: dict, seq: int, stage: str, status: str, count_fields: tuple | None) -> dict:
    required = {
        "kind", "seq", "observed_at_utc", "stage", "status",
        "mode", "stage_evidence", *FLAGS,
    }
    if set(obj) != required and set(obj) != required | {"counts"}:
        raise ValueError("Unexpected event property")
    if obj.get("kind") != KIND or obj.get("seq") != seq:
        raise ValueError("Invalid event identity or sequence")
    if obj.get("mode") != MODE or obj.get("stage_evidence") != STAGE_EVIDENCE:
        raise ValueError("Unverified mode or provenance changed")
    if any(obj.get(flag) is not False for flag in FLAGS):
        raise ValueError("Event claims unverified VMware/AI/SOC state")
    if obj.get("stage") != stage:
        raise ValueError("Step omitted or out of order")
    if status == "skipped_or_completed":
        if obj.get("status") not in ("skipped", "completed"):
            raise ValueError("Blue step must be skipped or completed")
    elif obj.get("status") != status:
        raise ValueError("Invalid step transition")
    timestamp = obj.get("observed_at_utc")
    if not isinstance(timestamp, str) or not (
        timestamp.endswith("Z") or timestamp.endswith("+00:00")
    ):
        raise ValueError("UTC timestamp required")
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)", timestamp) is None:
        raise ValueError("Non-canonical UTC event timestamp")
    try:
        moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Unparseable timestamp") from exc
    if moment.utcoffset() != timedelta(0):
        raise ValueError("Unexpected UTC offset")
    if count_fields is None:
        count_fields = ("research_candidate_count",) if obj["status"] == "completed" else ()
    if count_fields:
        counts = obj.get("counts")
        if not isinstance(counts, dict) or set(counts) != set(count_fields):
            raise ValueError("Incorrect stage counter set")
        if not all(_count(value) for value in counts.values()):
            raise ValueError("Invalid count")
    elif "counts" in obj:
        raise ValueError("Unexpected counter outside stage completion")
    return obj


def _terminal(obj: dict, events: list[dict]) -> str:
    if obj.get("kind") != TERM_KIND or obj.get("status") not in (
        "dry_run", "completed", "refused",
    ):
        raise ValueError("Invalid terminal")
    status = obj["status"]
    if status == "refused":
        if set(obj) != {
            "kind", "status", "attack_executed",
            "operational_ai_detection_verified", "soc_alerts_created",
        } or any(obj.get(k) is not False for k in (
            "attack_executed", "operational_ai_detection_verified", "soc_alerts_created",
        )):
            raise ValueError("Refused output claims operational success")
        return status

    if set(obj) != {"kind", "status", "result"}:
        raise ValueError("Unexpected terminal property")
    report = obj.get("result")
    if not isinstance(report, dict) or set(report) not in (
        TERMINAL_FIELDS, TERMINAL_FIELDS | {"fresh_guest_snapshot_export_performed"},
    ):
        raise ValueError("Terminal must be a strictly redacted summary")
    # New code records an optional verified-software-path flag, while old
    # SHA-pinned private audit files remain backward compatible. Any claimed
    # guest export requires real SCP and cannot be paired with a Blue bridge.
    fresh = report.get("fresh_guest_snapshot_export_performed", False)
    if type(fresh) is not bool or (fresh and (
        report.get("ssh_fetch_performed") is not True
        or report.get("blue_research_scoring_performed") is not False
    )):
        raise ValueError("Fresh guest export contradicts SCP or Blue research mode")
    if any(report.get(k) is not False for k in (
        "vmware_isolation_verified", "attack_executed",
        "operational_ai_detection_verified", "soc_alerts_created",
    )):
        raise ValueError("Terminal claims unverified operational state")
    if not _count(report.get("network_attempts")) or any(
        type(report.get(k)) is not bool
        for k in ("ssh_fetch_performed", "blue_research_scoring_performed")
    ):
        raise ValueError("Invalid terminal counters or flags")
    if report.get("captured_log_flow_count") is not None and not _count(
        report["captured_log_flow_count"]
    ):
        raise ValueError("Invalid flow count")
    if report.get("research_candidate_count") is not None and not _count(
        report["research_candidate_count"]
    ):
        raise ValueError("Invalid Blue count")
    if status == "dry_run":
        if report["mode"] != "DRY_RUN_EXECUTION_OFF" or len(events) != 1 or (
            events[0]["stage"], events[0]["status"]
        ) != ("preflight", "dry_run"):
            raise ValueError("Dry-run has executable stage evidence")
        if any((
            report["network_attempts"] != 0,
            report["captured_log_flow_count"] is not None,
            report["research_candidate_count"] is not None,
            report["ssh_fetch_performed"],
            fresh,
            report["blue_research_scoring_performed"],
        )):
            raise ValueError("Dry-run claims network or inference")
    else:
        if report["mode"] != "STEPWISE_VMWARE_BENIGN_CAPTURE" or len(events) != len(STEPS):
            raise ValueError("Completed session lacks mandatory steps")
        if report["ssh_fetch_performed"] is not True or not _count(
            report["captured_log_flow_count"]
        ):
            raise ValueError("Completed session lacks Zeek snapshot count")
        if report["network_attempts"] != events[2]["counts"]["attempted_probes"]:
            raise ValueError("Probe count differs between event and terminal")
        if report["captured_log_flow_count"] != events[4]["counts"]["snapshot_flow_count"]:
            raise ValueError("Zeek flow count differs between event and terminal")
        blue_completed = events[5]["status"] == "completed"
        if report["blue_research_scoring_performed"] is not blue_completed:
            raise ValueError("Blue stage differs from terminal")
        if blue_completed:
            if report["research_candidate_count"] != events[5]["counts"]["research_candidate_count"]:
                raise ValueError("Blue count differs between event and terminal")
        elif report["research_candidate_count"] is not None:
            raise ValueError("Skipped Blue stage has fake candidate count")
    return status


def _read_private(path: Path, expected_sha256: str) -> bytes:
    if not isinstance(expected_sha256, str) or PIN.fullmatch(expected_sha256) is None:
        raise ValueError("Independent lowercase SHA-256 pin is mandatory")
    if not path.is_absolute() or path.suffix.lower() != ".jsonl":
        raise ValueError("Require an absolute .jsonl file")
    if path.is_symlink() or path.resolve(strict=True).is_relative_to(ROOT):
        raise ValueError("Private evidence may not be a symlink or within Git")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected regular evidence file")
        data = stream.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("Missing, oversized, SHA-256 mismatched or altered progress file")
    if not data.endswith(b"\n") or data.startswith(b"\xef\xbb\xbf"):
        raise ValueError("Incomplete final line or UTF-8 BOM")
    return data


def audit(path: Path, expected_sha256: str) -> dict:
    data = _read_private(path, expected_sha256)
    rows = data.decode("utf-8", "strict").splitlines()
    if len(rows) > MAX_LINES or not rows or any(not line.strip() for line in rows):
        raise ValueError("Missing, extra or empty JSONL lines")
    records = [_json(line) for line in rows]
    terminal = records[-1]
    events = records[:-1]
    if len(events) > len(STEPS):
        raise ValueError("Too many events")
    if events and events[0].get("stage") == "preflight" and events[0].get("status") == "dry_run":
        if len(events) != 1:
            raise ValueError("Dry-run cannot continue with network steps")
        _event(events[0], 1, "preflight", "dry_run", ())
    else:
        for pos, event in enumerate(events):
            stage, status, fields = STEPS[pos]
            _event(event, pos + 1, stage, status, fields)
    # A valid sequence number cannot salvage a trace with a clock moving
    # backwards. This is a consistency screen, not independent clock sync.
    # Equal timestamps are allowed for rapid consecutive Python events.
    timestamps = [
        datetime.fromisoformat(event["observed_at_utc"].replace("Z", "+00:00"))
        for event in events
    ]
    if any(later < earlier for earlier, later in zip(timestamps, timestamps[1:])):
        raise ValueError("UTC event timestamps move backwards")
    status = _terminal(terminal, events)
    if status == "dry_run" and len(events) != 1:
        raise ValueError("Invalid dry-run evidence")
    if status == "completed" and len(events) != len(STEPS):
        raise ValueError("Missing completed phases")
    # Refusal can happen before preflight, during a benign probe, or during
    # SSH/Zeek; do not equate a partial prefix with a successful experiment.
    return {
        "kind": "da005_vmware_progress_file_audit_v1",
        "scope": "offline_internal_consistency_only",
        "progress_sha256": expected_sha256,
        "stage_events": len(events),
        "terminal_status": status,
        "jsonl_integrity_screen_passed": True,
        "vmware_isolation_verified": False,
        "attack_executed": False,
        "operational_ai_detection_verified": False,
        "soc_alerts_created": False,
        "physical_capture_authenticity_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jsonl-file", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    options = parser.parse_args(argv)
    try:
        report = audit(options.jsonl_file, options.expected_sha256)
    except (ValueError, OSError, TypeError, UnicodeError, RecursionError):
        print("DA005 progress file audit refused. Check independent SHA-256 and private evidence.", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
