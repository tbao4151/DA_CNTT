"""Offline, read-only consistency audit of a PRIVATE VMware Zeek SCP snapshot.

Checks fetched conn.log, its collector receipt, and optional research predictions.
No host connection, model inference, labels, network stimulus, or SOC write.
Self-consistent hashes DO NOT establish capture authenticity or VMware isolation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.lab_scope import inspect_zeek_lab_scope
from blue_team_ai.zeek import MAX_LOG_BYTES, parse_zeek_conn_log

MAX_JSON_BYTES = 16 * 1024 * 1024
_RECEIPT = re.compile(r"zeek_conn_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{12}\.receipt\.json\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FALSE_CAPTURE = ("host_only_isolation_verified", "capture_authenticity_verified",
                  "attack_detection_performed", "red_team_execution_performed")
_FALSE_REPORT = ("labels_used", "test_partition_exclusion_verified",
                 "host_only_isolation_verified", "capture_authenticity_verified",
                 "model_authorship_verified", "operational_attack_detection_verified",
                 "automated_alerts", "soc_cases_created", "live_capture")


def _bytes(path: Path, limit: int) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Private input must be an absolute non-symlink file")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT):
        raise ValueError("Evidence must stay outside the repository")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(resolved, flags)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Evidence must be a regular file")
        raw = handle.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ValueError("Missing or oversized evidence")
    return raw


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON property")
        obj[key] = value
    return obj


def _json(raw: bytes) -> dict:
    def reject_constant(_token):
        raise ValueError("Non-finite JSON constant")
    parsed = json.loads(raw.decode("utf-8", "strict"),
                        object_pairs_hook=_unique_object,
                        parse_constant=reject_constant)
    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object")
    return parsed


def _digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _require_digest(raw: bytes, expected: str | None) -> str:
    actual = hashlib.sha256(raw).hexdigest()
    if expected is not None and (not _digest(expected) or actual != expected):
        raise ValueError("Evidence differs from independently supplied SHA-256")
    return actual


def _assert_false_fields(report: dict, fields: tuple[str, ...]) -> None:
    if any(report.get(key) is not False for key in fields):
        raise ValueError("Evidence attempts to claim unverified operational state")


def _compare_predictions(report: dict, events: list[dict]) -> None:
    rows = report.get("predictions")
    if not isinstance(rows, list) or len(rows) != len(events):
        raise ValueError("Research predictions must cover exactly the Zeek flows")
    count = 0
    for row, event in zip(rows, events, strict=True):
        if not isinstance(row, dict):
            raise ValueError("Invalid prediction")
        for field, original in (
            ("uid", event["uid"]),
            ("event_time_utc", event["event_time_utc"]),
            ("src_ip", event["src_ip"]),
            ("dst_ip", event["dst_ip"]),
            ("src_port", event["src_port"]),
            ("dst_port", event["dst_port"]),
        ):
            if type(row.get(field)) is not type(original) or row[field] != original:
                raise ValueError("Research row differs from original Zeek flow")
        probability = row.get("attack_probability")
        candidate = row.get("research_candidate")
        if (type(probability) not in (int, float) or not math.isfinite(probability)
                or not 0 <= probability <= 1 or type(candidate) is not bool):
            raise ValueError("Invalid research-only probability/candidate")
        count += int(candidate)
    if type(report.get("research_candidate_count")) is not int or count != report["research_candidate_count"]:
        raise ValueError("Research candidate tally differs from original rows")


def verify_bundle(
    receipt_path: Path,
    *,
    research_report_path: Path | None = None,
    expected_receipt_sha256: str | None = None,
    expected_research_sha256: str | None = None,
) -> dict[str, object]:
    """Recheck source bytes, Zeek fields, scope and per-flow prediction references."""
    if (research_report_path is None) != (expected_research_sha256 is None):
        if expected_research_sha256 is not None:
            raise ValueError("Expected research SHA-256 requires research report")
    if not _RECEIPT.fullmatch(receipt_path.name):
        raise ValueError("Not a canonical Zeek SCP snapshot receipt name")
    receipt_raw = _bytes(receipt_path, MAX_JSON_BYTES)
    receipt_sha = _require_digest(receipt_raw, expected_receipt_sha256)
    receipt = _json(receipt_raw)
    base = receipt_path.name[:-len(".receipt.json")]
    log_name = base + ".log"
    if (receipt.get("version") != 1
            or receipt.get("capture_kind") != "read_only_vmware_scp_snapshot_unverified"
            or receipt.get("local_log_filename") != log_name
            or not _digest(receipt.get("log_sha256"))
            or receipt.get("scope_screen_passed") is not True):
        raise ValueError("Invalid bounded SCP receipt contract")
    _assert_false_fields(receipt, _FALSE_CAPTURE)
    # All source paths are generated from the canonical receipt name, not JSON.
    log_path = receipt_path.parent / log_name
    raw = _bytes(log_path, MAX_LOG_BYTES)
    log_sha = _require_digest(raw, receipt["log_sha256"])
    if type(receipt.get("bytes")) is not int or receipt["bytes"] != len(raw):
        raise ValueError("Snapshot byte count differs from receipt")
    cidr = receipt.get("declared_cidr")
    if not isinstance(cidr, str):
        raise ValueError("Missing declared lab CIDR")
    # Re-run strict Zeek parsing and subnet checks on the original pinned bytes.
    scope = inspect_zeek_lab_scope(raw, [cidr])
    if (type(receipt.get("flow_count")) is not int
            or receipt["flow_count"] != scope["flow_count"]
            or receipt.get("first_event_utc") != scope["first_event_utc"]
            or receipt.get("last_event_utc") != scope["last_event_utc"]):
        raise ValueError("Original Zeek event counts/time range differ from receipt")
    report_sha = None
    candidates = None
    if research_report_path is not None:
        expected_name = base + ".research.json"
        if research_report_path.name != expected_name or research_report_path.parent.resolve(strict=True) != receipt_path.parent.resolve(strict=True):
            raise ValueError("Research report must belong to this exact snapshot")
        report_raw = _bytes(research_report_path, MAX_JSON_BYTES)
        report_sha = _require_digest(report_raw, expected_research_sha256)
        report = _json(report_raw)
        if (report.get("report_version") != 1
                or report.get("mode") != "offline_new_zeek_research_inference_only"
                or report.get("origin") != "offline_zeek_log"
                or report.get("source_sha256") != log_sha
                or report.get("declared_scope_sha256") != scope["declared_scope_sha256"]
                or not _digest(report.get("model_sha256"))
                or type(report.get("flow_count")) is not int
                or report["flow_count"] != scope["flow_count"]):
            raise ValueError("Research report source/scope contract mismatch")
        _assert_false_fields(report, _FALSE_REPORT)
        _compare_predictions(report, parse_zeek_conn_log(raw))
        candidates = report["research_candidate_count"]
    return {
        "mode": "offline_vmware_snapshot_byte_consistency_audit",
        "receipt_sha256": receipt_sha,
        "log_sha256": log_sha,
        "research_report_sha256": report_sha,
        "flow_count": scope["flow_count"],
        "research_candidate_count": candidates,
        "original_zeek_scope_reparsed": True,
        "receipt_source_consistency_checked": True,
        "research_rows_matched_to_original_flows": research_report_path is not None,
        "independent_receipt_digest_supplied": expected_receipt_sha256 is not None,
        "independent_research_digest_supplied": expected_research_sha256 is not None,
        "guest_snapshot_authenticity_verified": False,
        "physical_vmware_isolation_verified": False,
        "packet_to_flow_causality_verified": False,
        "attack_detection_verified": False,
        "ground_truth_verified": False,
        "one_click_dual_ai_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--research-report", type=Path)
    parser.add_argument("--expected-receipt-sha256")
    parser.add_argument("--expected-research-sha256")
    args = parser.parse_args(argv)
    try:
        result = verify_bundle(
            args.receipt, research_report_path=args.research_report,
            expected_receipt_sha256=args.expected_receipt_sha256,
            expected_research_sha256=args.expected_research_sha256,
        )
    except (OSError, ValueError, TypeError, OverflowError, UnicodeError, KeyError):
        # Do not leak endpoint IPs, filenames, private paths or flow UIDs.
        print("Private VMware evidence consistency audit refused.", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
