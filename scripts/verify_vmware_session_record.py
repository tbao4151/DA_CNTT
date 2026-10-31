"""Read-only validation of an operator's private first VMware session evidence index.

Checks byte integrity and completeness, NOT authorization or physical isolation.
No network, packet capture, AI scoring, SOC writes or file creation.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = (
    "authorization", "vmware_hostonly_adapters", "guest_route_review",
    "capture_origin",
)
PIN = re.compile(r"[0-9a-f]{64}\Z")
SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{2,63}\Z")


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _read(
    path: Path, limit: int, *, parent: Path | None = None,
    used_file_ids: set[tuple[int, int]] | None = None,
) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Absolute non-symlink private paths required")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT) or (parent is not None and not resolved.is_relative_to(parent)):
        raise ValueError("Evidence path outside private session directory")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Not a regular evidence file")
        # Distinct paths can still be hard links to the same underlying file.
        # Use the opened descriptor's identity to avoid a second path lookup.
        # Some filesystems report inode 0; keep the resolved-path guard there.
        if used_file_ids is not None and metadata.st_ino:
            file_id = (metadata.st_dev, metadata.st_ino)
            if file_id in used_file_ids:
                raise ValueError("Evidence file hard-link reused across roles")
            used_file_ids.add(file_id)
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ValueError("Empty or oversized evidence file")
    return raw


def _json(raw: bytes) -> dict[str, object]:
    obj = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_object_pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    if not isinstance(obj, dict):
        raise ValueError("Expected JSON object")
    return obj


def _pin(raw: bytes, expected: str) -> None:
    if not isinstance(expected, str) or PIN.fullmatch(expected) is None:
        raise ValueError("Invalid SHA-256 pin")
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected):
        raise ValueError("Evidence SHA-256 mismatch")


def _relative_path(base: Path, value: str) -> Path:
    if (not isinstance(value, str) or len(value) > 240 or "\\" in value
            or ":" in value or any(p in ("", ".", "..") for p in value.split("/"))):
        raise ValueError("Invalid relative evidence path")
    path = base.joinpath(*value.split("/"))
    if not path.resolve(strict=True).is_relative_to(base):
        raise ValueError("Evidence path escapes private directory")
    return path


def verify_record(record_path: Path, record_pin: str, chain_path: Path, chain_pin: str) -> dict[str, object]:
    record_raw = _read(record_path, 128 * 1024)
    _pin(record_raw, record_pin)
    base = record_path.resolve(strict=True).parent
    record = _json(record_raw)
    if set(record) != {"record_version", "session_id", "checks"} or type(record["record_version"]) is not int or record["record_version"] != 1:
        raise ValueError("Unsupported session record")
    if not isinstance(record["session_id"], str) or SESSION.fullmatch(record["session_id"]) is None:
        raise ValueError("Invalid session ID")
    checks = record["checks"]
    if not isinstance(checks, dict) or set(checks) != set(CHECKS):
        raise ValueError("Incomplete manual evidence checklist")

    chain_raw = _read(chain_path, 64 * 1024, parent=base)
    _pin(chain_raw, chain_pin)
    chain = _json(chain_raw)
    required_true = (
        "configuration_snapshots_consistent", "offline_pcap_zeek_import_consistent",
        "independent_original_pcap_zeek_pins_verified",
        "independent_original_pcap_zeek_pins_required",
        "pcap_framing_required", "pcap_framing_verified",
    )
    required_false = (
        "vmware_isolation_verified", "capture_authenticity_verified", "traffic_authorized",
        "independent_labels_verified", "ai_inference_performed", "operational_alerts_created",
        "soc_case_created", "live_detection_latency_measured",
    )
    if (type(chain.get("report_version")) is not int or chain["report_version"] != 1
            or chain.get("mode") != "offline_private_lab_evidence_consistency_only"
            or any(chain.get(k) is not True for k in required_true)
            or any(chain.get(k) is not False for k in required_false)):
        raise ValueError("Not a strict, appropriately qualified offline chain report")
    if (type(chain.get("pcap_packet_count")) is not int or chain["pcap_packet_count"] < 1
            or type(chain.get("zeek_flow_count")) is not int or chain["zeek_flow_count"] < 1):
        raise ValueError("No bounded PCAP/Zeek observations")

    statuses: dict[str, str] = {}
    # One operator-supplied file cannot stand in for multiple distinct review roles.
    # This checks path identity, not the truth or independence of the contents.
    used_evidence_paths: set[Path] = set()
    used_file_ids: set[tuple[int, int]] = set()
    for key in CHECKS:
        entry = checks[key]
        if not isinstance(entry, dict) or entry.get("status") not in ("PASS", "FAIL", "NOT_MEASURED"):
            raise ValueError("Invalid manual check")
        status = entry["status"]
        if status == "PASS":
            if set(entry) != {"status", "path", "sha256"}:
                raise ValueError("PASS requires one pinned evidence file")
            evidence_path = _relative_path(base, entry["path"])
            resolved_evidence_path = evidence_path.resolve(strict=True)
            if resolved_evidence_path in used_evidence_paths:
                raise ValueError("Evidence file reused across manual check roles")
            used_evidence_paths.add(resolved_evidence_path)
            raw = _read(
                evidence_path, 4 * 1024 * 1024, parent=base,
                used_file_ids=used_file_ids,
            )
            _pin(raw, entry["sha256"])
        elif set(entry) != {"status"}:
            raise ValueError("Incomplete checks cannot claim pinned evidence")
        statuses[key] = status
    complete = all(value == "PASS" for value in statuses.values())
    return {
        "report_version": 1,
        "mode": "private_operator_session_index_consistency_only",
        "session_id": record["session_id"],
        "strict_offline_chain_report_shape_checked": True,
        "chain_report_sha256": chain_pin,
        "session_record_sha256": record_pin,
        "manual_evidence_hashes_checked": sum(s == "PASS" for s in statuses.values()),
        "recorded_manual_check_statuses": statuses,
        "ready_for_human_evidence_review": complete,
        "vmware_isolation_verified_by_software": False,
        "operator_authorization_verified_by_software": False,
        "capture_authenticity_verified_by_software": False,
        "attack_detection_validated": False,
        "interpretation": "Hash-matched operator-supplied records only; not independent proof of isolation, permission, capture origin, labels or AI detection.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--expected-record-sha256", required=True)
    parser.add_argument("--chain-report", type=Path, required=True)
    parser.add_argument("--expected-chain-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        report = verify_record(args.record, args.expected_record_sha256,
                               args.chain_report, args.expected_chain_sha256)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        print("Private VMware session record verification refused.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    return 0 if report["ready_for_human_evidence_review"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
