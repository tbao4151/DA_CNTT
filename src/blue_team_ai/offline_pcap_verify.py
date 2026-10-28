"""Read-only verification of a separately SHA-pinned offline PCAP -> Zeek import.

Checks the exact original PCAP, Zeek conn.log, report, and declared lab scope.
Does not run Zeek, open sockets, prove capture origin or authenticate attacks.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Sequence

from .lab_scope import inspect_zeek_lab_scope
from .offline_pcap import MAX_PCAP_BYTES, PCAP_MAGICS, _private_path
from .zeek import MAX_LOG_BYTES

MAX_REPORT_BYTES = 64 * 1024
FALSE_FLAGS = (
    "host_only_isolation_verified", "capture_authenticity_verified",
    "authorization_verified", "ground_truth_verified",
    "ai_inference_performed", "automated_alerts", "live_capture",
)
REPORT_KEYS = frozenset({
    "report_version", "mode", "source_kind", "pcap_sha256",
    "pcap_size_bytes", "zeek_conn_sha256", "zeek_conn_size_bytes",
    "flow_count", "declared_scope_sha256",
    "all_endpoints_within_declared_scope", "interpretation", *FALSE_FLAGS,
})


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate offline import report JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite offline import report value")


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _read_private(path: Path, *, limit: int) -> bytes:
    original = Path(path)
    if original.is_symlink():
        raise ValueError("Symlinked private evidence is not supported")
    resolved = _private_path(original, must_exist=True)
    if not resolved.is_file():
        raise ValueError("Private evidence must be a regular file")
    with resolved.open("rb") as source:
        data = source.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("Private evidence is empty or exceeds size limit")
    return data


def verify_offline_pcap_import(
    report_path: str | Path,
    *,
    expected_report_sha256: str,
    pcap_path: str | Path,
    log_path: str | Path,
    lab_cidrs: Sequence[str],
) -> dict[str, object]:
    """Recompute original-file hashes and scope against a separately pinned report.

    All inputs are private, absolute, outside the repository and read-only.
    The pin MUST be recorded separately before verification; a digest taken
    from the report being checked does not provide independent provenance.
    """
    if not _digest(expected_report_sha256):
        raise ValueError("Require an independently recorded lowercase report SHA-256")
    report_file = Path(report_path)
    pcap_file = Path(pcap_path)
    conn_file = Path(log_path)
    if report_file.name != "offline_import_report.json" or conn_file.name != "conn.log":
        raise ValueError("Expected original offline_import_report.json and conn.log")
    resolved = [
        _private_path(path, must_exist=True)
        for path in (report_file, pcap_file, conn_file)
    ]
    if len(set(resolved)) != 3 or resolved[0].parent != resolved[2].parent:
        raise ValueError("Report and conn.log must share a private output directory")

    raw_report = _read_private(report_file, limit=MAX_REPORT_BYTES)
    report_digest = hashlib.sha256(raw_report).hexdigest()
    if not hmac.compare_digest(report_digest, expected_report_sha256):
        raise ValueError("Offline import report SHA-256 mismatch")
    try:
        report = json.loads(
            raw_report.decode("utf-8"),
            object_pairs_hook=_unique_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid UTF-8 offline import report") from exc
    if not isinstance(report, dict) or set(report) != REPORT_KEYS:
        raise ValueError("Unsupported offline import report structure")
    if (type(report["report_version"]) is not int or report["report_version"] != 1
            or report["mode"] != "offline_classic_pcap_to_zeek_import"
            or report["source_kind"] != "operator_supplied_offline_pcap"
            or report["all_endpoints_within_declared_scope"] is not True
            or any(report[flag] is not False for flag in FALSE_FLAGS)
            or not isinstance(report["interpretation"], str)
            or not report["interpretation"].strip()):
        raise ValueError("Invalid import provenance or safety flags")
    if not all(_digest(report[key]) for key in (
        "pcap_sha256", "zeek_conn_sha256", "declared_scope_sha256"
    )):
        raise ValueError("Invalid source digest metadata")

    pcap = _read_private(pcap_file, limit=MAX_PCAP_BYTES)
    conn = _read_private(conn_file, limit=MAX_LOG_BYTES)
    if len(pcap) < 24 or pcap[:4] not in PCAP_MAGICS:
        raise ValueError("Expected a classic PCAP with a valid header")
    if (type(report["pcap_size_bytes"]) is not int
            or report["pcap_size_bytes"] != len(pcap)
            or not hmac.compare_digest(hashlib.sha256(pcap).hexdigest(), report["pcap_sha256"])):
        raise ValueError("Original PCAP differs from the pinned import report")
    if (type(report["zeek_conn_size_bytes"]) is not int
            or report["zeek_conn_size_bytes"] != len(conn)
            or not hmac.compare_digest(hashlib.sha256(conn).hexdigest(), report["zeek_conn_sha256"])):
        raise ValueError("Original Zeek conn.log differs from the pinned import report")
    scope = inspect_zeek_lab_scope(conn, lab_cidrs)
    if (type(report["flow_count"]) is not int
            or report["flow_count"] != scope["flow_count"]
            or report["declared_scope_sha256"] != scope["declared_scope_sha256"]):
        raise ValueError("Recorded Zeek flow count or declared CIDR scope differs")

    return {
        "mode": "offline_pinned_pcap_zeek_import_verification",
        "report_sha256": report_digest,
        "pcap_sha256": report["pcap_sha256"],
        "zeek_conn_sha256": report["zeek_conn_sha256"],
        "flow_count": scope["flow_count"],
        "original_files_verified": 2,
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "authorization_verified": False,
        "ground_truth_verified": False,
        "ai_inference_performed": False,
        "automated_alerts": False,
        "live_capture": False,
    }
