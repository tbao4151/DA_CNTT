"""Read-only verification of private offline Zeek new-log research predictions.

No network, retraining, label lookup, SOC write or operational alert.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import
from blue_team_ai.new_log_review import (
    MAX_NEW_LOG_REPORT_BYTES, review_pinned_new_log_report,
)
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from blue_team_ai.zeek import MAX_LOG_BYTES


def _private_file(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Direct symlinks are not accepted")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT) or not resolved.is_file():
        raise ValueError("Input must be a regular private file outside Git")
    return resolved


def _read_bounded(path: Path, limit: int) -> bytes:
    if path.is_symlink():
        raise ValueError("Symlink input not accepted")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected a regular private file")
        return stream.read(limit + 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--cidr", action="append", required=True,
                        help="Actual authorized RFC1918 Host-only subnet (repeat up to four)")
    parser.add_argument("--offline-import-report", type=Path,
                        help="Optional original PCAP-to-Zeek import report")
    parser.add_argument("--expected-offline-import-report-sha256",
                        help="Separately recorded original import-report SHA-256")
    parser.add_argument("--offline-import-pcap", type=Path,
                        help="Original private classic PCAP")
    args = parser.parse_args(argv)
    try:
        model_path = _private_file(args.model)
        log_path = _private_file(args.log)
        report_path = _private_file(args.report)
        if len({model_path, log_path, report_path}) != 3:
            raise ValueError("Model, capture and report must be separate files")
        if report_path.parent != log_path.parent or report_path.suffix.lower() != ".json":
            raise ValueError("Report must be private JSON alongside capture")
        import_options = (
            args.offline_import_report,
            args.expected_offline_import_report_sha256,
            args.offline_import_pcap,
        )
        if any(option is not None for option in import_options):
            if not all(option is not None for option in import_options):
                raise ValueError("All PCAP provenance options must be supplied")
            verified_import = verify_offline_pcap_import(
                args.offline_import_report,
                expected_report_sha256=args.expected_offline_import_report_sha256,
                pcap_path=args.offline_import_pcap,
                log_path=log_path,
                lab_cidrs=args.cidr,
            )
            if verified_import["zeek_conn_sha256"] != args.expected_log_sha256:
                raise ValueError("Pinned log differs from verified PCAP import")
        model = load_pinned_zeek_research_model(
            model_path, expected_sha256=args.expected_model_sha256,
        )
        result = review_pinned_new_log_report(
            _read_bounded(log_path, MAX_LOG_BYTES),
            model,
            _read_bounded(report_path, MAX_NEW_LOG_REPORT_BYTES),
            expected_log_sha256=args.expected_log_sha256,
            lab_cidrs=args.cidr,
            model_sha256=args.expected_model_sha256,
        )
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError):
        # Do not print private paths, IPs, UIDs, model parameters or raw records.
        print("Private Zeek research report verification refused.", file=sys.stderr)
        return 1
    print("Private new-log research report matches recomputed pinned inference.")
    print("report_sha256=" + str(result["report_sha256"]))
    print("flow_count=" + str(result["flow_count"]))
    print("research_candidate_count=" + str(result["research_candidate_count"]))
    print("NOT verified: VMware isolation, TEST exclusion, labels, model authorship or real detection.")
    if all(option is not None for option in import_options):
        print("offline_pcap_provenance_reverified=true (byte integrity and declared scope only)")
    print("No network, SOC case or operational alert generated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
