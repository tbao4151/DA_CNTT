"""Review pinned new-log research candidates; optionally open ONE manual SOC case.

Offline only. Listing candidates is read-only. Writing requires explicit
operator attestations and a private SQLite destination outside Git.
Neither mode emits operational alerts, generates traffic, or verifies attacks.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.new_log_review import (
    MAX_NEW_LOG_REPORT_BYTES, review_pinned_new_log_report,
)
from blue_team_ai.new_log_triage import create_new_log_candidate_case
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from blue_team_ai.zeek import MAX_LOG_BYTES


def _private_file(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Symlink input is not accepted")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT) or not resolved.is_file():
        raise ValueError("Inputs must be regular private files outside Git")
    return resolved


def _read_bounded(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected a regular private file")
        return stream.read(limit + 1)


def _private_db(path: Path, inputs: set[Path]) -> Path:
    if path.is_symlink() or path.suffix.lower() != ".sqlite3":
        raise ValueError("Database must be a private SQLite file, not a symlink")
    parent = path.parent.resolve(strict=True)
    resolved = parent / path.name
    if (
        resolved.is_relative_to(ROOT) or resolved in inputs
        or (resolved.exists() and not resolved.is_file())
    ):
        raise ValueError("Database must be a separate private file outside Git")
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--cidr", action="append", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--list-candidates", action="store_true")
    action.add_argument("--record-index", type=int)
    parser.add_argument("--db", type=Path, help="Private SQLite path for explicit write only")
    parser.add_argument("--confirm-reviewed", action="store_true")
    parser.add_argument("--confirm-authorized", action="store_true")
    parser.add_argument("--confirm-new-capture", action="store_true",
                        help="Operator attests capture is outside TRAIN/VALIDATION/TEST")
    args = parser.parse_args(argv)
    try:
        model_path = _private_file(args.model)
        log_path = _private_file(args.log)
        report_path = _private_file(args.report)
        inputs = {model_path, log_path, report_path}
        if len(inputs) != 3 or report_path.parent != log_path.parent or report_path.suffix.lower() != ".json":
            raise ValueError("Model, log and report must be separate; report alongside log")
        if args.list_candidates:
            if args.db is not None or any((
                args.confirm_reviewed, args.confirm_authorized, args.confirm_new_capture,
            )):
                raise ValueError("Listing must be read-only")
        elif args.db is None or not all((
            args.confirm_reviewed, args.confirm_authorized, args.confirm_new_capture,
        )):
            raise ValueError("Writing requires private DB and all explicit confirmations")
        db_path = _private_db(args.db, inputs) if args.db is not None else None
        model = load_pinned_zeek_research_model(
            model_path, expected_sha256=args.expected_model_sha256,
        )
        source_data = _read_bounded(log_path, MAX_LOG_BYTES)
        report_data = _read_bounded(report_path, MAX_NEW_LOG_REPORT_BYTES)
        review = review_pinned_new_log_report(
            source_data, model, report_data,
            expected_log_sha256=args.expected_log_sha256,
            lab_cidrs=args.cidr, model_sha256=args.expected_model_sha256,
        )
        if args.list_candidates:
            # The full JSON has already been checked against fresh inference.
            predictions = json.loads(report_data)["predictions"]
            print("Verified OFFLINE research candidates (zero-based index; first 500 flows):")
            for index, row in enumerate(predictions[:500]):
                if row["research_candidate"] is True:
                    print(f"record_index={index} probability={row['attack_probability']:.8f}")
            print("research_candidate_count_total=" + str(review["research_candidate_count"]))
            print("No SOC write, operational alert, or real detection verified.")
            return 0

        case_id = create_new_log_candidate_case(
            db_path, source_data=source_data, model=model,
            report_data=report_data,
            expected_log_sha256=args.expected_log_sha256,
            model_sha256=args.expected_model_sha256,
            lab_cidrs=args.cidr,
            record_index=args.record_index,
            analyst_confirmed=args.confirm_reviewed,
            operator_confirmed_authorized=args.confirm_authorized,
            operator_confirmed_new_capture=args.confirm_new_capture,
        )
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError, RecursionError):
        # Never print private IPs, UIDs, paths, model contents or raw evidence.
        print("Private new-log research SOC triage refused.", file=sys.stderr)
        return 1
    print(f"case_id={case_id} verdict=Unclassified (manual research review only)")
    print("Existing source+UID case may have been reused; original audit is preserved.")
    print("No confirmed attack, operational AI alert, or real lab detection verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
