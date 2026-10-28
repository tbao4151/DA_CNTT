"""Review pinned new-log research candidates; optionally open ONE manual SOC case.

Offline only. Listing candidates is read-only. Writing requires explicit
operator attestations and a private SQLite destination outside Git.
Neither mode emits operational alerts, generates traffic, or verifies attacks.
"""
from __future__ import annotations

import argparse
import hashlib
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
from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.partition_guard import verify_declared_partition_exclusion
from evaluate_zeek_lab import MAX_MANIFEST_BYTES, load_experiment_manifest
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



def create_ui_candidate_case(
    *, db_path: str | Path, model_path: str | Path,
    manifest_path: str | Path, expected_manifest_sha256: str,
    source_data: bytes, report_data: bytes,
    expected_log_sha256: str, expected_model_sha256: str,
    lab_cidrs: list[str], record_index: int,
    analyst_confirmed: bool, operator_confirmed_authorized: bool,
    operator_confirmed_new_capture: bool,
) -> int:
    """UI write boundary: reload pinned private evidence, then manual SOC triage.

    A prior UI preview is never sufficient authorization or partition evidence.
    No socket access, auto-alert, or confirmed attack classification.
    """
    if not all((
        analyst_confirmed is True, operator_confirmed_authorized is True,
        operator_confirmed_new_capture is True,
    )):
        raise ValueError("All three explicit analyst attestations are required")
    if not isinstance(source_data, bytes) or not 0 < len(source_data) <= MAX_LOG_BYTES:
        raise ValueError("Invalid bounded original Zeek log")
    if not isinstance(report_data, bytes) or not 0 < len(report_data) <= MAX_NEW_LOG_REPORT_BYTES:
        raise ValueError("Invalid bounded original prediction report")
    if (
        not isinstance(expected_log_sha256, str)
        or len(expected_log_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_log_sha256)
        or hashlib.sha256(source_data).hexdigest() != expected_log_sha256
    ):
        raise ValueError("Original NEW-log SHA-256 does not match independent reference")

    model_file = _private_file(Path(model_path))
    manifest_file = _private_file(Path(manifest_path))
    if model_file == manifest_file:
        raise ValueError("Model and manifest must be distinct private files")
    database = _private_db(Path(db_path), {model_file, manifest_file})
    manifest_bytes = _read_bounded(manifest_file, MAX_MANIFEST_BYTES)
    if (
        not 0 < len(manifest_bytes) <= MAX_MANIFEST_BYTES
        or not isinstance(expected_manifest_sha256, str)
        or len(expected_manifest_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_manifest_sha256)
        or hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256
    ):
        raise ValueError("Pinned manifest SHA-256 mismatch at SOC write boundary")
    captures, manifest_sha = load_experiment_manifest(
        manifest_file, lab_cidrs=lab_cidrs,
    )
    if manifest_sha != expected_manifest_sha256:
        raise ValueError("Manifest changed during SOC write validation")
    dataset = build_labeled_lab_dataset(captures)
    model = load_pinned_zeek_research_model(
        model_file, expected_sha256=expected_model_sha256,
    )
    return create_new_log_candidate_case(
        database, source_data=source_data, model=model,
        report_data=report_data, expected_log_sha256=expected_log_sha256,
        model_sha256=expected_model_sha256, lab_cidrs=lab_cidrs,
        record_index=record_index, analyst_confirmed=analyst_confirmed,
        operator_confirmed_authorized=operator_confirmed_authorized,
        operator_confirmed_new_capture=operator_confirmed_new_capture,
        declared_dataset=dataset, declared_manifest_sha256=manifest_sha,
        declared_captures=captures,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--manifest", type=Path,
                        help="Optional private preregistered TRAIN/VALIDATION/TEST manifest")
    parser.add_argument("--expected-manifest-sha256",
                        help="Independent SHA-256 pin required when --manifest is supplied")
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
        if (args.manifest is None) != (args.expected_manifest_sha256 is None):
            raise ValueError("Manifest and independent digest must be provided together")
        manifest_path = _private_file(args.manifest) if args.manifest is not None else None
        if manifest_path is not None:
            if manifest_path in inputs:
                raise ValueError("Manifest must be distinct from model/log/report")
            inputs.add(manifest_path)
        if len(inputs) != (4 if manifest_path is not None else 3) or report_path.parent != log_path.parent or report_path.suffix.lower() != ".json":
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
        declared_dataset = None
        declared_captures = None
        if manifest_path is not None:
            manifest_bytes = _read_bounded(manifest_path, MAX_MANIFEST_BYTES)
            expected_manifest_sha = args.expected_manifest_sha256
            if (
                len(expected_manifest_sha) != 64
                or any(ch not in "0123456789abcdef" for ch in expected_manifest_sha)
                or hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha
            ):
                raise ValueError("Independently pinned manifest SHA-256 mismatch")
            captures, manifest_sha = load_experiment_manifest(
                manifest_path, lab_cidrs=args.cidr,
            )
            if manifest_sha != expected_manifest_sha:
                raise ValueError("Manifest changed during validation")
            declared_dataset = build_labeled_lab_dataset(captures)
            declared_captures = captures
            verify_declared_partition_exclusion(
                model, declared_dataset, manifest_sha256=manifest_sha,
                new_capture_sha256=args.expected_log_sha256,
                declared_captures=captures, new_source_data=source_data,
            )
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
            if declared_dataset is not None:
                print("Pinned declared-partition exact-byte non-reuse checked; "
                      "normalized UID/time/five-tuple identity overlap checked; "
                      "historical/semantic independence NOT verified.")
            else:
                print("Declared TEST exclusion NOT checked; operator attestation only.")
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
            declared_dataset=declared_dataset,
            declared_manifest_sha256=args.expected_manifest_sha256,
            declared_captures=declared_captures,
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
