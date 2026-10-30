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
from blue_team_ai.research_alerts import MAX_RESEARCH_ALERT_BUNDLE_BYTES
from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import
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
    offline_import_report_path: str | Path | None = None,
    offline_import_report_sha256: str | None = None,
    offline_import_pcap_path: str | Path | None = None,
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
    provenance = (
        offline_import_report_path, offline_import_report_sha256,
        offline_import_pcap_path,
    )
    if any(value is not None for value in provenance) and not all(
        value is not None for value in provenance
    ):
        raise ValueError("All three pinned offline PCAP inputs are required")
    report_file = pcap_file = conn_file = None
    inputs = {model_file, manifest_file}
    if all(value is not None for value in provenance):
        report_file = _private_file(Path(offline_import_report_path))
        pcap_file = _private_file(Path(offline_import_pcap_path))
        conn_file = _private_file(report_file.parent / "conn.log")
        inputs.update((report_file, pcap_file, conn_file))
        if len(inputs) != 5:
            raise ValueError("PCAP, Zeek log, report, model and manifest must be distinct")
    database = _private_db(Path(db_path), inputs)
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
        require_label_sha256=True,
        expected_manifest_sha256=expected_manifest_sha256,
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
        offline_import_report_path=report_file,
        offline_import_report_sha256=offline_import_report_sha256,
        offline_import_pcap_path=pcap_file,
        offline_import_log_path=conn_file,
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
    parser.add_argument("--offline-import-report", type=Path,
                        help="Optional original offline_import_report.json")
    parser.add_argument("--expected-offline-import-report-sha256",
                        help="Independently recorded import report SHA-256")
    parser.add_argument("--offline-import-pcap", type=Path,
                        help="Original authorized classic PCAP (offline only)")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--list-candidates", action="store_true")
    action.add_argument("--record-index", type=int)
    parser.add_argument("--db", type=Path, help="Private SQLite path for explicit write only")
    parser.add_argument("--research-alert-bundle", type=Path,
                        help="Optional private exported research queue for strict manual handoff")
    parser.add_argument("--expected-research-alert-bundle-sha256",
                        help="Independent original SHA-256 of exported research queue")
    parser.add_argument("--research-alert-ref",
                        help="Original selected 64-character queue reference")
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
        bundle_options = (
            args.research_alert_bundle,
            args.expected_research_alert_bundle_sha256,
            args.research_alert_ref,
        )
        if any(value is not None for value in bundle_options) and not all(
            value is not None for value in bundle_options
        ):
            raise ValueError("All three pinned research queue flags are required")
        bundle_path = None
        if args.research_alert_bundle is not None:
            if args.list_candidates or args.manifest is None:
                raise ValueError("Pinned queue handoff requires a selected index and manifest")
            bundle_path = _private_file(args.research_alert_bundle)
            if (
                bundle_path.parent != log_path.parent
                or bundle_path.suffix.lower() != ".json"
                or bundle_path in inputs
            ):
                raise ValueError("Research queue must be distinct private JSON beside log")
            inputs.add(bundle_path)
        import_options = (
            args.offline_import_report,
            args.expected_offline_import_report_sha256,
            args.offline_import_pcap,
        )
        if any(value is not None for value in import_options) and not all(
            value is not None for value in import_options
        ):
            raise ValueError("All three offline PCAP provenance flags are required")
        import_report_path = None
        import_pcap_path = None
        if all(value is not None for value in import_options):
            import_report_path = _private_file(args.offline_import_report)
            import_pcap_path = _private_file(args.offline_import_pcap)
            if import_report_path in inputs or import_pcap_path in inputs or import_report_path == import_pcap_path:
                raise ValueError("PCAP provenance inputs must be distinct private files")
            inputs.update((import_report_path, import_pcap_path))
        if (args.manifest is None) != (args.expected_manifest_sha256 is None):
            raise ValueError("Manifest and independent digest must be provided together")
        manifest_path = _private_file(args.manifest) if args.manifest is not None else None
        if manifest_path is not None:
            if manifest_path in inputs:
                raise ValueError("Manifest must be distinct from model/log/report")
            inputs.add(manifest_path)
        expected_inputs = 3 + (1 if manifest_path is not None else 0) + (2 if import_report_path is not None else 0) + (1 if bundle_path is not None else 0)
        if len(inputs) != expected_inputs or report_path.parent != log_path.parent or report_path.suffix.lower() != ".json":
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
        if import_report_path is not None:
            verified_import = verify_offline_pcap_import(
                import_report_path,
                expected_report_sha256=args.expected_offline_import_report_sha256,
                pcap_path=import_pcap_path, log_path=log_path, lab_cidrs=args.cidr,
            )
            if verified_import["zeek_conn_sha256"] != args.expected_log_sha256:
                raise ValueError("Pinned new-log bytes differ from verified PCAP import")
        model = load_pinned_zeek_research_model(
            model_path, expected_sha256=args.expected_model_sha256,
        )
        source_data = _read_bounded(log_path, MAX_LOG_BYTES)
        report_data = _read_bounded(report_path, MAX_NEW_LOG_REPORT_BYTES)
        research_bundle_data = (
            _read_bounded(bundle_path, MAX_RESEARCH_ALERT_BUNDLE_BYTES)
            if bundle_path is not None else None
        )
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
                require_label_sha256=True,
                expected_manifest_sha256=expected_manifest_sha,
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
            if import_report_path is not None:
                print("offline_pcap_provenance_reverified=true (bytes and scope only)")
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
            offline_import_report_path=import_report_path,
            offline_import_report_sha256=args.expected_offline_import_report_sha256,
            offline_import_pcap_path=import_pcap_path,
            offline_import_log_path=log_path if import_report_path is not None else None,
            research_bundle_data=research_bundle_data,
            research_bundle_sha256=args.expected_research_alert_bundle_sha256,
            research_alert_ref=args.research_alert_ref,
        )
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError, RecursionError):
        # Never print private IPs, UIDs, paths, model contents or raw evidence.
        print("Private new-log research SOC triage refused.", file=sys.stderr)
        return 1
    print(f"case_id={case_id} verdict=Unclassified (manual research review only)")
    if import_report_path is not None:
        print("offline_pcap_provenance_reverified=true (bytes and scope only)")
    if bundle_path is not None:
        print("pinned_research_bundle_selection_reverified=true")
    print("Existing source+UID case may have been reused; original audit is preserved.")
    print("No confirmed attack, operational AI alert, or real lab detection verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
