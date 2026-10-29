"""Verify a manually created NEW-log SOC case against pinned offline evidence.

Read-only software consistency check; never an operational alert or attack
confirmation. Private inputs must remain outside the Git repository.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import
from blue_team_ai.partition_guard import verify_declared_partition_exclusion
from blue_team_ai.soc_evidence_link import verify_new_log_soc_case_link
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from blue_team_ai.new_log_review import MAX_NEW_LOG_REPORT_BYTES
from blue_team_ai.zeek import MAX_LOG_BYTES
from evaluate_zeek_lab import MAX_MANIFEST_BYTES, load_experiment_manifest
from triage_zeek_new_log import _private_file, _read_bounded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--case-id", type=int, required=True)
    parser.add_argument("--record-index", type=int, required=True)
    parser.add_argument("--cidr", action="append", required=True)
    parser.add_argument("--offline-import-report", type=Path)
    parser.add_argument("--expected-offline-import-report-sha256")
    parser.add_argument("--offline-import-pcap", type=Path)
    args = parser.parse_args(argv)
    try:
        model_path = _private_file(args.model)
        log_path = _private_file(args.log)
        report_path = _private_file(args.report)
        manifest_path = _private_file(args.manifest)
        db_path = _private_file(args.db)
        paths = {model_path, log_path, report_path, manifest_path, db_path}
        if (len(paths) != 5 or db_path.suffix.lower() != ".sqlite3"
                or report_path.suffix.lower() != ".json"
                or report_path.parent != log_path.parent):
            raise ValueError("Private evidence files must be distinct and correctly located")
        import_options = (
            args.offline_import_report,
            args.expected_offline_import_report_sha256,
            args.offline_import_pcap,
        )
        imported = None
        if any(value is not None for value in import_options):
            if not all(value is not None for value in import_options):
                raise ValueError("PCAP provenance options must be provided together")
            import_report = _private_file(args.offline_import_report)
            import_pcap = _private_file(args.offline_import_pcap)
            if len(paths | {import_report, import_pcap}) != 7:
                raise ValueError("Original PCAP provenance files must be distinct")
            imported = verify_offline_pcap_import(
                import_report,
                expected_report_sha256=args.expected_offline_import_report_sha256,
                pcap_path=import_pcap, log_path=log_path, lab_cidrs=args.cidr,
            )
            if imported["zeek_conn_sha256"] != args.expected_log_sha256:
                raise ValueError("PCAP import does not match independently pinned log")

        manifest_bytes = _read_bounded(manifest_path, MAX_MANIFEST_BYTES)
        manifest_pin = args.expected_manifest_sha256
        if (len(manifest_pin) != 64
                or any(c not in "0123456789abcdef" for c in manifest_pin)
                or hashlib.sha256(manifest_bytes).hexdigest() != manifest_pin):
            raise ValueError("Manifest SHA-256 pin mismatch")
        captures, manifest_sha = load_experiment_manifest(
            manifest_path, lab_cidrs=args.cidr,
            require_label_sha256=True,
            expected_manifest_sha256=manifest_pin,
        )
        if manifest_sha != manifest_pin:
            raise ValueError("Manifest changed during validation")
        dataset = build_labeled_lab_dataset(captures)
        model = load_pinned_zeek_research_model(
            model_path, expected_sha256=args.expected_model_sha256,
        )
        source_data = _read_bounded(log_path, MAX_LOG_BYTES)
        report_data = _read_bounded(report_path, MAX_NEW_LOG_REPORT_BYTES)
        verify_declared_partition_exclusion(
            model, dataset, manifest_sha256=manifest_sha,
            new_capture_sha256=args.expected_log_sha256,
            declared_captures=captures, new_source_data=source_data,
        )
        result = verify_new_log_soc_case_link(
            db_path, source_data=source_data, model=model,
            report_data=report_data,
            expected_log_sha256=args.expected_log_sha256,
            model_sha256=args.expected_model_sha256,
            lab_cidrs=args.cidr, record_index=args.record_index,
            case_id=args.case_id,
            expected_manifest_sha256=manifest_pin,
            expected_import_report_sha256=(
                imported["report_sha256"] if imported is not None else None
            ),
            expected_pcap_sha256=(
                imported["pcap_sha256"] if imported is not None else None
            ),
        )
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError, RecursionError):
        # No private paths, UIDs, IPs, labels or model contents on failure.
        print("Private NEW-log SOC evidence-link verification refused.", file=sys.stderr)
        return 1
    print(f"case_id={result['case_id']} offline_soc_evidence_link_verified=true")
    print("report_sha256=" + str(result["report_sha256"]))
    print("pinned_declared_partitions_screened=true (not complete historical proof)")
    if all(value is not None for value in import_options):
        print("offline_pcap_import_reverified=true (bytes and declared scope only)")
    print("sqlite_read_only=true; stored_snapshot_and_initial_audit_match=true")
    print("NOT verified: independent labels, physical Host-only isolation, "
          "operational alerts, real attack detection or event-to-SOC latency.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
