"""Export a private offline Zeek RESEARCH alert-candidate queue, never live alerts.

Re-verifies model, original log, complete saved predictions, and pinned
TRAIN/VALIDATION/TEST manifest/labels before atomic no-overwrite publication.
No network I/O, auto-SOC writes, model training or ground-truth inference.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.new_log_review import MAX_NEW_LOG_REPORT_BYTES
from blue_team_ai.research_alerts import build_verified_research_alert_bundle
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from evaluate_zeek_lab import load_experiment_manifest
from score_zeek_new_log import (
    _private_file, _read_bounded_capture, _write_new_report_atomically,
)
from verify_zeek_new_log_report import _read_bounded


def _sha256_pin(value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        c not in "0123456789abcdef" for c in value
    ):
        raise ValueError("Expected lowercase independently recorded SHA-256")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected-report-sha256", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--cidr", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--measure-research-export-runtime", action="store_true",
                        help="Measure only final verified queue recompute and JSON publication")
    args = parser.parse_args(argv)
    try:
        model_path = _private_file(args.model)
        log_path = _private_file(args.log)
        report_path = _private_file(args.report)
        manifest_path = _private_file(args.manifest)
        if len({model_path, log_path, report_path, manifest_path}) != 4:
            raise ValueError("All pinned inputs must be distinct")
        if report_path.parent != log_path.parent or report_path.suffix.lower() != ".json":
            raise ValueError("Prediction report must be alongside the original log")
        output = args.output.absolute()
        if (
            output.name in ("", ".", "..")
            or output.suffix.lower() != ".json"
            or output.parent.resolve(strict=True) != log_path.parent
            or output.is_relative_to(ROOT)
            or output.exists()
            or output.is_symlink()
        ):
            raise ValueError("Output must be a NEW private JSON beside the original log")
        model_pin = _sha256_pin(args.expected_model_sha256)
        log_pin = _sha256_pin(args.expected_log_sha256)
        report_pin = _sha256_pin(args.expected_report_sha256)
        manifest_pin = _sha256_pin(args.expected_manifest_sha256)
        report_data = _read_bounded(report_path, MAX_NEW_LOG_REPORT_BYTES)
        if not hmac.compare_digest(hashlib.sha256(report_data).hexdigest(), report_pin):
            raise ValueError("Original prediction report SHA-256 differs")
        model = load_pinned_zeek_research_model(model_path, expected_sha256=model_pin)
        source_data = _read_bounded_capture(log_path)
        captures, actual_manifest_sha = load_experiment_manifest(
            manifest_path, lab_cidrs=args.cidr,
            require_label_sha256=True,
            expected_manifest_sha256=manifest_pin,
        )
        dataset = build_labeled_lab_dataset(captures)
        if args.measure_research_export_runtime:
            started_ns = time.perf_counter_ns()
        bundle = build_verified_research_alert_bundle(
            source_data, model, report_data,
            expected_log_sha256=log_pin,
            model_sha256=model_pin,
            lab_cidrs=args.cidr,
            manifest_sha256=actual_manifest_sha,
            declared_dataset=dataset,
            declared_captures=captures,
        )
        payload = json.dumps(bundle, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        _write_new_report_atomically(output, payload)
        if args.measure_research_export_runtime:
            elapsed_ns = time.perf_counter_ns() - started_ns
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError, KeyError, RecursionError):
        print("Private offline research alert-candidate export refused.", file=sys.stderr)
        return 1
    print("Private OFFLINE research alert-candidate bundle published (NOT operational alerts).")
    print("research_alert_candidates_exported=" + str(bundle["research_alert_candidates_exported"]))
    print("candidates_outside_manual_triage_window=" + str(bundle["candidates_outside_manual_triage_window"]))
    print("No automatic SOC case, live capture, confirmed attack or operational alert.")
    if args.measure_research_export_runtime:
        print(f"offline_research_queue_export_duration_ms={elapsed_ns / 1_000_000:.6f}")
        print("offline_research_queue_export_boundary=verified_recompute_json_publish")
        print("detection_latency_measured=false; capture_zeek_analyst_wait_excluded=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
