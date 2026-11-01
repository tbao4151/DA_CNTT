"""Read-only offline runtime benchmark for a pinned NEW Zeek research log.

Requires the original private TRAIN/VALIDATION/TEST manifest and captures.
Outputs aggregate timing JSON to stdout only. No labels, network, or SOC writes.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.runtime_benchmark import benchmark_offline_new_log_scoring
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from blue_team_ai.zeek import MAX_LOG_BYTES
from check_zeek_partition_exclusion import (
    _check_digest, _private_regular_file, _read_bounded,
)
from evaluate_zeek_lab import MAX_MANIFEST_BYTES, load_experiment_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--cidr", action="append", required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    args = parser.parse_args(argv)
    # A separate monotonic clock records CLI phases outside the repeated
    # in-memory scoring benchmark; it is NOT packet-to-alert latency.
    started_ns = time.perf_counter_ns()
    try:
        paths = [_private_regular_file(p) for p in (
            args.model, args.manifest, args.log,
        )]
        if len(set(paths)) != 3:
            raise ValueError("Private inputs must be distinct")
        model_path, manifest_path, log_path = paths
        _check_digest(
            _read_bounded(manifest_path, MAX_MANIFEST_BYTES),
            args.expected_manifest_sha256,
        )
        source_data = _read_bounded(log_path, MAX_LOG_BYTES)
        _check_digest(source_data, args.expected_log_sha256)
        model = load_pinned_zeek_research_model(
            model_path, expected_sha256=args.expected_model_sha256,
        )
        captures, manifest_sha256 = load_experiment_manifest(
            manifest_path, lab_cidrs=args.cidr,
            require_label_sha256=True,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
        if manifest_sha256 != args.expected_manifest_sha256:
            raise ValueError("Manifest changed during validation")
        dataset = build_labeled_lab_dataset(captures)
        prepared_ns = time.perf_counter_ns()
        report = benchmark_offline_new_log_scoring(
            source_data, model,
            expected_log_sha256=args.expected_log_sha256,
            model_sha256=args.expected_model_sha256,
            lab_cidrs=args.cidr,
            declared_dataset=dataset,
            declared_manifest_sha256=manifest_sha256,
            declared_captures=captures,
            repetitions=args.repetitions,
            warmup=args.warmup,
        )
        finished_ns = time.perf_counter_ns()
        report["cli_phase_timing"] = {
            "method": "perf_counter_ns_same_process",
            "input_loading_and_manifest_preflight_ms": round(
                (prepared_ns - started_ns) / 1_000_000, 6
            ),
            "benchmark_call_including_gates_and_repetitions_ms": round(
                (finished_ns - prepared_ns) / 1_000_000, 6
            ),
            "pre_output_total_ms": round(
                (finished_ns - started_ns) / 1_000_000, 6
            ),
            "json_serialization_and_stdout_excluded": True,
            "process_startup_and_argument_parsing_excluded": True,
            "packet_capture_and_soc_excluded": True,
            "detection_latency_measured": False,
            "interpretation": (
                "Same-process offline CLI phase durations; benchmark call includes "
                "partition verification, untimed reference, warmups and repeated "
                "scoring. Not one-batch latency or capture-to-SOC time."
            ),
        }
    except (
        ValueError, OSError, TypeError, KeyError, UnicodeError,
        OverflowError, RecursionError,
    ):
        print("Private offline Zeek runtime benchmark refused; inspect local evidence.",
              file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
