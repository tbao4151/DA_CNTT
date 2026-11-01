"""Measure offline Zeek research scoring runtime, not attack detection latency.

Requires a pinned, original TRAIN/VALIDATION/TEST partition and NEW capture.
No model fitting, live collection, alerts, labels, or SOC database writes.
"""
from __future__ import annotations

import math
import platform
import statistics
import sys
import time
from collections.abc import Mapping, Sequence

from .labeled_dataset import LabeledLabDataset
from .new_log_inference import score_new_zeek_log
from .partition_guard import verify_declared_partition_exclusion

MAX_REPETITIONS = 20
MAX_WARMUP = 3


def describe_batch_variability(durations_ns: Sequence[int]) -> dict[str, object]:
    """Descriptive within-run spread; no independence or CI claim.

    This helper accepts integer monotonic durations, not event timestamps.
    It intentionally reports no confidence interval from 1..20 repetitions.
    """
    if not durations_ns or any(type(ns) is not int or ns <= 0 for ns in durations_ns):
        raise ValueError("Positive integer monotonic durations required")
    median_ns = statistics.median(durations_ns)
    mad_ns = statistics.median(abs(ns - median_ns) for ns in durations_ns)
    smallest, largest = min(durations_ns), max(durations_ns)
    return {
        "observations": len(durations_ns),
        "min_batch_ms": round(smallest / 1_000_000, 6),
        "max_batch_ms": round(largest / 1_000_000, 6),
        "range_batch_ms": round((largest - smallest) / 1_000_000, 6),
        "median_absolute_deviation_ms": round(mad_ns / 1_000_000, 6),
        "confidence_interval_estimated": False,
        "interpretation": (
            "Descriptive variation among repeated offline whole-log scoring "
            "calls on this process only; not an uncertainty interval, "
            "live throughput or event-to-SOC detection latency."
        ),
    }


def benchmark_offline_new_log_scoring(
    source_data: bytes,
    model: Mapping[str, object],
    *,
    expected_log_sha256: str,
    model_sha256: str,
    lab_cidrs: Sequence[str],
    declared_dataset: LabeledLabDataset,
    declared_manifest_sha256: str,
    declared_captures: Sequence[Mapping[str, object]],
    repetitions: int = 5,
    warmup: int = 1,
) -> dict[str, object]:
    """Measure parse + scope + feature extraction + inference per whole log.

    File I/O, pinned model loading, partition validation, and JSON serialization
    are excluded from the timed interval. This is a local batch-processing
    runtime, NOT event-to-detection, capture-to-alert or SOC latency.
    """
    if type(repetitions) is not int or not 1 <= repetitions <= MAX_REPETITIONS:
        raise ValueError("Repetitions must be an integer in 1..20")
    if type(warmup) is not int or not 0 <= warmup <= MAX_WARMUP:
        raise ValueError("Warmup must be an integer in 0..3")
    if declared_captures is None or declared_dataset is None:
        raise ValueError("Original declared captures and dataset are required")

    gate = verify_declared_partition_exclusion(
        model, declared_dataset,
        manifest_sha256=declared_manifest_sha256,
        new_capture_sha256=expected_log_sha256,
        declared_captures=declared_captures,
        new_source_data=source_data,
    )
    if gate["declared_flow_identity_nonreuse_checked"] is not True:
        raise ValueError("Original-capture identity screen must pass")

    def score() -> dict[str, object]:
        return score_new_zeek_log(
            source_data, model,
            expected_log_sha256=expected_log_sha256,
            lab_cidrs=lab_cidrs,
            model_sha256=model_sha256,
        )

    reference = score()  # Untimed input/schema/scope preflight.
    for _ in range(warmup):
        if score() != reference:
            raise ValueError("Non-deterministic offline scoring result")

    durations_ns: list[int] = []
    for _ in range(repetitions):
        start = time.perf_counter_ns()
        result = score()
        elapsed = time.perf_counter_ns() - start
        if result != reference:
            raise ValueError("Non-deterministic offline scoring result")
        if elapsed <= 0:
            raise ValueError("Nonpositive monotonic runtime measurement")
        durations_ns.append(elapsed)

    ordered = sorted(durations_ns)
    median_ns = statistics.median(ordered)
    p95_ns = ordered[math.ceil(0.95 * repetitions) - 1]  # Nearest rank.
    flow_count = reference["flow_count"]
    return {
        "report_version": 1,
        "mode": "offline_new_zeek_scoring_batch_runtime_only",
        "source_sha256": expected_log_sha256,
        "model_sha256": model_sha256,
        "declared_manifest_sha256": declared_manifest_sha256,
        "flow_count": flow_count,
        "research_candidate_count": reference["research_candidate_count"],
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "repetitions": repetitions,
        "warmup": warmup,
        "measurement_boundary": (
            "In-memory whole-log scope validation, parsing, feature extraction "
            "and model scoring only; excludes disk I/O, model load, manifest "
            "preflight, JSON serialization and downstream SOC handling."
        ),
        "per_batch_duration_ms": [round(ns / 1_000_000, 6) for ns in durations_ns],
        "batch_timing_variability": describe_batch_variability(durations_ns),
        "median_batch_ms": round(median_ns / 1_000_000, 6),
        "p95_nearest_rank_batch_ms": round(p95_ns / 1_000_000, 6),
        "median_throughput_flows_per_sec": round(
            flow_count * 1_000_000_000 / median_ns, 3
        ),
        "declared_partition_identity_screen_passed": True,
        "independent_partition_history_verified": False,
        "physical_host_only_isolation_verified": False,
        "label_truth_verified": False,
        "operational_attack_detection_verified": False,
        "detection_latency_measured": False,
        "capture_to_alert_latency_measured": False,
        "automated_alerts": False,
        "soc_cases_created": False,
        "live_capture": False,
        "interpretation": (
            "Software-only local offline batch scoring runtime, not detection "
            "delay or attack detection quality. CI synthetic timings are not "
            "student Windows/VMware measurements. Repeat on actual owned "
            "Host-only captures with hardware and capture provenance recorded."
        ),
    }
