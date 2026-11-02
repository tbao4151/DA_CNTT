"""Read-only descriptive summary of pinned, successful offline Blue CLI timings.

No inference, capture, SOC write, or live latency inference. All inputs must be
private operator-retained files; no raw evidence is returned in the summary.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

MAX_MANIFEST_BYTES = 64 * 1024
MAX_STDOUT_BYTES = 32 * 1024
MIN_TRIALS = 3
MAX_TRIALS = 50
MAX_DURATION_MS = Decimal("3600000")
SIX_PLACES = Decimal("0.000001")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\Z")
_PIN = re.compile(r"[0-9a-f]{64}\Z")
_DURATION = re.compile(r"[0-9]+\.[0-9]{6}\Z")

_STAGES = {
    "score": {
        "total": "offline_new_log_score_publish_duration_ms",
        "compute": "offline_new_log_score_duration_ms",
        "serialization": "offline_new_log_json_serialization_duration_ms",
        "publication": "offline_new_log_json_publish_duration_ms",
        "clock": ("offline_new_log_timing_clock", "perf_counter_ns_same_process"),
        "boundary": ("offline_new_log_score_publish_boundary", "score_json_atomic_publish"),
        "disclaimer": "detection_latency_measured=false; preflight_capture_zeek_excluded=true",
        "success": "Private offline Zeek research predictions written (NOT operational alerts).",
    },
    "queue": {
        "total": "offline_research_queue_export_duration_ms",
        "compute": "offline_research_queue_recompute_duration_ms",
        "serialization": "offline_research_queue_json_serialization_duration_ms",
        "publication": "offline_research_queue_json_publish_duration_ms",
        "clock": ("offline_research_queue_timing_clock", "perf_counter_ns_same_process"),
        "boundary": ("offline_research_queue_export_boundary", "verified_recompute_json_publish"),
        "disclaimer": "detection_latency_measured=false; capture_zeek_analyst_wait_excluded=true",
        "success": "Private OFFLINE research alert-candidate bundle published (NOT operational alerts).",
    },
}


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON object key")
        obj[key] = value
    return obj


def _check_pin(pin: str) -> str:
    if not isinstance(pin, str) or _PIN.fullmatch(pin) is None:
        raise ValueError("Invalid independent SHA-256 pin")
    return pin


def _read_regular(path: Path, limit: int) -> bytes:
    if path.is_symlink():
        raise ValueError("Symlink refused")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Regular file required")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Input exceeds bounded size")
    return raw


# Keep the stdout evidence contract aligned with the two CLI success paths.
# Unknown diagnostics must not be silently discarded as if the command succeeded.
_NON_TIMING_NOTICES = {
    "score": frozenset({
        "Private offline Zeek research predictions written (NOT operational alerts).",
        "Pinned declared TRAIN/VALIDATION/TEST and flow identity non-reuse screened.",
        "This does NOT independently verify capture history or label truth.",
        "Original PCAP/Zeek one-second timestamp presence checked before scoring.",
        "This is NOT proof of packet-to-flow derivation or capture authenticity.",
        "No SOC case, network traffic, label evaluation or live detection performed.",
    }),
    "queue": frozenset({
        "Private OFFLINE research alert-candidate bundle published (NOT operational alerts).",
        "No automatic SOC case, live capture, confirmed attack or operational alert.",
    }),
}
_NON_TIMING_COUNTERS = {
    "score": frozenset({"flow_count", "research_candidate_count"}),
    "queue": frozenset({"research_alert_candidates_exported", "candidates_outside_manual_triage_window"}),
}
_COUNTER_VALUE = re.compile(r"[0-9]{1,12}\Z")


def _validate_non_timing_lines(lines: list[str], stage: str) -> None:
    """Refuse unrecognized CLI stdout, including appended failures or other stages."""
    seen_counters: set[str] = set()
    for line in lines:
        if line.startswith("offline_") or line.startswith("detection_latency_measured="):
            continue  # Strict timing-key validation is performed below.
        if line in _NON_TIMING_NOTICES[stage]:
            continue
        key, sep, value = line.partition("=")
        if (sep and key in _NON_TIMING_COUNTERS[stage]
                and key not in seen_counters and _COUNTER_VALUE.fullmatch(value)):
            seen_counters.add(key)
            continue
        raise ValueError("Unexpected offline CLI stdout line")


def parse_timing_stdout(raw: bytes, stage: str) -> dict[str, Decimal]:
    """Require all expected successful CLI markers and consistent phase sums."""
    if stage not in _STAGES:
        raise ValueError("Unsupported stage")
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as exc:
        raise ValueError("Non-UTF8 timing input") from exc
    spec = _STAGES[stage]
    _validate_non_timing_lines(lines, stage)
    if lines.count(spec["success"]) != 1 or lines.count(spec["disclaimer"]) != 1:
        raise ValueError("Missing successful offline boundary")
    expected = {spec[key] for key in ("total", "compute", "serialization", "publication")}
    expected.update((spec["clock"][0], spec["boundary"][0]))
    observed: dict[str, str] = {}
    for line in lines:
        if not (line.startswith("offline_") or line.startswith("detection_latency_measured=")):
            continue
        if line == spec["disclaimer"]:
            continue
        if "=" not in line:
            raise ValueError("Malformed timing key")
        key, value = line.split("=", 1)
        if key not in expected or key in observed:
            raise ValueError("Unexpected or duplicate offline timing key")
        observed[key] = value
    if set(observed) != expected:
        raise ValueError("Missing timing key")
    if observed[spec["clock"][0]] != spec["clock"][1]:
        raise ValueError("Wrong clock")
    if observed[spec["boundary"][0]] != spec["boundary"][1]:
        raise ValueError("Wrong timing boundary")
    values = {}
    for field in ("total", "compute", "serialization", "publication"):
        value = observed[spec[field]]
        if _DURATION.fullmatch(value) is None:
            raise ValueError("Invalid duration")
        number = Decimal(value)
        if number > MAX_DURATION_MS:
            raise ValueError("Duration exceeds research bound")
        values[field] = number
    if abs(values["total"] - sum((values[k] for k in ("compute", "serialization", "publication")), Decimal(0))) > Decimal("0.000003"):
        raise ValueError("Inconsistent rounded phases")
    return values


def _stats(values: list[Decimal]) -> dict[str, float]:
    ordered = sorted(values)
    n = len(ordered)
    median = (ordered[(n - 1) // 2] + ordered[n // 2]) / 2
    p95 = ordered[math.ceil(n * 0.95) - 1]  # nearest-rank, no interpolation
    metrics = {
        "min": ordered[0], "median": median, "mean": sum(ordered) / n,
        "p95_nearest_rank": p95, "max": ordered[-1],
    }
    return {k: float(v.quantize(SIX_PLACES, rounding=ROUND_HALF_UP)) for k, v in metrics.items()}


def summarize_pinned_runs(manifest_path: Path, expected_manifest_sha256: str, repo_root: Path) -> dict:
    """Summarize paired trials without exposing input names, timestamps or contents."""
    _check_pin(expected_manifest_sha256)
    if manifest_path.is_symlink():
        raise ValueError("Manifest symlink refused")
    source = manifest_path.resolve(strict=True)
    if source.is_relative_to(repo_root.resolve()) or not source.is_file():
        raise ValueError("Manifest must be a private regular file outside repository")
    raw = _read_regular(source, MAX_MANIFEST_BYTES)
    if hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
        raise ValueError("Manifest SHA-256 mismatch")
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed manifest") from exc
    if not isinstance(manifest, dict) or set(manifest) != {"version", "trials"} or type(manifest["version"]) is not int or manifest["version"] != 1:
        raise ValueError("Invalid manifest contract")
    trials = manifest["trials"]
    if not isinstance(trials, list) or not MIN_TRIALS <= len(trials) <= MAX_TRIALS:
        raise ValueError("Require 3-50 paired trials")
    used: set[str] = set()
    all_values = {stage: {k: [] for k in ("total", "compute", "serialization", "publication")} for stage in _STAGES}
    for trial in trials:
        if not isinstance(trial, dict) or set(trial) != {"score_stdout", "score_sha256", "queue_stdout", "queue_sha256"}:
            raise ValueError("Invalid paired trial")
        for stage in ("score", "queue"):
            name = trial[f"{stage}_stdout"]
            if not isinstance(name, str) or not _NAME.fullmatch(name) or name in (".", "..") or name in used:
                raise ValueError("Invalid or reused private stdout name")
            used.add(name)
            expected = _check_pin(trial[f"{stage}_sha256"])
            file_path = source.parent / name
            original = _read_regular(file_path, MAX_STDOUT_BYTES)
            if hashlib.sha256(original).hexdigest() != expected:
                raise ValueError("Pinned stdout SHA-256 mismatch")
            parsed = parse_timing_stdout(original, stage)
            for field, value in parsed.items():
                all_values[stage][field].append(value)
    return {
        "mode": "offline_blue_research_runtime_descriptive_only",
        "trials_count": len(trials),
        "duration_unit": "milliseconds",
        "p95_definition": "nearest_rank",
        "stage_statistics_ms": {
            stage: {field: _stats(values) for field, values in fields.items()}
            for stage, fields in all_values.items()
        },
        "original_stdout_sha256_verified": True,
        "cross_trial_input_equivalence_verified": False,
        "original_pcap_zeek_verified": False,
        "independent_ground_truth_verified": False,
        "vmware_isolation_verified": False,
        "packet_event_to_alert_latency_measured": False,
        "end_to_end_pipeline_wall_clock_measured": False,
        "operational_alerts_created": False,
        "soc_cases_created": False,
    }
