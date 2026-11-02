"""Synthetic-only read-only regression; no VMware, packet capture or attack."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.offline_runtime_summary import parse_timing_stdout, summarize_pinned_runs


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stdout(stage: str, total: str = "6.000000") -> bytes:
    if stage == "score":
        return ("Private offline Zeek research predictions written (NOT operational alerts).\n"
                "flow_count=12\nresearch_candidate_count=2\n"
                f"offline_new_log_score_publish_duration_ms={total}\n"
                "offline_new_log_score_duration_ms=3.000000\n"
                "offline_new_log_json_serialization_duration_ms=1.000000\n"
                "offline_new_log_json_publish_duration_ms=2.000000\n"
                "offline_new_log_timing_clock=perf_counter_ns_same_process\n"
                "offline_new_log_score_publish_boundary=score_json_atomic_publish\n"
                "detection_latency_measured=false; preflight_capture_zeek_excluded=true\n").encode()
    return ("Private OFFLINE research alert-candidate bundle published (NOT operational alerts).\n"
            "research_alert_candidates_exported=2\ncandidates_outside_manual_triage_window=0\n"
            f"offline_research_queue_export_duration_ms={total}\n"
            "offline_research_queue_recompute_duration_ms=3.000000\n"
            "offline_research_queue_json_serialization_duration_ms=1.000000\n"
            "offline_research_queue_json_publish_duration_ms=2.000000\n"
            "offline_research_queue_timing_clock=perf_counter_ns_same_process\n"
            "offline_research_queue_export_boundary=verified_recompute_json_publish\n"
            "detection_latency_measured=false; capture_zeek_analyst_wait_excluded=true\n").encode()


def fixture(tmp_path):
    trials = []
    for i in range(3):
        item = {}
        for stage in ("score", "queue"):
            name = f"trial-{i}-{stage}.txt"
            raw = stdout(stage)
            (tmp_path / name).write_bytes(raw)
            item[f"{stage}_stdout"] = name
            item[f"{stage}_sha256"] = sha(raw)
        trials.append(item)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": 1, "trials": trials}), encoding="utf-8")
    return manifest, trials


def test_summary_aggregates_three_paired_runs_read_only(tmp_path):
    manifest, _ = fixture(tmp_path)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    result = summarize_pinned_runs(manifest, sha(manifest.read_bytes()), ROOT)
    assert result["trials_count"] == 3
    assert result["stage_statistics_ms"]["score"]["total"] == {
        "min": 6.0, "median": 6.0, "mean": 6.0, "p95_nearest_rank": 6.0, "max": 6.0,
    }
    assert result["stage_statistics_ms"]["queue"]["compute"]["mean"] == 3.0
    assert result["packet_event_to_alert_latency_measured"] is False
    assert result["cross_trial_input_equivalence_verified"] is False
    assert result["soc_cases_created"] is False
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert "trial-" not in json.dumps(result)


def test_cli_emits_only_aggregate_json(tmp_path):
    manifest, _ = fixture(tmp_path)
    command = [sys.executable, str(ROOT / "scripts/summarize_offline_blue_runtime.py"),
               "--manifest", str(manifest), "--expected-manifest-sha256", sha(manifest.read_bytes())]
    process = subprocess.run(command, capture_output=True, text=True)
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["trials_count"] == 3
    assert str(tmp_path) not in process.stdout


@pytest.mark.parametrize("change", [
    "bad_manifest_pin", "changed_stdout", "wrong_stdout_pin", "missing_phase",
    "duplicate_phase", "extra_offline_key", "wrong_clock", "wrong_disclaimer",
    "phase_mismatch", "negative_duration", "path_traversal", "reused_stdout",
    "too_few_trials", "duplicate_manifest_key", "wrong_version", "missing_stdout",
])
def test_fail_closed_no_partial_summary(tmp_path, change):
    manifest, trials = fixture(tmp_path)
    score = tmp_path / trials[0]["score_stdout"]
    if change == "bad_manifest_pin":
        pin = "0" * 64
    else:
        pin = None
        if change == "changed_stdout":
            score.write_bytes(score.read_bytes() + b"tampered\n")
        elif change == "wrong_stdout_pin":
            trials[0]["score_sha256"] = "0" * 64
        elif change in {"missing_phase", "duplicate_phase", "extra_offline_key", "wrong_clock", "wrong_disclaimer", "phase_mismatch", "negative_duration"}:
            raw = score.read_bytes()
            if change == "missing_phase":
                raw = raw.replace(b"offline_new_log_score_duration_ms=3.000000\n", b"")
            elif change == "duplicate_phase":
                raw += b"offline_new_log_score_duration_ms=3.000000\n"
            elif change == "extra_offline_key":
                raw += b"offline_new_log_untrusted_duration_ms=0.000001\n"
            elif change == "wrong_clock":
                raw = raw.replace(b"perf_counter_ns_same_process", b"wall_clock")
            elif change == "wrong_disclaimer":
                raw = raw.replace(b"detection_latency_measured=false", b"detection_latency_measured=true")
            elif change == "phase_mismatch":
                raw = raw.replace(b"score_publish_duration_ms=6.000000", b"score_publish_duration_ms=8.000000")
            else:
                raw = raw.replace(b"score_duration_ms=3.000000", b"score_duration_ms=-3.000000")
            score.write_bytes(raw)
            trials[0]["score_sha256"] = sha(raw)
        elif change == "path_traversal":
            trials[0]["score_stdout"] = "../other.txt"
        elif change == "reused_stdout":
            trials[0]["queue_stdout"] = trials[0]["score_stdout"]
        elif change == "too_few_trials":
            trials.pop()
        elif change == "wrong_version":
            manifest.write_text(json.dumps({"version": True, "trials": trials}), encoding="utf-8")
        elif change == "missing_stdout":
            score.unlink()
        if change == "duplicate_manifest_key":
            manifest.write_text('{"version":1,"version":1,"trials":[]}', encoding="utf-8")
        elif change != "wrong_version":
            manifest.write_text(json.dumps({"version": 1, "trials": trials}), encoding="utf-8")
        pin = sha(manifest.read_bytes())
    with pytest.raises((ValueError, OSError)):
        summarize_pinned_runs(manifest, pin, ROOT)


def test_p95_nearest_rank_and_even_median():
    from blue_team_ai.offline_runtime_summary import _stats
    from decimal import Decimal
    metrics = _stats([Decimal(x) for x in ("1", "2", "3", "9")])
    assert metrics["median"] == 2.5
    assert metrics["p95_nearest_rank"] == 9.0


def test_parser_rejects_non_utf8_and_mismatched_stage():
    with pytest.raises(ValueError):
        parse_timing_stdout(b"\xff", "score")
    with pytest.raises(ValueError):
        parse_timing_stdout(stdout("score"), "queue")


@pytest.mark.parametrize("stage", ["score", "queue"])
def test_parser_accepts_actual_cli_counter_and_notice_contract(stage):
    raw = stdout(stage).decode("utf-8")
    if stage == "score":
        notices = (
            "Pinned declared TRAIN/VALIDATION/TEST and flow identity non-reuse screened.\n"
            "This does NOT independently verify capture history or label truth.\n"
            "Original PCAP/Zeek one-second timestamp presence checked before scoring.\n"
            "This is NOT proof of packet-to-flow derivation or capture authenticity.\n"
            "No SOC case, network traffic, label evaluation or live detection performed.\n"
        )
    else:
        notices = (
            "No automatic SOC case, live capture, confirmed attack or operational alert.\n"
        )
    first, rest = raw.split("\n", 1)
    complete = (first + "\n" + notices + rest).encode("utf-8")
    assert parse_timing_stdout(complete, stage)["total"] == 6


@pytest.mark.parametrize("stage", ["score", "queue"])
@pytest.mark.parametrize("unexpected", [
    "Traceback (most recent call last):",
    "ERROR: command failed after printing success",
    "unexpected_counter=1",
    "flow_count=-1",
    "Private OFFLINE research alert-candidate bundle published (NOT operational alerts).",
])
def test_parser_rejects_unrecognized_stdout_without_partial_success(stage, unexpected):
    if stage == "queue" and unexpected.startswith("Private OFFLINE"):
        unexpected = "Private offline Zeek research predictions written (NOT operational alerts)."
    with pytest.raises(ValueError, match="Unexpected offline CLI stdout line"):
        parse_timing_stdout(stdout(stage) + (unexpected + "\n").encode(), stage)


@pytest.mark.parametrize("stage,counter,line", [
    ("score", "flow_count", b"flow_count=12\\n"),
    ("score", "research_candidate_count", b"research_candidate_count=2\\n"),
    ("queue", "research_alert_candidates_exported", b"research_alert_candidates_exported=2\\n"),
    ("queue", "candidates_outside_manual_triage_window", b"candidates_outside_manual_triage_window=0\\n"),
])
def test_parser_rejects_missing_required_cli_counter(stage, counter, line):
    assert line in stdout(stage)
    with pytest.raises(ValueError, match="Missing required offline CLI counters"):
        parse_timing_stdout(stdout(stage).replace(line, b""), stage)


def test_parser_rejects_more_score_candidates_than_flows():
    raw = stdout("score").replace(b"research_candidate_count=2", b"research_candidate_count=13")
    with pytest.raises(ValueError, match="Research candidates exceed flow count"):
        parse_timing_stdout(raw, "score")


@pytest.mark.parametrize("stage,counter", [
    ("score", "flow_count"),
    ("queue", "research_alert_candidates_exported"),
])
def test_parser_rejects_duplicate_or_non_numeric_cli_counters(stage, counter):
    for values in ("1\n" + counter + "=2", "NaN", "9" * 30):
        extra = (counter + "=" + values + "\n").encode()
        with pytest.raises(ValueError, match="Unexpected offline CLI stdout line"):
            parse_timing_stdout(stdout(stage) + extra, stage)
