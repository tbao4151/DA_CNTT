"""Synthetic read-only receipt checks; no network, model or VMware subprocess."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.offline_receipt_verify import verify_paired_receipts


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def stdout(stage: str) -> bytes:
    if stage == "score":
        return (
            "Private offline Zeek research predictions written (NOT operational alerts).\n"
            "flow_count=12\nresearch_candidate_count=2\n"
            "No SOC case, network traffic, label evaluation or live detection performed.\n"
            "offline_new_log_score_publish_duration_ms=6.000000\n"
            "offline_new_log_score_duration_ms=3.000000\n"
            "offline_new_log_json_serialization_duration_ms=1.000000\n"
            "offline_new_log_json_publish_duration_ms=2.000000\n"
            "offline_new_log_timing_clock=perf_counter_ns_same_process\n"
            "offline_new_log_score_publish_boundary=score_json_atomic_publish\n"
            "detection_latency_measured=false; preflight_capture_zeek_excluded=true\n"
        ).encode()
    return (
        "Private OFFLINE research alert-candidate bundle published (NOT operational alerts).\n"
        "research_alert_candidates_exported=2\n"
        "candidates_outside_manual_triage_window=0\n"
        "No automatic SOC case, live capture, confirmed attack or operational alert.\n"
        "offline_research_queue_export_duration_ms=6.000000\n"
        "offline_research_queue_recompute_duration_ms=3.000000\n"
        "offline_research_queue_json_serialization_duration_ms=1.000000\n"
        "offline_research_queue_json_publish_duration_ms=2.000000\n"
        "offline_research_queue_timing_clock=perf_counter_ns_same_process\n"
        "offline_research_queue_export_boundary=verified_recompute_json_publish\n"
        "detection_latency_measured=false; capture_zeek_analyst_wait_excluded=true\n"
    ).encode()


def make_manifest(folder: Path):
    trials = []
    for number in range(3):
        trial_id = f"{number:03d}"
        entry = {"trial_id": trial_id}
        for stage in ("score", "queue"):
            prefix = f"trial-{trial_id}-{stage}"
            out = folder / f"{prefix}-output.json"
            out.write_bytes(b'{"research":true}\n')
            original_stdout = stdout(stage)
            (folder / f"{prefix}.stdout.txt").write_bytes(original_stdout)
            (folder / f"{prefix}.stderr.txt").write_bytes(b"")
            script = "score_zeek_new_log.py" if stage == "score" else "export_zeek_research_alerts.py"
            flag = ("--measure-inference-publication-runtime" if stage == "score"
                    else "--measure-research-export-runtime")
            receipt = {
                "version": 1, "stage": stage, "trial_id": trial_id,
                "command_argv_private": [
                    sys.executable, str(ROOT / "scripts" / script), "--output", str(out), flag
                ],
                "started_utc": "2026-11-03T00:00:00.000+00:00",
                "finished_utc": "2026-11-03T00:00:01.000+00:00",
                "external_process_wall_duration_ms_not_detection_latency": 1000.0,
                "exit_code": 0, "timed_out": False, "launch_failed": False,
                "python_version": "3.12.9",
                "stdout_file": f"{prefix}.stdout.txt",
                "stdout_sha256": sha(original_stdout), "stdout_bytes": len(original_stdout),
                "stderr_file": f"{prefix}.stderr.txt",
                "stderr_sha256": sha(b""), "stderr_bytes": 0,
                "timing_stdout_contract_valid": True,
                "output_sha256": sha(out.read_bytes()),
                "successful_offline_timing_trial": True,
                "vmware_isolation_or_capture_authenticity_verified": False,
                "packet_to_alert_latency_measured": False,
            }
            name = f"{prefix}.receipt.json"
            receipt_raw = (json.dumps(receipt, indent=2) + "\n").encode()
            (folder / name).write_bytes(receipt_raw)
            entry[f"{stage}_receipt"] = name
            entry[f"{stage}_sha256"] = sha(receipt_raw)
        trials.append(entry)
    manifest = folder / "receipt-manifest.json"
    manifest.write_text(json.dumps({"version": 1, "trials": trials}), encoding="utf-8")
    return manifest, trials


def test_successful_paired_receipts_are_read_only_and_privacy_safe(tmp_path):
    manifest, _ = make_manifest(tmp_path)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    result = verify_paired_receipts(manifest, sha(manifest.read_bytes()), ROOT)
    assert result["paired_trials_verified"] == 3
    assert result["recorded_exit_codes_zero_and_stream_hashes_verified"] is True
    assert result["retained_published_json_sha256_verified"] is True
    assert result["packet_event_to_alert_latency_measured"] is False
    assert result["independent_process_authenticity_verified"] is False
    assert str(tmp_path) not in json.dumps(result)
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


@pytest.mark.parametrize("mutation", [
    "bad_manifest_pin", "tampered_stdout", "tampered_output", "tampered_receipt",
    "failed_exit", "nonempty_stderr", "wrong_script", "wrong_stage",
    "duplicate_trial_id", "missing_output", "duplicate_json_key", "missing_receipt",
])
def test_tamper_and_false_success_refused(tmp_path, mutation):
    manifest, trials = make_manifest(tmp_path)
    first = trials[0]
    name = first["score_receipt"]
    receipt_file = tmp_path / name
    receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
    if mutation == "tampered_stdout":
        (tmp_path / receipt["stdout_file"]).write_bytes(b"success-looking but untrusted\n")
    elif mutation == "tampered_output":
        (tmp_path / "trial-000-score-output.json").write_bytes(b'{"stale":true}\n')
    elif mutation == "tampered_receipt":
        receipt_file.write_bytes(receipt_file.read_bytes() + b" ")
    elif mutation == "missing_output":
        (tmp_path / "trial-000-score-output.json").unlink()
    elif mutation == "missing_receipt":
        receipt_file.unlink()
    elif mutation in {"failed_exit", "nonempty_stderr", "wrong_script", "wrong_stage"}:
        if mutation == "failed_exit":
            receipt["exit_code"] = 1
        elif mutation == "nonempty_stderr":
            stderr = b"warning\n"
            (tmp_path / receipt["stderr_file"]).write_bytes(stderr)
            receipt["stderr_bytes"] = len(stderr)
            receipt["stderr_sha256"] = sha(stderr)
        elif mutation == "wrong_script":
            receipt["command_argv_private"][1] = str(ROOT / "scripts" / "train_siem.py")
        else:
            receipt["stage"] = "queue"
        receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
        first["score_sha256"] = sha(receipt_file.read_bytes())
    elif mutation == "duplicate_trial_id":
        trials[1]["trial_id"] = trials[0]["trial_id"]
    elif mutation == "duplicate_json_key":
        receipt_file.write_bytes(b'{"version":1,"version":1}')
        first["score_sha256"] = sha(receipt_file.read_bytes())
    if mutation in {"failed_exit", "nonempty_stderr", "wrong_script", "wrong_stage",
                    "duplicate_trial_id", "duplicate_json_key"}:
        manifest.write_text(json.dumps({"version": 1, "trials": trials}), encoding="utf-8")
    pin = "0" * 64 if mutation == "bad_manifest_pin" else sha(manifest.read_bytes())
    with pytest.raises((ValueError, OSError)):
        verify_paired_receipts(manifest, pin, ROOT)


def test_refuses_missing_or_unpinned_manifest(tmp_path):
    manifest, _ = make_manifest(tmp_path)
    with pytest.raises(ValueError):
        verify_paired_receipts(manifest, "not-a-sha", ROOT)
    with pytest.raises((ValueError, OSError)):
        verify_paired_receipts(tmp_path / "missing.json", "0" * 64, ROOT)


@pytest.mark.parametrize(("field", "invalid"), [
    ("started_utc", "2026-11-03T00:00:00+00:00"),
    ("started_utc", "2026-11-03T07:00:00.000+07:00"),
    ("started_utc", "2026-11-03T00:00:60.000+00:00"),
    ("finished_utc", "2026-11-02T23:59:59.000+00:00"),
    ("external_process_wall_duration_ms_not_detection_latency", -1.0),
    ("external_process_wall_duration_ms_not_detection_latency", True),
    ("external_process_wall_duration_ms_not_detection_latency", "NaN"),
    ("external_process_wall_duration_ms_not_detection_latency", 4.0),
    ("external_process_wall_duration_ms_not_detection_latency", 4_000_000.0),
])
def test_refuses_invalid_recorder_clock_even_when_receipt_is_repinned(
    tmp_path, field, invalid
):
    manifest, trials = make_manifest(tmp_path)
    receipt_file = tmp_path / trials[0]["score_receipt"]
    receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
    receipt[field] = invalid
    receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
    trials[0]["score_sha256"] = sha(receipt_file.read_bytes())
    manifest.write_text(json.dumps({"version": 1, "trials": trials}), encoding="utf-8")
    with pytest.raises((ValueError, OSError)):
        verify_paired_receipts(manifest, sha(manifest.read_bytes()), ROOT)


def test_opt_in_runtime_summary_uses_only_verified_receipts(tmp_path):
    manifest, _ = make_manifest(tmp_path)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    pin = sha(manifest.read_bytes())
    default = verify_paired_receipts(manifest, pin, ROOT)
    assert "stage_statistics_ms" not in default
    result = verify_paired_receipts(
        manifest, pin, ROOT, include_runtime_summary=True
    )
    assert result["paired_trials_verified"] == result["trials_count"] == 3
    assert result["runtime_summary_source"] == "verified_paired_subprocess_receipts"
    assert result["stage_statistics_ms"]["score"]["total"]["median"] == 6.0
    assert result["stage_statistics_ms"]["queue"]["publication"]["mean"] == 2.0
    assert result["packet_event_to_alert_latency_measured"] is False
    assert result["end_to_end_pipeline_wall_clock_measured"] is False
    assert result["operational_alerts_created"] is False
    assert str(tmp_path) not in json.dumps(result)
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_opt_in_runtime_summary_rejects_repinned_nonzero_exit(tmp_path):
    manifest, trials = make_manifest(tmp_path)
    receipt_file = tmp_path / trials[0]["score_receipt"]
    receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
    receipt["exit_code"] = 1
    receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
    trials[0]["score_sha256"] = sha(receipt_file.read_bytes())
    manifest.write_text(json.dumps({"version": 1, "trials": trials}), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_paired_receipts(
            manifest, sha(manifest.read_bytes()), ROOT, include_runtime_summary=True
        )


def test_opt_in_runtime_summary_cli_is_aggregate_only(tmp_path):
    manifest, _ = make_manifest(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_offline_blue_receipts.py"),
         "--manifest", str(manifest), "--expected-manifest-sha256",
         sha(manifest.read_bytes()), "--include-runtime-summary"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["trials_count"] == 3
    assert report["stage_statistics_ms"]["score"]["total"]["mean"] == 6.0
    assert str(tmp_path) not in proc.stdout
