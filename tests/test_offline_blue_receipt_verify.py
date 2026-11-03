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


@pytest.mark.parametrize(("target_trial", "target_stage", "source_trial", "source_stage"), [
    (1, "score", 0, "score"),  # same stage, different trials
    (0, "queue", 0, "score"),  # score and queue share one output
    (2, "queue", 1, "queue"),  # later queue trial reuses an earlier queue
])
def test_refuses_reused_published_json_output_path(
    tmp_path, target_trial, target_stage, source_trial, source_stage
):
    manifest, trials = make_manifest(tmp_path)
    source_output = tmp_path / (
        f"trial-{source_trial:03d}-{source_stage}-output.json"
    )
    target_entry = trials[target_trial]
    receipt_path = tmp_path / target_entry[f"{target_stage}_receipt"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    argv = receipt["command_argv_private"]
    argv[argv.index("--output") + 1] = str(source_output)
    # Repin the forged receipt and manifest: hash consistency alone must
    # not permit two distinct trial/stage IDs to share retained JSON.
    receipt["output_sha256"] = sha(source_output.read_bytes())
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    target_entry[f"{target_stage}_sha256"] = sha(receipt_path.read_bytes())
    manifest.write_text(
        json.dumps({"version": 1, "trials": trials}), encoding="utf-8"
    )
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(ValueError, match="reuse a published JSON output path"):
        verify_paired_receipts(manifest, sha(manifest.read_bytes()), ROOT)
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


def make_comparable_manifest(folder: Path):
    manifest, trials = make_manifest(folder)
    inputs = []
    for name, data in (("model.json", b"synthetic model"),
                       ("new.log", b"synthetic log"),
                       ("labels-manifest.json", b"synthetic manifest")):
        path = folder / name
        path.write_bytes(data)
        inputs.extend((str(path), sha(data)))
    for trial in trials:
        for stage in ("score", "queue"):
            receipt_path = folder / trial[f"{stage}_receipt"]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            args = receipt["command_argv_private"]
            common = [
                "--model", inputs[0], "--expected-model-sha256", inputs[1],
                "--log", inputs[2], "--expected-log-sha256", inputs[3],
                "--manifest", inputs[4], "--expected-manifest-sha256", inputs[5],
                "--cidr", "192.168.56.0/24",
            ]
            if stage == "queue":
                report = folder / f"trial-{trial['trial_id']}-score-output.json"
                common += ["--report", str(report),
                           "--expected-report-sha256", sha(report.read_bytes())]
            args[2:2] = common
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            trial[f"{stage}_sha256"] = sha(receipt_path.read_bytes())
    manifest.write_text(json.dumps({"version": 1, "trials": trials}), encoding="utf-8")
    return manifest, trials


def test_strict_paired_input_integrity_and_score_queue_binding(tmp_path):
    manifest, _ = make_comparable_manifest(tmp_path)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    pin = sha(manifest.read_bytes())
    assert "cross_trial_pinned_source_inputs_consistent" not in verify_paired_receipts(
        manifest, pin, ROOT
    )
    verified = verify_paired_receipts(
        manifest, pin, ROOT, require_paired_inputs=True, include_runtime_summary=True
    )
    assert verified["retained_model_log_manifest_sha256_verified"] is True
    assert verified["score_to_queue_published_report_pin_verified"] is True
    assert verified["cross_trial_pinned_source_inputs_consistent"] is True
    assert verified["cross_trial_input_equivalence_verified"] is False
    assert verified["stage_statistics_ms"]["score"]["total"]["median"] == 6.0
    assert str(tmp_path) not in json.dumps(verified)
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


@pytest.mark.parametrize("mutation", [
    "tampered_model", "pair_model_pin", "cross_trial_log_pin",
    "wrong_report_path", "wrong_report_pin", "duplicate_model_flag",
    "missing_score_manifest", "unknown_arg",
])
def test_strict_paired_input_refuses_repinned_mismatch(tmp_path, mutation):
    manifest, trials = make_comparable_manifest(tmp_path)
    if mutation == "tampered_model":
        (tmp_path / "model.json").write_bytes(b"changed")
    else:
        trial = trials[1] if mutation == "cross_trial_log_pin" else trials[0]
        stages = (("score", "queue") if mutation == "cross_trial_log_pin" else
                  ("score",) if mutation in ("missing_score_manifest", "unknown_arg") else
                  ("queue",))
        for stage in stages:
            path = tmp_path / trial[f"{stage}_receipt"]
            receipt = json.loads(path.read_text(encoding="utf-8"))
            args = receipt["command_argv_private"]
            if mutation == "pair_model_pin":
                args[args.index("--expected-model-sha256") + 1] = "a" * 64
            elif mutation == "cross_trial_log_pin":
                args[args.index("--expected-log-sha256") + 1] = "b" * 64
            elif mutation == "wrong_report_path":
                args[args.index("--report") + 1] = str(tmp_path / "trial-000-queue-output.json")
            elif mutation == "wrong_report_pin":
                args[args.index("--expected-report-sha256") + 1] = "c" * 64
            elif mutation == "duplicate_model_flag":
                args[-1:-1] = ["--model", str(tmp_path / "model.json")]
            elif mutation == "missing_score_manifest":
                for flag in ("--manifest", "--expected-manifest-sha256"):
                    idx = args.index(flag)
                    del args[idx:idx + 2]
            elif mutation == "unknown_arg":
                args[-1:-1] = ["--arbitrary", "unexpected"]
            path.write_text(json.dumps(receipt), encoding="utf-8")
            trial[f"{stage}_sha256"] = sha(path.read_bytes())
        manifest.write_text(json.dumps({"version": 1, "trials": trials}), encoding="utf-8")
    with pytest.raises((ValueError, OSError)):
        verify_paired_receipts(
            manifest, sha(manifest.read_bytes()), ROOT, require_paired_inputs=True
        )


def test_strict_paired_input_cli_private_output(tmp_path):
    manifest, _ = make_comparable_manifest(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_offline_blue_receipts.py"),
         "--manifest", str(manifest), "--expected-manifest-sha256",
         sha(manifest.read_bytes()), "--require-paired-inputs"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["score_to_queue_published_report_pin_verified"] is True
    assert str(tmp_path) not in proc.stdout
    assert "192.168.56." not in proc.stdout


# Reuse the existing synthetic-only offline import fixture; it does not run Zeek
# or collect traffic and cannot authenticate the provenance of a PCAP.
from test_offline_pcap_verify import imported


def _with_optional_pcap_import(tmp_path, imported):
    manifest, trials = make_comparable_manifest(tmp_path)
    for trial in trials:
        for stage in ("score", "queue"):
            receipt_path = tmp_path / trial[f"{stage}_receipt"]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            args = receipt["command_argv_private"]
            args[args.index("--log") + 1] = str(imported["log"])
            args[args.index("--expected-log-sha256") + 1] = sha(
                imported["log"].read_bytes()
            )
            if stage == "score":
                args[-1:-1] = [
                    "--offline-import-report", str(imported["report"]),
                    "--expected-offline-import-report-sha256", imported["pin"],
                    "--offline-import-pcap", str(imported["pcap"]),
                ]
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            trial[f"{stage}_sha256"] = sha(receipt_path.read_bytes())
    manifest.write_text(json.dumps({"version": 1, "trials": trials}), encoding="utf-8")
    return manifest, trials


def test_strict_receipts_recheck_optional_pcap_import_bytes(tmp_path, imported):
    manifest, _ = _with_optional_pcap_import(tmp_path, imported)
    before = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    verified = verify_paired_receipts(
        manifest, sha(manifest.read_bytes()), ROOT, require_paired_inputs=True,
    )
    assert verified["paired_trials_verified"] == 3
    assert verified["retained_optional_pcap_import_bytes_verified"] is True
    assert verified["original_pcap_zeek_verified"] is False
    assert verified["vmware_isolation_verified"] is False
    assert str(tmp_path) not in json.dumps(verified)
    assert before == {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


@pytest.mark.parametrize("mutation", [
    "changed_pcap", "changed_import_report", "wrong_import_pin",
    "missing_pcap_flag", "different_pcap_path", "wrong_score_log",
])
def test_strict_receipts_refuse_optional_pcap_import_mismatch(
    tmp_path, imported, mutation
):
    manifest, trials = _with_optional_pcap_import(tmp_path, imported)
    if mutation == "changed_pcap":
        imported["pcap"].write_bytes(imported["pcap"].read_bytes() + b"tamper")
    elif mutation == "changed_import_report":
        imported["report"].write_bytes(imported["report"].read_bytes() + b"tamper")
    else:
        receipt_path = tmp_path / trials[0]["score_receipt"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        args = receipt["command_argv_private"]
        if mutation == "wrong_import_pin":
            args[args.index("--expected-offline-import-report-sha256") + 1] = "0" * 64
        elif mutation == "missing_pcap_flag":
            idx = args.index("--offline-import-pcap")
            del args[idx:idx + 2]
        elif mutation == "different_pcap_path":
            duplicate = tmp_path / "same-bytes-other-source.pcap"
            duplicate.write_bytes(imported["pcap"].read_bytes())
            args[args.index("--offline-import-pcap") + 1] = str(duplicate)
        else:
            args[args.index("--log") + 1] = str(tmp_path / "new.log")
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        trials[0]["score_sha256"] = sha(receipt_path.read_bytes())
        manifest.write_text(json.dumps({"version": 1, "trials": trials}),
                            encoding="utf-8")
    with pytest.raises((ValueError, OSError)):
        verify_paired_receipts(
            manifest, sha(manifest.read_bytes()), ROOT, require_paired_inputs=True,
        )


def test_strict_receipts_without_optional_pcap_do_not_claim_pcap_verified(tmp_path):
    manifest, _ = make_comparable_manifest(tmp_path)
    verified = verify_paired_receipts(
        manifest, sha(manifest.read_bytes()), ROOT, require_paired_inputs=True,
    )
    assert "retained_optional_pcap_import_bytes_verified" not in verified
    assert verified["original_pcap_zeek_verified"] is False
