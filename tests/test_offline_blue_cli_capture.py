"""Synthetic process-result tests; never invoke a real capture or network operation."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import capture_offline_blue_cli as recorder


def _args(tmp_path):
    output = tmp_path / "predictions.json"
    return ["--output", str(output)], output


def _fake_run(tmp_path, stdout_data: bytes, *, exit_code=0, stderr_data=b"", create_output=True):
    def run(command, **kwargs):
        assert command[0] == sys.executable
        assert command[1].endswith(("score_zeek_new_log.py", "export_zeek_research_alerts.py"))
        assert kwargs["shell"] is False
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["timeout"] == 600
        kwargs["stdout"].write(stdout_data)
        kwargs["stderr"].write(stderr_data)
        if create_output:
            Path(command[command.index("--output") + 1]).write_bytes(b'{"research":true}\n')
        return SimpleNamespace(returncode=exit_code)
    return run


@pytest.mark.parametrize("stage", ["score", "queue"])
def test_capture_real_return_code_and_original_stdout_receipt(tmp_path, monkeypatch, stage):
    args, output = _args(tmp_path)
    raw = b"contract-valid stdout fixture\n"
    monkeypatch.setattr(recorder, "parse_timing_stdout", lambda b, s: {"total": 1} if b == raw and s == stage else (_ for _ in ()).throw(ValueError()))
    monkeypatch.setattr(recorder.subprocess, "run", _fake_run(tmp_path, raw))
    receipt = recorder.capture_stage(stage, tmp_path, "001", args)
    assert receipt["exit_code"] == 0
    assert receipt["successful_offline_timing_trial"] is True
    assert receipt["timing_stdout_contract_valid"] is True
    assert receipt["stdout_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["output_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert receipt["packet_to_alert_latency_measured"] is False
    assert receipt["command_argv_private"][-1].startswith("--measure-")
    assert json.loads((tmp_path / f"trial-001-{stage}.receipt.json").read_text())["exit_code"] == 0
    assert (tmp_path / f"trial-001-{stage}.stdout.txt").read_bytes() == raw


def test_success_looking_stdout_does_not_override_failed_process(tmp_path, monkeypatch):
    args, _ = _args(tmp_path)
    monkeypatch.setattr(recorder, "parse_timing_stdout", lambda b, s: {"total": 1})
    monkeypatch.setattr(recorder.subprocess, "run", _fake_run(tmp_path, b"looks valid", exit_code=2))
    receipt = recorder.capture_stage("score", tmp_path, "failed", args)
    assert receipt["exit_code"] == 2
    assert receipt["successful_offline_timing_trial"] is False
    assert receipt["timing_stdout_contract_valid"] is False


@pytest.mark.parametrize("bad_stdout,stderr,create_output", [
    (True, b"", True), (False, b"warning", True), (False, b"", False),
])
def test_false_success_refused(tmp_path, monkeypatch, bad_stdout, stderr, create_output):
    args, _ = _args(tmp_path)
    def parser(raw, stage):
        if bad_stdout:
            raise ValueError("malformed")
        return {"total": 1}
    monkeypatch.setattr(recorder, "parse_timing_stdout", parser)
    monkeypatch.setattr(recorder.subprocess, "run", _fake_run(
        tmp_path, b"stdout", stderr_data=stderr, create_output=create_output))
    receipt = recorder.capture_stage("queue", tmp_path, "invalid", args)
    assert receipt["successful_offline_timing_trial"] is False
    assert (tmp_path / "trial-invalid-queue.receipt.json").exists()


def test_timeout_retains_failure_receipt(tmp_path, monkeypatch):
    args, _ = _args(tmp_path)
    def timeout(*a, **kwargs):
        kwargs["stdout"].write(b"partial")
        raise subprocess.TimeoutExpired(a[0], kwargs["timeout"])
    monkeypatch.setattr(recorder.subprocess, "run", timeout)
    receipt = recorder.capture_stage("score", tmp_path, "timeout", args)
    assert receipt["timed_out"] is True
    assert receipt["exit_code"] is None
    assert receipt["successful_offline_timing_trial"] is False
    assert (tmp_path / "trial-timeout-score.stdout.txt").read_bytes() == b"partial"


def test_existing_evidence_never_overwritten_or_executed(tmp_path, monkeypatch):
    args, _ = _args(tmp_path)
    target = tmp_path / "trial-001-score.stdout.txt"
    target.write_bytes(b"original")
    monkeypatch.setattr(recorder.subprocess, "run", lambda *a, **kw: pytest.fail("must not execute"))
    with pytest.raises(ValueError, match="overwritten"):
        recorder.capture_stage("score", tmp_path, "001", args)
    assert target.read_bytes() == b"original"


@pytest.mark.parametrize("trial,argv", [
    ("../outside", ["--output", "x.json"]),
    ("001", ["--output=some.json"]),
    ("001", ["--output", "x.json", "--output", "y.json"]),
    ("001", ["--help", "--output", "x.json"]),
    ("001", ["--output", "x.json", "--measure-research-export-runtime"]),
])
def test_invalid_invocation_refused_before_running(tmp_path, monkeypatch, trial, argv):
    monkeypatch.setattr(recorder.subprocess, "run", lambda *a, **kw: pytest.fail("must not execute"))
    with pytest.raises(ValueError):
        recorder.capture_stage("queue", tmp_path, trial, argv)


def test_cli_refuses_without_executing_or_exposing_paths(tmp_path, capsys):
    status = recorder.main(["--stage", "score", "--evidence-dir", str(tmp_path),
                            "--trial-id", "001", "--", "--help"])
    assert status == 1
    assert str(tmp_path) not in capsys.readouterr().err


def test_process_launch_failure_is_retained_as_unsuccessful_receipt(tmp_path, monkeypatch):
    args, _ = _args(tmp_path)
    monkeypatch.setattr(recorder.subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(OSError("launch refused")))
    receipt = recorder.capture_stage("score", tmp_path, "launch", args)
    assert receipt["launch_failed"] is True
    assert receipt["exit_code"] is None
    assert receipt["successful_offline_timing_trial"] is False
    assert (tmp_path / "trial-launch-score.receipt.json").exists()
