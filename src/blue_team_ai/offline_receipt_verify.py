"""Read-only verification of private paired offline Blue subprocess receipts.

A receipt is not a signature and does not authenticate capture provenance.
Only local files are read. No subprocess, network, SOC, or model is invoked.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .offline_runtime_summary import (
    MAX_STDOUT_BYTES, _check_pin, _read_regular, _unique_pairs,
    parse_timing_stdout,
)

MAX_MANIFEST_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_TRIAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SCRIPT = {"score": "score_zeek_new_log.py",
           "queue": "export_zeek_research_alerts.py"}
_FLAG = {"score": "--measure-inference-publication-runtime",
         "queue": "--measure-research-export-runtime"}
_RECEIPT_KEYS = frozenset({
    "version", "stage", "trial_id", "command_argv_private",
    "started_utc", "finished_utc",
    "external_process_wall_duration_ms_not_detection_latency",
    "exit_code", "timed_out", "launch_failed", "python_version",
    "stdout_file", "stdout_sha256", "stdout_bytes",
    "stderr_file", "stderr_sha256", "stderr_bytes",
    "timing_stdout_contract_valid", "output_sha256",
    "successful_offline_timing_trial",
    "vmware_isolation_or_capture_authenticity_verified",
    "packet_to_alert_latency_measured",
})


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(raw: bytes) -> dict:
    def reject_constant(value: str):
        raise ValueError("Non-finite JSON constant")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed private JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("Private JSON object required")
    return value


def _private_file(folder: Path, name: str, limit: int) -> bytes:
    # Names are derived from a bounded trial ID, not arbitrary manifest paths.
    path = folder / name
    return _read_regular(path, limit)


def _verify_stage(folder: Path, trial_id: str, stage: str,
                  receipt_name: str, receipt_pin: str, root: Path) -> None:
    expected_name = f"trial-{trial_id}-{stage}.receipt.json"
    if receipt_name != expected_name:
        raise ValueError("Receipt filename does not match stage and trial")
    raw = _private_file(folder, receipt_name, MAX_RECEIPT_BYTES)
    if _digest(raw) != _check_pin(receipt_pin):
        raise ValueError("Receipt SHA-256 mismatch")
    receipt = _json(raw)
    if (set(receipt) != _RECEIPT_KEYS or type(receipt["version"]) is not int
            or receipt["version"] != 1 or receipt["stage"] != stage
            or receipt["trial_id"] != trial_id):
        raise ValueError("Invalid recorder receipt contract")
    if (type(receipt["exit_code"]) is not int or receipt["exit_code"] != 0
            or receipt["timed_out"] is not False
            or receipt["launch_failed"] is not False
            or receipt["timing_stdout_contract_valid"] is not True
            or receipt["successful_offline_timing_trial"] is not True
            or receipt["vmware_isolation_or_capture_authenticity_verified"] is not False
            or receipt["packet_to_alert_latency_measured"] is not False):
        raise ValueError("Unsuccessful or inconsistent offline subprocess receipt")
    for stream in ("stdout", "stderr"):
        expected_file = f"trial-{trial_id}-{stage}.{stream}.txt"
        if receipt[f"{stream}_file"] != expected_file:
            raise ValueError("Recorder stream filename mismatch")
        content = _private_file(folder, expected_file,
                                MAX_STDOUT_BYTES if stream == "stdout" else MAX_RECEIPT_BYTES)
        if (not isinstance(receipt[f"{stream}_sha256"], str)
                or _SHA.fullmatch(receipt[f"{stream}_sha256"]) is None
                or _digest(content) != receipt[f"{stream}_sha256"]
                or type(receipt[f"{stream}_bytes"]) is not int
                or len(content) != receipt[f"{stream}_bytes"]):
            raise ValueError("Recorder stream integrity mismatch")
        if stream == "stderr" and content:
            raise ValueError("Successful subprocess must have empty stderr")
        if stream == "stdout":
            parse_timing_stdout(content, stage)

    command = receipt["command_argv_private"]
    if (not isinstance(command, list) or len(command) < 5
            or any(not isinstance(x, str) or not x for x in command)
            or command.count("--output") != 1
            or command.count(_FLAG[stage]) != 1
            or command[-1] != _FLAG[stage]
            or any(x.startswith("--output=") for x in command)):
        raise ValueError("Unexpected recorded command")
    if Path(command[1]).resolve() != (root / "scripts" / _SCRIPT[stage]).resolve():
        raise ValueError("Recorded command is not an allowlisted Blue script")
    idx = command.index("--output")
    if idx + 1 >= len(command) or command[idx + 1].startswith("--"):
        raise ValueError("Recorded JSON output path missing")
    output = Path(command[idx + 1])
    if (not output.is_absolute() or output.is_symlink()
            or output.resolve().is_relative_to(root.resolve())):
        raise ValueError("Invalid private JSON output path")
    if (not isinstance(receipt["output_sha256"], str)
            or _SHA.fullmatch(receipt["output_sha256"]) is None
            or _digest(_read_regular(output, MAX_OUTPUT_BYTES)) != receipt["output_sha256"]):
        raise ValueError("Published JSON hash mismatch")


def verify_paired_receipts(manifest_path: Path, expected_sha256: str,
                           repo_root: Path) -> dict:
    """Verify 3-50 paired receipts and their retained original output files.

    The SHA-256 of the manifest must be obtained independently. Results
    deliberately exclude paths, timestamps, private command arguments and IPs.
    """
    _check_pin(expected_sha256)
    if manifest_path.is_symlink():
        raise ValueError("Manifest symlink refused")
    source = manifest_path.resolve(strict=True)
    root = repo_root.resolve()
    if source.is_relative_to(root):
        raise ValueError("Private manifest must be outside repository")
    raw = _read_regular(source, MAX_MANIFEST_BYTES)
    if _digest(raw) != expected_sha256:
        raise ValueError("Receipt manifest SHA-256 mismatch")
    manifest = _json(raw)
    if (set(manifest) != {"version", "trials"}
            or type(manifest["version"]) is not int or manifest["version"] != 1
            or not isinstance(manifest["trials"], list)
            or not 3 <= len(manifest["trials"]) <= 50):
        raise ValueError("Require version-1 manifest with 3-50 paired trials")
    seen_ids: set[str] = set()
    for trial in manifest["trials"]:
        if (not isinstance(trial, dict)
                or set(trial) != {"trial_id", "score_receipt", "score_sha256",
                                  "queue_receipt", "queue_sha256"}):
            raise ValueError("Invalid paired receipt manifest entry")
        trial_id = trial["trial_id"]
        if (not isinstance(trial_id, str)
                or _TRIAL_ID.fullmatch(trial_id) is None
                or trial_id.casefold() in seen_ids):
            raise ValueError("Invalid or reused trial ID")
        seen_ids.add(trial_id.casefold())
        for stage in ("score", "queue"):
            _verify_stage(source.parent, trial_id, stage,
                          trial[f"{stage}_receipt"], trial[f"{stage}_sha256"], root)
    return {
        "mode": "offline_blue_receipt_integrity_review_only",
        "paired_trials_verified": len(manifest["trials"]),
        "recorded_exit_codes_zero_and_stream_hashes_verified": True,
        "retained_published_json_sha256_verified": True,
        "timing_stdout_contract_rechecked": True,
        "independent_process_authenticity_verified": False,
        "cross_trial_input_equivalence_verified": False,
        "original_pcap_zeek_verified": False,
        "vmware_isolation_verified": False,
        "packet_event_to_alert_latency_measured": False,
        "soc_cases_created": False,
    }
