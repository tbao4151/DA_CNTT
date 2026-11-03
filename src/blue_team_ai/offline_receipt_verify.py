"""Read-only verification of private paired offline Blue subprocess receipts.

A receipt is not a signature and does not authenticate capture provenance.
Only local files are read. No subprocess, network, SOC, or model is invoked.
"""
from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime
from decimal import Decimal
from pathlib import Path
import re

from .offline_pcap_verify import verify_offline_pcap_import
from .offline_runtime_summary import (
    MAX_STDOUT_BYTES, _check_pin, _read_regular, _unique_pairs,
    parse_timing_stdout, _stats,
)

MAX_MANIFEST_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_TRIAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_UTC_RECEIPT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00\Z")
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



def _validate_recorded_clock(receipt: dict) -> Decimal:
    """Check recorder UTC metadata without treating it as detection latency.

    The external duration comes from perf_counter_ns; UTC timestamps come
    from a separate wall clock and must not be equated to that duration.
    """
    instants = []
    for key in ("started_utc", "finished_utc"):
        value = receipt[key]
        if not isinstance(value, str) or _UTC_RECEIPT.fullmatch(value) is None:
            raise ValueError("Invalid UTC recorder timestamp")
        try:
            instants.append(datetime.fromisoformat(value))
        except ValueError as exc:
            raise ValueError("Invalid UTC recorder timestamp") from exc
    if instants[1] < instants[0]:
        raise ValueError("Recorder UTC timestamps out of order")
    elapsed = receipt["external_process_wall_duration_ms_not_detection_latency"]
    if (type(elapsed) not in (int, float)
            or not 0 <= elapsed <= 3_660_000
            or not math.isfinite(elapsed)):
        raise ValueError("Invalid monotonic subprocess duration")
    return Decimal(str(elapsed))

def _verify_stage(folder: Path, trial_id: str, stage: str,
                  receipt_name: str, receipt_pin: str, root: Path) -> dict[str, Decimal]:
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
    external_wall_ms = _validate_recorded_clock(receipt)
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
            measured = parse_timing_stdout(content, stage)
            # Same monotonic clock family; allow 1 ms for recorder rounding.
            if measured["total"] > external_wall_ms + Decimal("1.000"):
                raise ValueError("Stage timing exceeds recorded subprocess wall time")

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
    return measured, command, receipt["output_sha256"]



# Strict opt-in source/queue consistency, not process attestation.
_PAIRED_FLAGS = {
    "score": frozenset({
        "--model", "--expected-model-sha256", "--log", "--expected-log-sha256",
        "--manifest", "--expected-manifest-sha256", "--cidr", "--output",
        "--offline-import-report", "--expected-offline-import-report-sha256",
        "--offline-import-pcap", "--require-pcap-zeek-timestamp-corroboration",
    }),
    "queue": frozenset({
        "--model", "--expected-model-sha256", "--log", "--expected-log-sha256",
        "--manifest", "--expected-manifest-sha256", "--cidr", "--output",
        "--report", "--expected-report-sha256",
    }),
}
_INPUT_LIMITS = {"model": 2 * 1024 * 1024, "log": 15 * 1024 * 1024,
                 "manifest": 256 * 1024}


def _paired_command_inputs(command: list[str], stage: str, root: Path,
                           digest_cache: dict[Path, str]) -> dict:
    """Require pinned retained inputs and an unambiguous CLI argument contract."""
    options: dict[str, str] = {}
    cidrs: list[str] = []
    args = command[2:-1]  # interpreter, fixed script, final timing flag
    i = 0
    while i < len(args):
        flag = args[i]
        if flag not in _PAIRED_FLAGS[stage]:
            raise ValueError("Unsupported paired timing command option")
        if flag == "--require-pcap-zeek-timestamp-corroboration":
            if flag in options:
                raise ValueError("Duplicate paired timing flag")
            options[flag] = "true"
            i += 1
            continue
        if i + 1 >= len(args) or not args[i + 1] or args[i + 1].startswith("--"):
            raise ValueError("Missing paired timing option value")
        if flag == "--cidr":
            cidrs.append(args[i + 1])
        elif flag in options:
            raise ValueError("Duplicate paired timing option")
        else:
            options[flag] = args[i + 1]
        i += 2
    required = {"--model", "--expected-model-sha256", "--log",
                "--expected-log-sha256", "--manifest",
                "--expected-manifest-sha256", "--output"}
    if stage == "queue":
        required |= {"--report", "--expected-report-sha256"}
    if not required.issubset(options) or not 1 <= len(cidrs) <= 4:
        raise ValueError("Incomplete paired timing source pins")
    if len(set(cidrs)) != len(cidrs):
        raise ValueError("Duplicate paired timing CIDR")
    common: list = []
    resolved_paths: list[Path] = []
    for role in ("model", "log", "manifest"):
        candidate = Path(options["--" + role])
        if not candidate.is_absolute() or candidate.is_symlink():
            raise ValueError("Paired source path must be absolute and not a symlink")
        resolved = candidate.resolve(strict=True)
        if resolved.is_relative_to(root):
            raise ValueError("Paired source input must be outside repository")
        pin = _check_pin(options["--expected-" + role + "-sha256"])
        if resolved not in digest_cache:
            digest_cache[resolved] = _digest(_read_regular(resolved, _INPUT_LIMITS[role]))
        if digest_cache[resolved] != pin:
            raise ValueError("Paired source input bytes changed")
        common.extend((str(resolved), pin))
        resolved_paths.append(resolved)
    if len(set(resolved_paths)) != 3:
        raise ValueError("Paired source roles must be distinct")
    common.append(tuple(sorted(cidrs)))
    output = Path(options["--output"])
    if not output.is_absolute():
        raise ValueError("Paired output path must be absolute")
    output = output.resolve(strict=True)
    if stage == "score":
        optional_flags = ("--offline-import-report",
                          "--expected-offline-import-report-sha256",
                          "--offline-import-pcap")
        optional = tuple(options.get(k) for k in optional_flags)
        if any(v is not None for v in optional) and not all(v is not None for v in optional):
            raise ValueError("Incomplete optional PCAP import inputs")
        if ("--require-pcap-zeek-timestamp-corroboration" in options
                and not all(v is not None for v in optional)):
            raise ValueError("Timestamp gate without PCAP import")
        # The original scoring CLI can optionally consume a pinned offline
        # PCAP import. Strict receipt verification must recheck those retained
        # bytes, not merely compare operator-controlled argument strings.
        verified_import = None
        if all(v is not None for v in optional):
            verified_import = verify_offline_pcap_import(
                Path(optional[0]),
                expected_report_sha256=optional[1],
                pcap_path=Path(optional[2]),
                log_path=Path(options["--log"]),
                lab_cidrs=cidrs,
            )
            if verified_import["zeek_conn_sha256"] != _check_pin(
                options["--expected-log-sha256"]
            ):
                raise ValueError("Offline import log differs from paired score input")
        optional_identity = (
            (str(Path(optional[0]).resolve(strict=True)),
             verified_import["report_sha256"],
             str(Path(optional[2]).resolve(strict=True)),
             verified_import["pcap_sha256"])
            if verified_import is not None else (None, None, None, None)
        )
        return {"common": tuple(common), "output": output,
                "optional": optional_identity + (
                    options.get("--require-pcap-zeek-timestamp-corroboration"),),
                "pcap_import_checked": verified_import is not None}
    report = Path(options["--report"])
    if not report.is_absolute() or report.is_symlink():
        raise ValueError("Queue report path must be absolute and not a symlink")
    return {"common": tuple(common), "output": output,
            "report": report.resolve(strict=True),
            "report_pin": _check_pin(options["--expected-report-sha256"])}


def verify_paired_receipts(manifest_path: Path, expected_sha256: str,
                           repo_root: Path, *,
                           include_runtime_summary: bool = False,
                           require_paired_inputs: bool = False) -> dict:
    """Verify 3-50 paired receipts and their retained original output files.

    The SHA-256 of the manifest must be obtained independently. Results
    deliberately exclude paths, timestamps, private command arguments and IPs.
    """
    if type(include_runtime_summary) is not bool or type(require_paired_inputs) is not bool:
        raise ValueError("Invalid receipt verification option")
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
    digest_cache: dict[Path, str] = {}
    reference_inputs = None
    reference_optional = None
    optional_pcap_import_checked = False
    durations = {stage: {key: [] for key in ("total", "compute", "serialization", "publication")}
                 for stage in ("score", "queue")} if include_runtime_summary else None
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
        stage_inputs = {}
        for stage in ("score", "queue"):
            measured, command, output_sha = _verify_stage(
                source.parent, trial_id, stage,
                trial[f"{stage}_receipt"], trial[f"{stage}_sha256"], root,
            )
            if require_paired_inputs:
                stage_inputs[stage] = _paired_command_inputs(
                    command, stage, root, digest_cache,
                )
                stage_inputs[stage]["output_sha"] = output_sha
            if durations is not None:
                for field, value in measured.items():
                    durations[stage][field].append(value)
        if require_paired_inputs:
            score, queue = stage_inputs["score"], stage_inputs["queue"]
            if (score["common"] != queue["common"]
                    or queue["report"] != score["output"]
                    or queue["report_pin"] != score["output_sha"]):
                raise ValueError("Score/queue pinned source or report handoff differs")
            if reference_inputs is None:
                reference_inputs = score["common"]
                reference_optional = score["optional"]
                optional_pcap_import_checked = score["pcap_import_checked"]
            elif (score["common"] != reference_inputs
                  or score["optional"] != reference_optional):
                raise ValueError("Paired trials do not use the same pinned inputs")
    result = {
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
    if require_paired_inputs:
        result.update({
            "retained_model_log_manifest_sha256_verified": True,
            "score_to_queue_published_report_pin_verified": True,
            "cross_trial_pinned_source_inputs_consistent": True,
            "cross_trial_input_equivalence_verified": False,
        })
        if optional_pcap_import_checked:
            result["retained_optional_pcap_import_bytes_verified"] = True
    if durations is not None:
        result.update({
            "trials_count": len(manifest["trials"]),
            "duration_unit": "milliseconds",
            "p95_definition": "nearest_rank",
            "stage_statistics_ms": {
                stage: {field: _stats(values) for field, values in fields.items()}
                for stage, fields in durations.items()
            },
            "runtime_summary_source": "verified_paired_subprocess_receipts",
            "end_to_end_pipeline_wall_clock_measured": False,
            "operational_alerts_created": False,
        })
    return result
