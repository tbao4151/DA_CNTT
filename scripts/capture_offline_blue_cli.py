"""Capture one actual offline Blue CLI exit status and stdout as private evidence.

Runs only the repository's pinned score or research-queue script, never a shell,
network collector, Red Team command, or arbitrary executable. A receipt is
operator-local metadata, not an authenticated chain of custody or live latency.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.offline_runtime_summary import MAX_STDOUT_BYTES, parse_timing_stdout

_SCRIPTS = {"score": "score_zeek_new_log.py", "queue": "export_zeek_research_alerts.py"}
_TRIAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}\Z")


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _cli_output_path(args: list[str]) -> Path:
    # Do not permit ambiguous output destinations, including --output=path.
    if args.count("--output") != 1 or any(a.startswith("--output=") for a in args):
        raise ValueError("Exactly one separate --output argument is required")
    index = args.index("--output")
    if index + 1 == len(args) or args[index + 1].startswith("--"):
        raise ValueError("Missing output path")
    path = Path(args[index + 1]).absolute()
    if path.is_relative_to(ROOT) or path.suffix.lower() != ".json" or not path.parent.is_dir():
        raise ValueError("Private JSON output outside repository required")
    return path


def capture_stage(stage: str, evidence_dir: Path, trial_id: str,
                  cli_args: list[str], timeout_seconds: int = 600) -> dict:
    """Run one allowlisted CLI and record genuine return code and bounded stdout.

    Never reuses an existing stdout/stderr/receipt name. Failure evidence is
    retained and marked unsuccessful; it cannot be a successful timing trial.
    """
    if stage not in _SCRIPTS or not _TRIAL_ID.fullmatch(trial_id):
        raise ValueError("Invalid stage or trial identifier")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600:
        raise ValueError("Invalid timeout")
    if not cli_args or any(a in ("--help", "-h", "--version") for a in cli_args):
        raise ValueError("A real offline CLI invocation is required")
    if any(a in ("--measure-inference-publication-runtime", "--measure-research-export-runtime")
           for a in cli_args):
        raise ValueError("Timing flag is managed by the recorder")
    output = _cli_output_path(cli_args)
    if evidence_dir.is_symlink():
        raise ValueError("Evidence directory symlink refused")
    folder = evidence_dir.resolve(strict=True)
    if not folder.is_dir() or folder.is_relative_to(ROOT.resolve()):
        raise ValueError("Evidence directory must exist outside repository")
    if output == folder or output.is_relative_to(ROOT.resolve()):
        raise ValueError("Invalid output path")
    prefix = f"trial-{trial_id}-{stage}"
    stdout_path = folder / f"{prefix}.stdout.txt"
    stderr_path = folder / f"{prefix}.stderr.txt"
    receipt_path = folder / f"{prefix}.receipt.json"
    if any(p.exists() or p.is_symlink() for p in (stdout_path, stderr_path, receipt_path)):
        raise ValueError("Existing private evidence must never be overwritten")
    flag = ("--measure-inference-publication-runtime" if stage == "score"
            else "--measure-research-export-runtime")
    command = [sys.executable, str(ROOT / "scripts" / _SCRIPTS[stage]), *cli_args, flag]
    started_utc = _utc()
    started_ns = time.perf_counter_ns()
    return_code: int | None = None
    timed_out = False
    launch_failed = False
    # Exclusive file creation prevents accidentally overwriting old trial data.
    # If opening stderr fails, only the newly created empty stdout is removed.
    with stdout_path.open("xb") as stdout_stream:
        try:
            stderr_stream = stderr_path.open("xb")
        except OSError:
            stdout_path.unlink()
            raise
        with stderr_stream:
            try:
                result = subprocess.run(
                    command, stdin=subprocess.DEVNULL, stdout=stdout_stream,
                    stderr=stderr_stream, cwd=ROOT, shell=False,
                    timeout=timeout_seconds, check=False,
                )
                return_code = result.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
            except OSError:
                launch_failed = True
    elapsed_ms = round((time.perf_counter_ns() - started_ns) / 1_000_000, 3)
    stdout_size = stdout_path.stat().st_size
    stderr_size = stderr_path.stat().st_size
    timing_contract_valid = False
    if return_code == 0 and not timed_out and not launch_failed and stdout_size <= MAX_STDOUT_BYTES:
        try:
            parse_timing_stdout(stdout_path.read_bytes(), stage)
            timing_contract_valid = True
        except (ValueError, UnicodeError, ArithmeticError):
            pass
    output_digest = None
    if (timing_contract_valid and not output.is_symlink() and output.is_file()
            and output.stat().st_size <= 64 * 1024 * 1024):
        output_digest = _digest(output)
    verified_success = (return_code == 0 and not timed_out and timing_contract_valid
                        and output_digest is not None and stderr_size == 0)
    receipt = {
        "version": 1,
        "stage": stage,
        "trial_id": trial_id,
        "command_argv_private": command,
        "started_utc": started_utc,
        "finished_utc": _utc(),
        "external_process_wall_duration_ms_not_detection_latency": elapsed_ms,
        "exit_code": return_code,
        "timed_out": timed_out,
        "launch_failed": launch_failed,
        "python_version": sys.version.split()[0],
        "stdout_file": stdout_path.name,
        "stdout_sha256": _digest(stdout_path),
        "stdout_bytes": stdout_size,
        "stderr_file": stderr_path.name,
        "stderr_sha256": _digest(stderr_path),
        "stderr_bytes": stderr_size,
        "timing_stdout_contract_valid": timing_contract_valid,
        "output_sha256": output_digest,
        "successful_offline_timing_trial": verified_success,
        "vmware_isolation_or_capture_authenticity_verified": False,
        "packet_to_alert_latency_measured": False,
    }
    with receipt_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=tuple(_SCRIPTS), required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--trial-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("cli_args", nargs=argparse.REMAINDER,
                        help="Pass -- then the selected offline CLI arguments")
    args = parser.parse_args(argv)
    forwarded = args.cli_args[1:] if args.cli_args[:1] == ["--"] else args.cli_args
    try:
        receipt = capture_stage(args.stage, args.evidence_dir, args.trial_id,
                                forwarded, args.timeout_seconds)
    except (ValueError, OSError, TypeError):
        print("Offline Blue evidence capture refused; inspect private inputs.", file=sys.stderr)
        return 1
    if receipt["successful_offline_timing_trial"]:
        print("Private offline Blue CLI stdout and successful exit receipt recorded.")
        return 0
    print("Offline Blue CLI did not complete a valid timing trial; private failure receipt retained.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
