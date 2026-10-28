"""Score a NEW, private, authorized Zeek conn.log with a pinned research model.

Offline only. No socket, traffic generation, model fitting, label lookup,
operational alert or SOC database write. Never use a held-out TEST capture.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.new_log_inference import score_new_zeek_log
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from blue_team_ai.zeek import MAX_LOG_BYTES


def _private_file(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Direct symlinks are not accepted")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT) or not resolved.is_file():
        raise ValueError("Private input must be a regular file outside repository")
    return resolved


def _read_bounded_capture(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError("Capture symlink not accepted")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Capture must be a regular file")
        return stream.read(MAX_LOG_BYTES + 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, type=Path, help="Private JSON model")
    parser.add_argument("--expected-model-sha256", required=True,
                        help="Model digest independently recorded before this run")
    parser.add_argument("--log", required=True, type=Path, help="NEW private Zeek ASCII conn.log")
    parser.add_argument("--expected-log-sha256", required=True,
                        help="Capture digest independently recorded before this run")
    parser.add_argument("--cidr", action="append", required=True,
                        help="Actual owned RFC1918 Host-only CIDR (repeat up to four)")
    parser.add_argument("--output", required=True, type=Path,
                        help="NEW private prediction JSON alongside the capture")
    args = parser.parse_args(argv)
    try:
        model_path = _private_file(args.model)
        log_path = _private_file(args.log)
        if model_path == log_path:
            raise ValueError("Model and capture must be different")
        output = args.output.absolute()
        if (
            output.name in ("", ".", "..") or output.suffix.lower() != ".json"
            or output.parent.resolve(strict=True) != log_path.parent
            or output.is_relative_to(ROOT)
            or output.exists() or output.is_symlink()
        ):
            raise ValueError("Output must be a new private JSON alongside the capture")
        model = load_pinned_zeek_research_model(
            model_path, expected_sha256=args.expected_model_sha256,
        )
        raw = _read_bounded_capture(log_path)
        report = score_new_zeek_log(
            raw, model,
            expected_log_sha256=args.expected_log_sha256,
            lab_cidrs=args.cidr,
            model_sha256=args.expected_model_sha256,
        )
        payload = (json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
        with output.open("x", encoding="utf-8") as stream:
            stream.write(payload)
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError):
        # Avoid leaking private paths, IPs, UIDs or model parameters in shared CI.
        print("Private new-log Zeek inference refused; inspect local evidence.", file=sys.stderr)
        return 1
    print("Private offline Zeek research predictions written (NOT operational alerts).")
    print("flow_count=" + str(report["flow_count"]))
    print("research_candidate_count=" + str(report["research_candidate_count"]))
    print("No SOC case, network traffic, label evaluation or live detection performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
