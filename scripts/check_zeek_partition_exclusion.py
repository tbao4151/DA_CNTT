"""Read-only offline preflight for new Zeek capture vs ALL declared splits.

Requires independently recorded model, manifest and capture SHA-256 values.
No scoring, network access, SOC writes or operational alert generation.
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

from blue_team_ai.lab_scope import inspect_zeek_lab_scope
from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.partition_guard import verify_declared_partition_exclusion
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from blue_team_ai.zeek import MAX_LOG_BYTES
from evaluate_zeek_lab import MAX_MANIFEST_BYTES, load_experiment_manifest


def _private_regular_file(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Symlink input refused")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT) or not resolved.is_file():
        raise ValueError("Expected a private regular file outside repository")
    return resolved


def _read_bounded(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected regular input file")
        raw = stream.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise ValueError("Empty or oversized input file")
    return raw


def _check_digest(raw: bytes, expected: str) -> None:
    if (
        not isinstance(expected, str) or len(expected) != 64
        or any(c not in "0123456789abcdef" for c in expected)
        or hashlib.sha256(raw).hexdigest() != expected
    ):
        raise ValueError("Pinned SHA-256 mismatch")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--cidr", action="append", required=True,
                        help="Owned RFC1918 Host-only CIDR; repeat up to four")
    args = parser.parse_args(argv)
    try:
        model_path = _private_regular_file(args.model)
        manifest_path = _private_regular_file(args.manifest)
        log_path = _private_regular_file(args.log)
        if len({model_path, manifest_path, log_path}) != 3:
            raise ValueError("Model, manifest and new capture must be distinct")
        _check_digest(_read_bounded(manifest_path, MAX_MANIFEST_BYTES),
                      args.expected_manifest_sha256)
        raw = _read_bounded(log_path, MAX_LOG_BYTES)
        _check_digest(raw, args.expected_log_sha256)
        inspect_zeek_lab_scope(raw, args.cidr)
        model = load_pinned_zeek_research_model(
            model_path, expected_sha256=args.expected_model_sha256,
        )
        captures, manifest_sha = load_experiment_manifest(
            manifest_path, lab_cidrs=args.cidr,
        )
        dataset = build_labeled_lab_dataset(captures)
        result = verify_declared_partition_exclusion(
            model, dataset, manifest_sha256=manifest_sha,
            new_capture_sha256=args.expected_log_sha256,
            declared_captures=captures, new_source_data=raw,
        )
    except (ValueError, OSError, TypeError, UnicodeError, KeyError, OverflowError):
        print("Private Zeek partition non-reuse check refused; inspect local evidence.",
              file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
