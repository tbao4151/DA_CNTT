"""Read-only aggregate timing review of a privately pinned offline SOC stage record."""
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

from blue_team_ai.offline_stage_timing import (
    MAX_TIMING_RECORD_BYTES, review_offline_soc_stage_timing,
)
from check_zeek_partition_exclusion import _private_regular_file, _read_bounded

# Bounded streaming reads: do not load large original PCAPs into memory.
MAX_TIMING_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
_EVIDENCE_FLAGS = {
    "pcap": "evidence_pcap",
    "zeek_conn": "evidence_zeek_conn",
    "model": "evidence_model",
    "research_report": "evidence_research_report",
    "soc_case_export": "evidence_soc_case_export",
}


def _hash_private_evidence_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode)
                or not 0 < before.st_size <= MAX_TIMING_EVIDENCE_FILE_BYTES):
            raise ValueError("Original evidence file is empty or oversized")
        digest = hashlib.sha256()
        total = 0
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_TIMING_EVIDENCE_FILE_BYTES:
                raise ValueError("Original evidence exceeds read bound")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if total != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in fields
        ):
            raise ValueError("Original evidence changed during hashing")
        return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--expected-record-sha256", required=True)
    for flag in _EVIDENCE_FLAGS.values():
        parser.add_argument("--" + flag.replace("_", "-"), type=Path)
    args = parser.parse_args(argv)
    try:
        private = _private_regular_file(args.record)
        record_data = _read_bounded(private, MAX_TIMING_RECORD_BYTES)
        # Refuse malformed/stale records before opening any other evidence.
        review_offline_soc_stage_timing(
            record_data, expected_record_sha256=args.expected_record_sha256,
        )
        supplied = {key: getattr(args, flag) for key, flag in _EVIDENCE_FLAGS.items()}
        if any(path is not None for path in supplied.values()) and not all(
            path is not None for path in supplied.values()
        ):
            raise ValueError("All five evidence files must be supplied together")
        observed = None
        if all(path is not None for path in supplied.values()):
            observed = {}
            seen = [private]
            for key, path in supplied.items():
                original = _private_regular_file(path)
                if any(os.path.samefile(original, other) for other in seen):
                    raise ValueError("Original evidence files must be distinct")
                seen.append(original)
                observed[key] = _hash_private_evidence_file(original)
        report = review_offline_soc_stage_timing(
            record_data, expected_record_sha256=args.expected_record_sha256,
            observed_evidence_sha256=observed,
        )
    except (ValueError, OSError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError):
        print("Private offline SOC stage timing review refused; inspect local evidence.",
              file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
