"""Read-only comparison of two independently pinned private Zeek conn.log files.

This CLI never executes Zeek, captures traffic, scores AI or writes SOC cases.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.offline_pcap import _private_path
from blue_team_ai.zeek import MAX_LOG_BYTES
from blue_team_ai.zeek_reprocessing_compare import (
    compare_parsed_zeek_reprocessing,
    compare_strict_zeek_reprocessing,
)
from verify_pcap_zeek_tuple import _pinned_private_bytes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-log", type=Path, required=True)
    parser.add_argument("--expected-original-sha256", required=True)
    parser.add_argument("--reprocessed-log", type=Path, required=True)
    parser.add_argument("--expected-reprocessed-sha256", required=True)
    parser.add_argument("--strict-all-fields", action="store_true", help="Compare every raw Zeek column except UID, including extra fields and declared types")
    args = parser.parse_args(argv)
    try:
        original_path = _private_path(args.original_log, must_exist=True)
        reprocessed_path = _private_path(args.reprocessed_log, must_exist=True)
        if original_path == reprocessed_path:
            raise ValueError("Comparison requires two distinct private log files")
        original = _pinned_private_bytes(
            original_path, args.expected_original_sha256, limit=MAX_LOG_BYTES,
        )
        reprocessed = _pinned_private_bytes(
            reprocessed_path, args.expected_reprocessed_sha256, limit=MAX_LOG_BYTES,
        )
        comparator = (compare_strict_zeek_reprocessing if args.strict_all_fields
                      else compare_parsed_zeek_reprocessing)
        report = comparator(original, reprocessed)
    except (OSError, ValueError, TypeError) as exc:
        print(f"Offline Zeek reprocessing comparison refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
