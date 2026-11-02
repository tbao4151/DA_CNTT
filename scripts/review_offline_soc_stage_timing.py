"""Read-only aggregate timing review of a privately pinned offline SOC stage record."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.offline_stage_timing import (
    MAX_TIMING_RECORD_BYTES, review_offline_soc_stage_timing,
)
from check_zeek_partition_exclusion import _private_regular_file, _read_bounded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--expected-record-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        private = _private_regular_file(args.record)
        report = review_offline_soc_stage_timing(
            _read_bounded(private, MAX_TIMING_RECORD_BYTES),
            expected_record_sha256=args.expected_record_sha256,
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
