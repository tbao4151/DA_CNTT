"""Inspect private pinned offline Zeek telemetry quality; never capture traffic."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.telemetry_quality import inspect_zeek_telemetry_quality
from blue_team_ai.zeek import MAX_LOG_BYTES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--cidr", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-zeek-types", action="store_true",
                        help="Require compatible Zeek #fields/#types headers (opt-in)")
    parser.add_argument("--event-start-utc", help="Optional inclusive UTC Zeek start-time lower bound, YYYY-MM-DDTHH:MM:SSZ")
    parser.add_argument("--event-end-utc", help="Optional inclusive UTC Zeek start-time upper bound, YYYY-MM-DDTHH:MM:SSZ")
    args = parser.parse_args(argv)
    try:
        if args.log.is_symlink() or args.output.is_symlink():
            raise ValueError("Symlinks are not accepted")
        source = args.log.resolve(strict=True)
        destination = args.output.resolve()
        if (
            not source.is_file() or source.is_relative_to(ROOT)
            or destination.is_relative_to(ROOT) or destination == source
            or destination.exists() or not destination.parent.is_dir()
        ):
            raise ValueError("Use separate private files outside Git")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(source, flags)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Expected a regular private file")
            raw = stream.read(MAX_LOG_BYTES + 1)
        report = inspect_zeek_telemetry_quality(
            raw, expected_sha256=args.expected_log_sha256, lab_cidrs=args.cidr,
            require_zeek_types=args.require_zeek_types,
            event_window_start_utc=args.event_start_utc,
            event_window_end_utc=args.event_end_utc,
        )
        payload = json.dumps(report, indent=2, allow_nan=False) + "\n"
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
        print("Offline quality report saved privately; no capture or attack detection verified.")
        return 0
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError):
        # No private paths, endpoints, UIDs or CIDRs in shared CI output.
        print("Private offline telemetry quality check refused.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
