"""Check declared IPv4 lab scope in a private offline Zeek conn.log; no traffic."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.lab_scope import inspect_zeek_lab_scope
from blue_team_ai.zeek import MAX_LOG_BYTES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True, help="Local authorized Zeek ASCII conn.log")
    parser.add_argument("--cidr", action="append", required=True, help="Explicit RFC1918 lab CIDR; repeat up to four times")
    parser.add_argument("--output", type=Path, required=True, help="New JSON report outside the repository")
    args = parser.parse_args(argv)
    try:
        log_path = args.log.resolve(strict=True)
        output_path = args.output.resolve()
        if not log_path.is_file() or output_path == log_path or output_path.is_relative_to(ROOT):
            raise ValueError("Unsafe input or output path")
        if not output_path.parent.is_dir():
            raise ValueError("Output parent directory does not exist")
        if output_path.exists():
            raise FileExistsError("Report exists")
        with log_path.open("rb") as stream:
            raw = stream.read(MAX_LOG_BYTES + 1)
        report = inspect_zeek_lab_scope(raw, args.cidr)
        payload = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        with output_path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
        print("Offline scope screening complete; isolation and label truth NOT verified.")
        return 0
    except (ValueError, OSError, UnicodeError, TypeError):
        # Avoid exposing raw private paths, IPs, UIDs, or CIDRs in shared CI logs.
        print("Offline scope screening refused; inspect private inputs locally.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
