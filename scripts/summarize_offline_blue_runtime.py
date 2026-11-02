"""Summarize pinned paired offline Blue CLI stdout timings (never live latency)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.offline_runtime_summary import summarize_pinned_runs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = summarize_pinned_runs(args.manifest, args.expected_manifest_sha256, ROOT)
    except (ValueError, OSError, TypeError, OverflowError, RecursionError):
        print("Private offline runtime summary refused; inspect local evidence.", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
