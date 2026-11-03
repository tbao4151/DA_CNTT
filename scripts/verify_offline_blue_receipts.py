"""Verify private pinned Blue CLI exit receipts without running any process."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.offline_receipt_verify import verify_paired_receipts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--include-runtime-summary", action="store_true",
                        help="Summarize verified receipt timings (offline descriptive only)")
    args = parser.parse_args(argv)
    try:
        result = verify_paired_receipts(
            args.manifest, args.expected_manifest_sha256, ROOT,
            include_runtime_summary=args.include_runtime_summary,
        )
    except (ValueError, OSError, TypeError, OverflowError, RecursionError):
        print("Private Blue receipt verification refused; inspect local evidence.",
              file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
