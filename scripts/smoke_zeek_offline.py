"""Offline acceptance: run an installed Zeek on a BENIGN SYNTHETIC PCAP.

Does not use VMware, capture traffic, perform attacks, score AI, or create cases.
The resulting private files are a local toolchain smoke test, not lab evidence.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.zeek_smoke import run_benign_zeek_smoke


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="New absolute private directory outside repository")
    parser.add_argument("--confirm-synthetic-only", action="store_true",
                        help="Acknowledge that this is synthetic benign traffic, NOT lab capture")
    args = parser.parse_args(argv)
    try:
        result = run_benign_zeek_smoke(
            args.output_dir,
            operator_confirmed_synthetic=args.confirm_synthetic_only,
        )
    except (ValueError, OSError, TypeError) as exc:
        print(f"Benign offline Zeek smoke refused: {type(exc).__name__}. "
              "No network interface was accessed. Inspect private output.", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
