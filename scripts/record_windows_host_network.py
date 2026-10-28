"""Save read-only Windows host network configuration evidence outside Git."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.windows_host_preflight import collect_windows_host_preflight


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--confirm-private-evidence", action="store_true",
        help="Acknowledge that hostnames, IP addresses and routes remain private.",
    )
    args = parser.parse_args(argv)
    if not args.confirm_private_evidence:
        parser.error("Explicit --confirm-private-evidence is required")
    try:
        collect_windows_host_preflight(args.output_dir)
    except (ValueError, OSError) as exc:
        print("Windows host preflight refused; inspect private folder locally.", file=sys.stderr)
        return 1
    print(
        "Read-only host snapshot saved outside Git. "
        "Guest isolation, authorization and attack detection NOT verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
