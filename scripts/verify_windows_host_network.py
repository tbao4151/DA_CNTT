"""Verify an independently pinned private Windows host snapshot offline."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.host_preflight_verify import verify_host_preflight


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected-report-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_host_preflight(
            args.report, expected_report_sha256=args.expected_report_sha256
        )
    except (ValueError, OSError, TypeError):
        print("Private host evidence verification refused; inspect originals locally.", file=sys.stderr)
        return 1
    print(
        f"Pinned report and {result['original_files_verified']} original files match. "
        "VMware Host-only isolation, guest routes and attack detection NOT verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
