"""Read-only verification of a separately pinned private PCAP -> Zeek import."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--expected-report-sha256", required=True)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--cidr", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_offline_pcap_import(
            args.report,
            expected_report_sha256=args.expected_report_sha256,
            pcap_path=args.pcap, log_path=args.log, lab_cidrs=args.cidr,
        )
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError):
        print("Pinned offline PCAP import verification refused; inspect private originals.",
              file=sys.stderr)
        return 1
    print(
        f"Verified original PCAP, Zeek conn.log and report for "
        f"{result['flow_count']} offline flows. "
        "VMware isolation, capture authenticity, ground truth and AI detection NOT verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
