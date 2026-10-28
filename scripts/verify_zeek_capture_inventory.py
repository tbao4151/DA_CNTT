"""Verify a private Zeek capture inventory and five originals, without writes."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.capture_evidence_verify import verify_capture_inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--expected-report-sha256", required=True)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--cidr", required=True, action="append")
    parser.add_argument("--vmware-screenshot", required=True, type=Path)
    parser.add_argument("--host-adapter-screenshot", required=True, type=Path)
    parser.add_argument("--zeek-version-file", required=True, type=Path)
    parser.add_argument("--scenario-notes", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_capture_inventory(
            args.report,
            expected_report_sha256=args.expected_report_sha256,
            log_path=args.log, cidrs=args.cidr,
            vmware_screenshot=args.vmware_screenshot,
            host_adapter_screenshot=args.host_adapter_screenshot,
            zeek_version_file=args.zeek_version_file,
            scenario_notes=args.scenario_notes,
        )
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError):
        print("Pinned capture inventory verification refused; inspect private originals.", file=sys.stderr)
        return 1
    print(
        f"Verified {result['original_files_verified']} original files and "
        f"{result['flow_count']} Zeek flow records. "
        "Host-only isolation, ground truth and attack detection NOT verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
