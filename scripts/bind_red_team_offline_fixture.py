"""Read-only Red Team proposal-to-PCAP evidence binding; never replay traffic."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.offline_pcap import _private_path
from red_team_ai.offline_fixture_binding import MAX_AUDIT_BYTES, bind_pending_offline_fixture


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, help="Private exported Red Team planning audit JSON")
    parser.add_argument("--expected-audit-sha256", required=True)
    parser.add_argument("--report", required=True, help="Private offline_import_report.json")
    parser.add_argument("--expected-report-sha256", required=True)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--log", required=True, help="Private Zeek conn.log")
    parser.add_argument("--cidr", action="append", required=True, help="Approved lab CIDR; repeat for each")
    parser.add_argument("--confirm-authorized", action="store_true")
    parser.add_argument("--confirm-offline-only", action="store_true")
    parser.add_argument("--confirm-fixture-reviewed", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not 1 <= len(args.cidr) <= 4:
            raise ValueError("Expected one to four lab CIDRs")
        audit_path = Path(args.audit)
        if audit_path.is_symlink():
            raise ValueError("Symlinked audit refused")
        audit_path = _private_path(audit_path, must_exist=True)
        if not audit_path.is_file():
            raise ValueError("Expected a private regular audit file")
        with audit_path.open("rb") as source:
            audit_data = source.read(MAX_AUDIT_BYTES + 1)
        result = bind_pending_offline_fixture(
            audit_data,
            expected_audit_sha256=args.expected_audit_sha256,
            import_report_path=args.report,
            expected_import_report_sha256=args.expected_report_sha256,
            pcap_path=args.pcap,
            conn_log_path=args.log,
            lab_cidrs=args.cidr,
            operator_confirmed_authorized=args.confirm_authorized,
            operator_confirmed_offline=args.confirm_offline_only,
            operator_confirmed_fixture_reviewed=args.confirm_fixture_reviewed,
        )
    except (ValueError, TypeError, OSError, UnicodeError, RecursionError):
        print("Refused private offline Red Team evidence binding; check original pins and scope.", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
