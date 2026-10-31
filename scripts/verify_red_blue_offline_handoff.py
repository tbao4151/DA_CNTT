"""Read-only, private Red/Blue handoff verification; no packets or SOC writes."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.new_log_review import MAX_NEW_LOG_REPORT_BYTES
from blue_team_ai.offline_pcap import _private_path
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from blue_team_ai.zeek import MAX_LOG_BYTES
from red_team_ai.offline_fixture_binding import MAX_AUDIT_BYTES
from shared.offline_handoff import verify_red_blue_offline_handoff


def _read_regular_bounded(path: Path, limit: int) -> bytes:
    if path.is_symlink():
        raise ValueError("Symlinked private file refused")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("Expected a regular private file")
        data = source.read(limit + 1)
    if not 0 < len(data) <= limit:
        raise ValueError("Private evidence exceeds bound or is empty")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--expected-audit-sha256", required=True)
    parser.add_argument("--offline-import-report", required=True, type=Path)
    parser.add_argument("--expected-offline-import-report-sha256", required=True)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--blue-report", required=True, type=Path)
    parser.add_argument("--expected-blue-report-sha256", required=True)
    parser.add_argument("--cidr", required=True, action="append")
    parser.add_argument("--confirm-authorized", action="store_true")
    parser.add_argument("--confirm-offline-only", action="store_true")
    parser.add_argument("--confirm-fixture-reviewed", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not 1 <= len(args.cidr) <= 4:
            raise ValueError("Expected one to four declared Host-only CIDRs")
        files = {
            key: _private_path(value, must_exist=True)
            for key, value in {
                "audit": args.audit,
                "import": args.offline_import_report,
                "pcap": args.pcap,
                "log": args.log,
                "model": args.model,
                "blue": args.blue_report,
            }.items()
        }
        if len(set(files.values())) != len(files):
            raise ValueError("All private evidence roles require distinct files")
        if files["blue"].parent != files["log"].parent or files["blue"].suffix.lower() != ".json":
            raise ValueError("Blue report must be JSON beside the original Zeek log")
        model = load_pinned_zeek_research_model(
            files["model"], expected_sha256=args.expected_model_sha256,
        )
        result = verify_red_blue_offline_handoff(
            audit_data=_read_regular_bounded(files["audit"], MAX_AUDIT_BYTES),
            expected_audit_sha256=args.expected_audit_sha256,
            import_report_path=files["import"],
            expected_import_report_sha256=args.expected_offline_import_report_sha256,
            pcap_path=files["pcap"],
            conn_log_path=files["log"],
            source_data=_read_regular_bounded(files["log"], MAX_LOG_BYTES),
            expected_log_sha256=args.expected_log_sha256,
            model=model,
            model_sha256=args.expected_model_sha256,
            blue_report_data=_read_regular_bounded(files["blue"], MAX_NEW_LOG_REPORT_BYTES),
            expected_blue_report_sha256=args.expected_blue_report_sha256,
            lab_cidrs=args.cidr,
            operator_confirmed_authorized=args.confirm_authorized,
            operator_confirmed_offline=args.confirm_offline_only,
            operator_confirmed_fixture_reviewed=args.confirm_fixture_reviewed,
        )
    except (ValueError, TypeError, OSError, UnicodeError, OverflowError, RecursionError):
        print("Private offline Red/Blue handoff refused; inspect local pins and scope.", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
