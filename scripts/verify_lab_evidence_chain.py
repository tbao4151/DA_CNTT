"""Read-only offline cross-check of a private VMware lab evidence chain.

This only combines existing strict host/guest snapshot and PCAP->Zeek
provenance checks. It neither collects traffic nor certifies network isolation.
"""
from __future__ import annotations

import argparse
import hmac
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import
from blue_team_ai.paired_network_preflight import assess_paired_network_snapshots
from check_paired_network_preflight import _load_private_pinned_snapshot


def verify_chain(args: argparse.Namespace) -> dict[str, object]:
    """Recheck pinned original files without changing or exporting evidence."""
    paths = [
        args.host_snapshot, args.guest_snapshot,
        args.pcap, args.log, args.import_report,
    ]
    if any(not path.is_absolute() or path.is_symlink() for path in paths):
        raise ValueError("Require absolute non-symlink evidence paths")
    resolved = [path.resolve(strict=True) for path in paths]
    if len(set(resolved)) != len(resolved):
        raise ValueError("Evidence paths must be distinct")

    host = _load_private_pinned_snapshot(
        args.host_snapshot, args.expected_host_sha256,
    )
    guest = _load_private_pinned_snapshot(
        args.guest_snapshot, args.expected_guest_sha256,
    )
    paired = assess_paired_network_snapshots(
        host, guest,
        host_adapter=args.host_adapter,
        guest_adapter=args.guest_adapter,
        expected_cidr=args.cidr,
    )
    original_pins = (args.expected_pcap_sha256, args.expected_log_sha256)
    if args.require_independent_original_pins and not all(
        pin is not None for pin in original_pins
    ):
        raise ValueError("Strict lab gate requires both independent original pins")
    if any(pin is not None for pin in original_pins):
        if not all(pin is not None for pin in original_pins):
            raise ValueError("Original PCAP and Zeek SHA-256 pins must be paired")
        if any(re.fullmatch(r"[0-9a-f]{64}", pin) is None for pin in original_pins):
            raise ValueError("Original pins must be lowercase SHA-256 digests")
    imported = verify_offline_pcap_import(
        args.import_report,
        expected_report_sha256=args.expected_import_report_sha256,
        pcap_path=args.pcap,
        log_path=args.log,
        lab_cidrs=[args.cidr],
    )
    if all(pin is not None for pin in original_pins):
        if (not hmac.compare_digest(imported["pcap_sha256"], args.expected_pcap_sha256)
                or not hmac.compare_digest(imported["zeek_conn_sha256"], args.expected_log_sha256)):
            raise ValueError("Original evidence does not match independent pins")
    if not (paired["host_configuration_passed"]
            and paired["guest_configuration_passed"]
            and paired["declared_subnet_consistent"]
            and paired["host_guest_ipv4_distinct"]
            and imported["original_files_verified"] == 2):
        raise ValueError("Incomplete offline evidence checks")
    return {
        "report_version": 1,
        "mode": "offline_private_lab_evidence_consistency_only",
        "configuration_snapshots_consistent": True,
        "offline_pcap_zeek_import_consistent": True,
        "independent_original_pcap_zeek_pins_verified": all(
            pin is not None for pin in original_pins
        ),
        "independent_original_pcap_zeek_pins_required": (
            args.require_independent_original_pins
        ),
        "host_snapshot_sha256": args.expected_host_sha256,
        "guest_snapshot_sha256": args.expected_guest_sha256,
        "import_report_sha256": imported["report_sha256"],
        "pcap_sha256": imported["pcap_sha256"],
        "zeek_conn_sha256": imported["zeek_conn_sha256"],
        "zeek_flow_count": imported["flow_count"],
        "vmware_isolation_verified": False,
        "capture_authenticity_verified": False,
        "traffic_authorized": False,
        "independent_labels_verified": False,
        "ai_inference_performed": False,
        "operational_alerts_created": False,
        "soc_case_created": False,
        "live_detection_latency_measured": False,
        "interpretation": (
            "Only the supplied, independently SHA-256-pinned private files "
            "are mutually consistent under the existing offline checks. "
            "Manually verify VMware isolation, scope authorization, capture "
            "origin and independent ground truth before research claims."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-snapshot", required=True, type=Path)
    parser.add_argument("--expected-host-sha256", required=True)
    parser.add_argument("--host-adapter", required=True)
    parser.add_argument("--guest-snapshot", required=True, type=Path)
    parser.add_argument("--expected-guest-sha256", required=True)
    parser.add_argument("--guest-adapter", required=True)
    parser.add_argument("--cidr", required=True)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--import-report", required=True, type=Path)
    parser.add_argument("--expected-import-report-sha256", required=True)
    parser.add_argument("--expected-pcap-sha256", help="Optional independently recorded original PCAP SHA-256; requires Zeek pin")
    parser.add_argument("--expected-log-sha256", help="Optional independently recorded original conn.log SHA-256; requires PCAP pin")
    parser.add_argument(
        "--require-independent-original-pins", action="store_true",
        help="Fail closed unless both independently recorded original PCAP and Zeek SHA-256 pins are supplied",
    )
    args = parser.parse_args(argv)
    try:
        result = verify_chain(args)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        print("Offline lab evidence consistency check refused.", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
