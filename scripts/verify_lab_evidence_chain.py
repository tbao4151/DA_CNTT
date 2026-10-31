"""Read-only offline cross-check of a private VMware lab evidence chain.

This only combines existing strict host/guest snapshot and PCAP->Zeek
provenance checks. It neither collects traffic nor certifies network isolation.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import
from blue_team_ai.pcap_structure import MAX_CLASSIC_PCAP_BYTES
from blue_team_ai.pcap_zeek_tuple import corroborate_pcap_zeek_tuples
from blue_team_ai.paired_network_preflight import assess_paired_network_snapshots
from blue_team_ai.zeek import MAX_LOG_BYTES, parse_zeek_conn_log
from check_paired_network_preflight import _load_private_pinned_snapshot
from verify_pcap_zeek_tuple import _pinned_private_bytes


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
    if args.require_host_ipv6_screened and paired["host_ipv6_screened"] is not True:
        raise ValueError("Strict host IPv6 screen requires a valid v2 host snapshot")
    if args.require_guest_endpoint and not args.require_independent_original_pins:
        raise ValueError("Guest flow presence requires the strict original-pin gate")
    if args.require_pcap_framing and not args.require_independent_original_pins:
        raise ValueError("PCAP framing requires the strict original-pin gate")
    if (args.require_pcap_zeek_tuples or args.require_pcap_zeek_timestamps) and not args.require_independent_original_pins:
        raise ValueError("PCAP/Zeek tuple checks require strict independent original pins")
    if args.require_pcap_zeek_timestamps and not args.require_pcap_zeek_tuples:
        raise ValueError("Timestamp check requires PCAP/Zeek tuple check")
    if args.require_distinct_pcap_packets and not args.require_pcap_zeek_timestamps:
        raise ValueError("Distinct packet gate requires timestamp corroboration")
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
        require_pcap_framing=args.require_pcap_framing,
    )
    if all(pin is not None for pin in original_pins):
        if (not hmac.compare_digest(imported["pcap_sha256"], args.expected_pcap_sha256)
                or not hmac.compare_digest(imported["zeek_conn_sha256"], args.expected_log_sha256)):
            raise ValueError("Original evidence does not match independent pins")
    # Opt-in semantic corroboration: re-read *original* bounded files and
    # recheck their hashes against the import verifier before decoding.
    # Tuple/timestamp presence is not a one-to-one packet/flow identity proof.
    tuple_report = None
    if args.require_pcap_zeek_tuples:
        pcap_bytes = _pinned_private_bytes(
            args.pcap, imported["pcap_sha256"], limit=MAX_CLASSIC_PCAP_BYTES,
        )
        zeek_bytes = _pinned_private_bytes(
            args.log, imported["zeek_conn_sha256"], limit=MAX_LOG_BYTES,
        )
        tuple_report = corroborate_pcap_zeek_tuples(
            pcap_bytes, zeek_bytes,
            require_timestamp_corroboration=args.require_pcap_zeek_timestamps,
            require_distinct_packet_corroboration=args.require_distinct_pcap_packets,
        )
        if tuple_report["matched_zeek_flow_count"] != imported["flow_count"]:
            raise ValueError("Tuple corroboration count differs from verified import")
    # Optional research-readiness check: the declared guest must actually
    # occur in at least one *verified* Zeek flow. This does not establish
    # that the capture originated from the guest or that the PCAP is authentic.
    if args.require_guest_endpoint:
        with args.log.open("rb") as source:
            log_bytes = source.read(MAX_LOG_BYTES + 1)
        if (len(log_bytes) > MAX_LOG_BYTES or not hmac.compare_digest(
                hashlib.sha256(log_bytes).hexdigest(), imported["zeek_conn_sha256"])):
            raise ValueError("Zeek evidence changed after provenance verification")
        guest_nic = next(nic for nic in guest["adapters"] if nic["status"] == "Up")
        guest_ip = guest_nic["ipv4"][0]["address"]
        if not any(guest_ip in (flow["src_ip"], flow["dst_ip"])
                   for flow in parse_zeek_conn_log(log_bytes)):
            raise ValueError("Declared guest is absent from the verified Zeek flows")
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
        "host_ipv6_screened": paired["host_ipv6_screened"],
        "host_ipv6_screening_required": args.require_host_ipv6_screened,
        "offline_pcap_zeek_import_consistent": True,
        "pcap_framing_required": args.require_pcap_framing,
        "pcap_framing_verified": imported["pcap_framing_verified"],
        "pcap_packet_count": imported["pcap_packet_count"],
        "pcap_zeek_tuples_required": args.require_pcap_zeek_tuples,
        "pcap_zeek_tuples_verified": tuple_report is not None,
        "pcap_zeek_timestamps_required": args.require_pcap_zeek_timestamps,
        "pcap_zeek_distinct_packets_required": args.require_distinct_pcap_packets,
        "pcap_zeek_distinct_packets_correlated": args.require_distinct_pcap_packets,
        "pcap_zeek_matched_flow_count": (
            tuple_report["matched_zeek_flow_count"] if tuple_report is not None else None
        ),
        "pcap_zeek_nearest_packet_offset_max_ms": (
            tuple_report["timestamp_nearest_packet_offset_max_ms"]
            if tuple_report is not None else None
        ),
        "pcap_zeek_distinct_assigned_offset_max_ms": (
            tuple_report["distinct_assigned_packet_offset_max_ms"]
            if tuple_report is not None else None
        ),
        "pcap_zeek_potential_tuple_reuse": (
            tuple_report["potential_packet_reuse_for_multiple_zeek_flows"]
            if tuple_report is not None else None
        ),
        "packet_to_flow_identity_verified": False,
        "guest_endpoint_presence_required": args.require_guest_endpoint,
        "guest_endpoint_observed_in_verified_log": args.require_guest_endpoint,
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
    parser.add_argument(
        "--require-host-ipv6-screened", action="store_true",
        help="Fail closed on legacy host v1 snapshots without selected-adapter IPv6 visibility",
    )
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--import-report", required=True, type=Path)
    parser.add_argument("--expected-import-report-sha256", required=True)
    parser.add_argument("--expected-pcap-sha256", help="Optional independently recorded original PCAP SHA-256; requires Zeek pin")
    parser.add_argument("--expected-log-sha256", help="Optional independently recorded original conn.log SHA-256; requires PCAP pin")
    parser.add_argument(
        "--require-pcap-framing", action="store_true",
        help="With strict original pins, require valid bounded classic-PCAP packet record framing",
    )
    parser.add_argument(
        "--require-pcap-zeek-tuples", action="store_true",
        help="With strict original pins, require every Zeek IPv4 TCP/UDP 5-tuple in original Ethernet PCAP",
    )
    parser.add_argument(
        "--require-pcap-zeek-timestamps", action="store_true",
        help="With strict pins and tuple check, require same-tuple packet within 1s of Zeek flow start",
    )
    parser.add_argument(
        "--require-distinct-pcap-packets", action="store_true",
        help="Requires tuple and timestamp gates; one matching PCAP record per Zeek flow",
    )
    parser.add_argument(
        "--require-guest-endpoint", action="store_true",
        help="With strict original pins, require a verified Zeek flow involving the declared guest IPv4",
    )
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
