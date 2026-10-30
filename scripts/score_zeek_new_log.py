"""Score a NEW, private, authorized Zeek conn.log with a pinned research model.

Offline only. No socket, traffic generation, model fitting, label lookup,
operational alert or SOC database write. Never use a held-out TEST capture.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.partition_guard import verify_declared_partition_exclusion
from evaluate_zeek_lab import load_experiment_manifest
from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import
from blue_team_ai.offline_pcap import MAX_PCAP_BYTES
from blue_team_ai.pcap_zeek_tuple import corroborate_pcap_zeek_tuples
from blue_team_ai.new_log_inference import score_new_zeek_log
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from blue_team_ai.zeek import MAX_LOG_BYTES


def _private_file(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Direct symlinks are not accepted")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT) or not resolved.is_file():
        raise ValueError("Private input must be a regular file outside repository")
    return resolved


def _read_bounded_capture(path: Path, *, limit: int = MAX_LOG_BYTES) -> bytes:
    if path.is_symlink():
        raise ValueError("Capture symlink not accepted")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Capture must be a regular file")
        return stream.read(limit + 1)


def _write_new_report_atomically(output: Path, payload: str) -> None:
    """Publish a complete private report without overwriting a competing file.

    A same-directory temporary file is flushed before an atomic hard-link
    publication. Unlike os.replace(), os.link() refuses an existing target,
    including one created between the preflight and publication. On filesystems
    without hard-link support, fail closed rather than risk partial evidence.
    """
    descriptor, temporary = tempfile.mkstemp(
        prefix=".da005-new-log-", suffix=".tmp", dir=output.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output)
    finally:
        os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, type=Path, help="Private JSON model")
    parser.add_argument("--expected-model-sha256", required=True,
                        help="Model digest independently recorded before this run")
    parser.add_argument("--log", required=True, type=Path, help="NEW private Zeek ASCII conn.log")
    parser.add_argument("--expected-log-sha256", required=True,
                        help="Capture digest independently recorded before this run")
    parser.add_argument("--cidr", action="append", required=True,
                        help="Actual owned RFC1918 Host-only CIDR (repeat up to four)")
    parser.add_argument("--offline-import-report", type=Path,
                        help="Optional pinned PCAP -> Zeek import report")
    parser.add_argument("--expected-offline-import-report-sha256",
                        help="Independent SHA-256 of the original import report")
    parser.add_argument("--offline-import-pcap", type=Path,
                        help="Original private classic PCAP for provenance verification")
    parser.add_argument("--require-pcap-zeek-timestamp-corroboration", action="store_true",
                        help="Opt-in 1s PCAP/Zeek timestamp-presence gate before research scoring; requires all three offline import options")
    parser.add_argument("--manifest", type=Path,
                        help="Optional private TRAIN/VALIDATION/TEST manifest; requires pinned labels")
    parser.add_argument("--expected-manifest-sha256",
                        help="Independent manifest SHA-256 (required with --manifest)")
    parser.add_argument("--output", required=True, type=Path,
                        help="NEW private prediction JSON alongside the capture")
    parser.add_argument("--measure-inference-publication-runtime", action="store_true",
                        help="Opt-in offline score + JSON publication software timing only")
    args = parser.parse_args(argv)
    try:
        model_path = _private_file(args.model)
        log_path = _private_file(args.log)
        if model_path == log_path:
            raise ValueError("Model and capture must be different")
        if (args.manifest is None) != (args.expected_manifest_sha256 is None):
            raise ValueError("Manifest and independent digest must be supplied together")
        manifest_path = _private_file(args.manifest) if args.manifest is not None else None
        if manifest_path is not None and manifest_path in (model_path, log_path):
            raise ValueError("Manifest must differ from model and new capture")
        output = args.output.absolute()
        if (
            output.name in ("", ".", "..") or output.suffix.lower() != ".json"
            or output.parent.resolve(strict=True) != log_path.parent
            or output.is_relative_to(ROOT)
            or output.exists() or output.is_symlink()
        ):
            raise ValueError("Output must be a new private JSON alongside the capture")
        import_options = (
            args.offline_import_report,
            args.expected_offline_import_report_sha256,
            args.offline_import_pcap,
        )
        if args.require_pcap_zeek_timestamp_corroboration and not all(
            option is not None for option in import_options
        ):
            raise ValueError("Timestamp gate requires all pinned offline PCAP import inputs")
        if any(option is not None for option in import_options):
            if not all(option is not None for option in import_options):
                raise ValueError("All offline PCAP provenance options must be supplied")
            verified_import = verify_offline_pcap_import(
                args.offline_import_report,
                expected_report_sha256=args.expected_offline_import_report_sha256,
                pcap_path=args.offline_import_pcap,
                log_path=log_path,
                lab_cidrs=args.cidr,
            )
            if verified_import["zeek_conn_sha256"] != args.expected_log_sha256:
                raise ValueError("Pinned log does not match the verified PCAP import")
        model = load_pinned_zeek_research_model(
            model_path, expected_sha256=args.expected_model_sha256,
        )
        raw = _read_bounded_capture(log_path)
        if args.require_pcap_zeek_timestamp_corroboration:
            # The prior import-report check pins the PCAP and conn.log, but
            # it does not establish their packet/flow temporal consistency.
            # Re-read bounded original bytes at the scoring boundary and
            # compare them against that independently pinned import report.
            pcap_path = _private_file(args.offline_import_pcap)
            pcap_bytes = _read_bounded_capture(pcap_path, limit=MAX_PCAP_BYTES)
            if (len(pcap_bytes) > MAX_PCAP_BYTES
                    or hashlib.sha256(pcap_bytes).hexdigest() != verified_import["pcap_sha256"]
                    or hashlib.sha256(raw).hexdigest() != verified_import["zeek_conn_sha256"]):
                raise ValueError("Original PCAP/Zeek bytes changed before timestamp gate")
            corroborate_pcap_zeek_tuples(
                pcap_bytes, raw, require_timestamp_corroboration=True,
            )
        if manifest_path is not None:
            # A separate preflight is not sufficient: re-read the pinned
            # original TRAIN/VALIDATION/TEST captures at the scoring boundary.
            captures, manifest_sha = load_experiment_manifest(
                manifest_path, lab_cidrs=args.cidr,
                require_label_sha256=True,
                expected_manifest_sha256=args.expected_manifest_sha256,
            )
            dataset = build_labeled_lab_dataset(captures)
            partition_gate = verify_declared_partition_exclusion(
                model, dataset, manifest_sha256=manifest_sha,
                new_capture_sha256=args.expected_log_sha256,
                declared_captures=captures, new_source_data=raw,
            )
            if partition_gate["declared_flow_identity_nonreuse_checked"] is not True:
                raise ValueError("Original capture identity screen did not run")
        started_ns = time.perf_counter_ns() if args.measure_inference_publication_runtime else None
        report = score_new_zeek_log(
            raw, model,
            expected_log_sha256=args.expected_log_sha256,
            lab_cidrs=args.cidr,
            model_sha256=args.expected_model_sha256,
        )
        payload = (json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
        _write_new_report_atomically(output, payload)
        elapsed_ns = time.perf_counter_ns() - started_ns if started_ns is not None else None
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError):
        # Avoid leaking private paths, IPs, UIDs or model parameters in shared CI.
        print("Private new-log Zeek inference refused; inspect local evidence.", file=sys.stderr)
        return 1
    print("Private offline Zeek research predictions written (NOT operational alerts).")
    print("flow_count=" + str(report["flow_count"]))
    print("research_candidate_count=" + str(report["research_candidate_count"]))
    if manifest_path is not None:
        print("Pinned declared TRAIN/VALIDATION/TEST and flow identity non-reuse screened.")
        print("This does NOT independently verify capture history or label truth.")
    if args.require_pcap_zeek_timestamp_corroboration:
        print("Original PCAP/Zeek one-second timestamp presence checked before scoring.")
        print("This is NOT proof of packet-to-flow derivation or capture authenticity.")
    print("No SOC case, network traffic, label evaluation or live detection performed.")
    if elapsed_ns is not None:
        print(f"offline_new_log_score_publish_duration_ms={elapsed_ns / 1_000_000:.6f}")
        print("offline_new_log_score_publish_boundary=score_json_atomic_publish")
        print("detection_latency_measured=false; preflight_capture_zeek_excluded=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
