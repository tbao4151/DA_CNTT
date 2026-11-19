"""One-command VMware Zeek SNAPSHOT -> pinned offline Blue research scoring.

Requires an independently SHA-256-pinned private Zeek research JSON model.
No Red Team executor, automated alerts, SOC database writes, or claims about
physical VMware isolation, model truth, or live detection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.new_log_review import MAX_NEW_LOG_REPORT_BYTES
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from fetch_zeek_hostonly import REMOTE_PATHS, fetch
import score_zeek_new_log

_LOG_NAME = re.compile(r"zeek_conn_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{12}\.log\Z")


def run_bridge(
    *,
    host: str,
    cidr: str,
    username: str,
    known_hosts: Path,
    output_dir: Path,
    model_path: Path,
    expected_model_sha256: str,
    remote_path: str = REMOTE_PATHS[0],
    identity_file: Path | None = None,
    timeout: int = 45,
    manifest_path: Path | None = None,
    expected_manifest_sha256: str | None = None,
) -> dict[str, object]:
    """Verify model before network transfer, then pin snapshot and score offline.

    The retrieval receipt pins the bytes as observed by THIS program; this is
    not an independent assertion that the guest created an authentic capture.
    A successful score is a research candidate list, not a confirmed attack.
    """
    if (manifest_path is None) != (expected_manifest_sha256 is None):
        raise ValueError("Manifest and independent hash must be supplied together")
    if model_path.is_symlink():
        raise ValueError("Private model symlinks are not accepted")
    resolved_model = model_path.resolve(strict=True)
    if not resolved_model.is_file() or resolved_model.is_relative_to(ROOT):
        raise ValueError("Private model must be a file outside repository")
    if output_dir.is_symlink():
        raise ValueError("Output directory symlinks are not accepted")
    output_dir = output_dir.resolve(strict=True)
    if not output_dir.is_dir() or output_dir.is_relative_to(ROOT):
        raise ValueError("Output directory must exist outside repository")
    if manifest_path is not None:
        if manifest_path.is_symlink():
            raise ValueError("Private manifest symlinks are not accepted")
        resolved_manifest = manifest_path.resolve(strict=True)
        if (not resolved_manifest.is_file()
                or resolved_manifest.is_relative_to(ROOT)
                or resolved_manifest == resolved_model):
            raise ValueError("Manifest must be a distinct private file")
    # Fail before contacting the guest on invalid/incompatible model bytes.
    load_pinned_zeek_research_model(
        resolved_model, expected_sha256=expected_model_sha256
    )

    receipt = fetch(
        host=host,
        cidr=cidr,
        username=username,
        known_hosts=known_hosts,
        output_dir=output_dir,
        remote_path=remote_path,
        identity_file=identity_file,
        timeout=timeout,
    )
    log_name = receipt.get("local_log_filename")
    if not isinstance(log_name, str) or not _LOG_NAME.fullmatch(log_name):
        raise RuntimeError("Invalid capture file name from fetch receipt")
    log_path = output_dir / log_name
    report_path = log_path.with_suffix(".research.json")
    if report_path.exists() or report_path.is_symlink():
        raise RuntimeError("Research output already exists; refusing overwrite")
    score_args = [
        "--model", str(resolved_model),
        "--expected-model-sha256", expected_model_sha256,
        "--log", str(log_path),
        "--expected-log-sha256", str(receipt["log_sha256"]),
        "--cidr", cidr,
        "--output", str(report_path),
    ]
    if manifest_path is not None:
        score_args += [
            "--manifest", str(resolved_manifest),
            "--expected-manifest-sha256", str(expected_manifest_sha256),
        ]
    # Delegate all actual feature/model verification, train/validation exclusion,
    # and (optional) held-out partition screening to the existing tested CLI.
    if score_zeek_new_log.main(score_args) != 0:
        raise RuntimeError(
            "Offline Zeek research scoring refused; preserved read-only capture "
            "for private investigation, without generating an AI report"
        )
    # Fail closed before claiming a complete bridge if downstream output does
    # not bind the exact fetched SHA-256 or tries to claim a live/alert result.
    with report_path.open("rb") as stream:
        payload = stream.read(MAX_NEW_LOG_REPORT_BYTES + 1)
    if not payload or len(payload) > MAX_NEW_LOG_REPORT_BYTES:
        raise RuntimeError("Research report missing or oversized")
    report = json.loads(payload.decode("utf-8", errors="strict"))
    if (
        not isinstance(report, dict)
        or report.get("source_sha256") != receipt["log_sha256"]
        or report.get("model_sha256") != expected_model_sha256
        or report.get("mode") != "offline_new_zeek_research_inference_only"
        or report.get("live_capture") is not False
        or report.get("automated_alerts") is not False
        or report.get("soc_cases_created") is not False
        or type(report.get("flow_count")) is not int
        or type(report.get("research_candidate_count")) is not int
        or report["flow_count"] != receipt["flow_count"]
        or not 0 <= report["research_candidate_count"] <= report["flow_count"]
    ):
        raise RuntimeError("Research report is not bound to the fetched capture")
    return {
        "mode": "vmware_scp_snapshot_then_offline_zeek_research",
        "capture_origin": "private_vmware_scp_snapshot_unverified",
        "receipt_file": log_path.with_suffix(".receipt.json").name,
        "log_file": log_path.name,
        "log_sha256": receipt["log_sha256"],
        "report_file": report_path.name,
        "report_sha256": hashlib.sha256(payload).hexdigest(),
        "model_sha256": expected_model_sha256,
        "flow_count": report["flow_count"],
        "research_candidate_count": report["research_candidate_count"],
        "train_validation_test_exclusion_checked": manifest_path is not None,
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "operational_attack_detection_verified": False,
        "red_team_execution_performed": False,
        "automated_alerts": False,
        "soc_cases_created": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cidr", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--remote-path", default=REMOTE_PATHS[0])
    parser.add_argument("--identity-file", type=Path,
                        help="Private SSH key; never included in a research report")
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args(argv)
    try:
        result = run_bridge(
            host=args.host, cidr=args.cidr, username=args.user,
            known_hosts=args.known_hosts, output_dir=args.output_dir,
            model_path=args.model, expected_model_sha256=args.expected_model_sha256,
            remote_path=args.remote_path, identity_file=args.identity_file,
            timeout=args.timeout,
            manifest_path=args.manifest,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
    except (ValueError, OSError, TypeError, RuntimeError, UnicodeError,
            OverflowError, json.JSONDecodeError):
        print(
            "VMware Zeek snapshot-to-research bridge refused. "
            "Check private setup, pinned model and local evidence; "
            "no verified operational attack alert was created.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
