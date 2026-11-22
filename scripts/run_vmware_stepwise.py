"""Step-by-step: benign VMware traffic -> bounded Zeek SCP -> optional Blue research.

One command, but NOT live attack/detection or autonomous Red/Blue AI:
traffic generation is fixed, explicit opt-in, and operator-selected.
Research scoring requires a separately pinned private Zeek v1 JSON model.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import fetch_zeek_hostonly as collector
import export_and_fetch_zeek_hostonly as fresh_export
import run_hostonly_benign_traffic as stimulus
import run_vmware_zeek_research as blue
from shared.zeek_stimulus_match import screen_candidate_zeek_matches


def run_sequence(
    *,
    source_ip: str,
    target_ip: str,
    cidr: str,
    scenario_id: str,
    username: str,
    known_hosts: Path,
    output_dir: Path,
    identity_file: Path | None = None,
    remote_path: str = collector.REMOTE_PATHS[0],
    fresh_guest_snapshot: bool = False,
    execute: bool = False,
    operator_confirmed_hostonly: bool = False,
    attempts: int = 2,
    settle_s: int = 2,
    zeek_wait_s: int = 0,
    model_path: Path | None = None,
    expected_model_sha256: str | None = None,
    progress_sink: Callable[[dict[str, object]], None] | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> dict[str, object]:
    """Prepare all credentials and pinned model *before* sending a packet.

    Optional progress events are emitted only after reaching each real
    operator-assisted stage; they never assert VM isolation, AI attack
    execution, verified detection, or live SOC alerts.
    """
    if progress_sink is not None and not callable(progress_sink):
        raise ValueError("Progress sink must be callable")
    if stop_requested is not None and not callable(stop_requested):
        raise ValueError("Stop checker must be callable")

    def check_stop() -> None:
        if stop_requested is not None and stop_requested():
            raise stimulus.OperatorStopRequested("Operator requested a cooperative stop")

    progress_seq = 0

    def emit(stage: str, status: str, **counts: int) -> None:
        nonlocal progress_seq
        if progress_sink is None:
            return
        if stage not in ("preflight", "red", "zeek", "blue", "audit", "soc"):
            raise ValueError("Unknown VMware progress stage")
        if status not in ("dry_run", "running", "completed", "skipped"):
            raise ValueError("Unknown VMware progress status")
        if any(type(value) is not int or value < 0 for value in counts.values()):
            raise ValueError("Invalid bounded VMware progress count")
        progress_seq += 1
        event: dict[str, object] = {
            "kind": "da005_vmware_stepwise_progress_v1",
            "seq": progress_seq,
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "status": status,
            "mode": "operator_assisted_benign_hostonly_experiment",
            "stage_evidence": "program_execution_only_not_independently_verified",
            "vmware_isolation_verified": False,
            "attack_executed": False,
            "ai_attack_planning_executed": False,
            "operational_ai_detection_verified": False,
            "soc_alerts_created": False,
        }
        if counts:
            event["counts"] = counts
        progress_sink(event)
    scope = stimulus.validate_scope(
        source_ip=source_ip, target_ip=target_ip, cidr=cidr
    )
    if (model_path is None) != (expected_model_sha256 is None):
        raise ValueError("Pinned model and expected SHA-256 must be supplied together")
    if type(settle_s) is not int or not 0 <= settle_s <= 5:
        raise ValueError("Capture settle seconds must be in range 0..5")
    # A Zeek conn.log record can appear long after a TCP probe has closed.
    # Optional, bounded extra grace time avoids exporting an empty/stale log.
    # No speculative guest log reads, extra traffic or repeated snapshots.
    if type(zeek_wait_s) is not int or not 0 <= zeek_wait_s <= 180:
        raise ValueError("Extra Zeek log wait seconds must be in range 0..180")
    if zeek_wait_s and not fresh_guest_snapshot:
        raise ValueError("Extra Zeek log wait is only available for fresh guest snapshots")
    # The fresh guest helper is a deliberately separate, operator-installed
    # privileged export. No arbitrary remote path or model bridge fallback.
    # All these checks run before ANY network probe, even in dry-run.
    if type(fresh_guest_snapshot) is not bool:
        raise ValueError("Fresh guest snapshot selection must be boolean")
    if fresh_guest_snapshot and (
        username != "da005"
        or identity_file is None
        or remote_path != collector.REMOTE_PATHS[0]
        or model_path is not None
    ):
        raise ValueError(
            "Fresh guest snapshot requires da005, a pinned SSH identity, "
            "default remote-path setting, and no unverified Blue model bridge"
        )
    # Dry-run still validates bounded execution parameters but opens no socket.
    planned = stimulus.run(
        source_ip=source_ip, target_ip=target_ip, cidr=cidr,
        scenario_id=scenario_id, count=attempts, execute=False,
    )
    if not execute:
        emit("preflight", "dry_run")
        return {
            "mode": "DRY_RUN_EXECUTION_OFF",
            "scope": scope,
            "traffic": planned,
            "ssh_fetch_performed": False,
            "blue_research_scoring_performed": False,
            "vmware_isolation_verified": False,
            "automated_soc_alerts": False,
        }
    if operator_confirmed_hostonly is not True:
        raise ValueError("Operator must independently confirm VMware Host-only isolation")
    # A preexisting stop marker blocks an executable session before its first
    # socket, including cases in which earlier session cleanup was incomplete.
    check_stop()
    # Hard fail before network traffic if private directories/key files or
    # local model are not prepared. The scp subprocess enforces host-key pinning.
    stimulus._private_dir(output_dir)
    collector._private_path(known_hosts, must_be_file=True)
    collector.validate_remote_path(remote_path, username)
    if identity_file is not None:
        identity = collector._private_path(identity_file, must_be_file=True)
        if not 0 < identity.stat().st_size <= collector.MAX_SSH_IDENTITY_BYTES:
            raise ValueError("SSH identity must be a bounded private file")
    if model_path is not None:
        resolved_model = model_path.resolve(strict=True)
        if model_path.is_symlink() or resolved_model.is_relative_to(ROOT):
            raise ValueError("Private Zeek research model must not be in Git")
        blue.load_pinned_zeek_research_model(
            resolved_model, expected_sha256=expected_model_sha256
        )

    check_stop()
    emit("preflight", "completed")
    check_stop()
    emit("red", "running")
    traffic_options = dict(
        source_ip=source_ip, target_ip=target_ip, cidr=cidr,
        scenario_id=scenario_id, count=attempts, execute=True,
        operator_confirmed_hostonly=True, output_dir=output_dir,
    )
    if stop_requested is not None:
        traffic_options["stop_requested"] = stop_requested
    traffic_result = stimulus.run(**traffic_options)
    check_stop()
    emit("red", "completed", attempted_probes=traffic_result["network_attempts"])
    check_stop()
    emit("zeek", "running")
    # Zeek may append a completed conn.log record asynchronously.
    # This does not prove that the record corresponds to our probes.
    if settle_s:
        # This small flush wait is non-interruptible by a stop marker; the
        # requested stop is enforced immediately afterward, before SCP.
        time.sleep(settle_s)
    check_stop()
    if fresh_guest_snapshot:
        # Zeek may emit conn.log on timeout rather than socket close. Keep
        # this additional wait opt-in, limited and cooperative with STOP.
        # Only ONE privileged snapshot export is requested afterward.
        for _ in range(zeek_wait_s):
            check_stop()
            time.sleep(1)
    check_stop()
    if model_path is None:
        if fresh_guest_snapshot:
            # One bounded SSH sudo helper call, then pinned SCP; the guest
            # creates this snapshot AFTER benign traffic rather than fetching
            # a stale pre-probe export. No model inference is implied.
            zeek_receipt = fresh_export.export_and_fetch(
                host=target_ip, cidr=cidr, username=username,
                known_hosts=known_hosts, identity_file=identity_file,
                output_dir=output_dir, execute=True,
                operator_confirmed_hostonly=True,
            )
            if (
                zeek_receipt.get("guest_export_and_scp_sha256_consistent") is not True
                or zeek_receipt.get("scp_executed") is not True
            ):
                raise RuntimeError("Fresh guest export receipt failed verification")
        else:
            zeek_receipt = collector.fetch(
                host=target_ip, cidr=cidr,
                username=username, known_hosts=known_hosts, output_dir=output_dir,
                identity_file=identity_file, remote_path=remote_path,
            )
        blue_result = None
        log_name = zeek_receipt["local_log_filename"]
        log_sha = zeek_receipt["log_sha256"]
        flow_count = zeek_receipt["flow_count"]
        emit("zeek", "completed", snapshot_flow_count=flow_count)
        emit("blue", "skipped")
    else:
        blue_result = blue.run_bridge(
            host=target_ip, cidr=cidr, username=username,
            known_hosts=known_hosts, output_dir=output_dir,
            identity_file=identity_file, remote_path=remote_path,
            model_path=model_path, expected_model_sha256=expected_model_sha256,
        )
        log_name = blue_result["log_file"]
        log_sha = blue_result["log_sha256"]
        flow_count = blue_result["flow_count"]
        # The bridge performs both SCP and research scoring internally. We
        # report each completion only AFTER it returns, not before.
        emit("zeek", "completed", snapshot_flow_count=flow_count)
        emit("blue", "completed", research_candidate_count=blue_result["research_candidate_count"])
    check_stop()
    emit("audit", "running")
    # Verify the locally fetched bytes AGAIN at the session-correlation boundary.
    # Filename and digest originate from the bounded SCP receipt/bridge.
    log_path = output_dir.resolve(strict=True) / str(log_name)
    with log_path.open("rb") as stream:
        raw = stream.read(collector.MAX_LOG_BYTES + 1)
    correlation = screen_candidate_zeek_matches(
        traffic_result, raw, expected_log_sha256=str(log_sha),
    )
    correlation_file = log_path.with_suffix(".candidate-links.json")
    check_stop()
    if correlation_file.is_symlink():
        raise ValueError("Candidate link output symlink rejected")
    with correlation_file.open("x", encoding="utf-8") as stream:
        json.dump(correlation, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    emit("audit", "completed",
         candidate_matches=correlation["candidate_match_count"],
         unmatched_attempts=correlation["unmatched_probe_count"])
    check_stop()
    emit("soc", "skipped")
    return {
        "mode": "STEPWISE_VMWARE_BENIGN_CAPTURE",
        "scope": scope,
        "scenario_id": scenario_id,
        "traffic_receipt": traffic_result.get("private_receipt_filename"),
        "traffic_attempts": traffic_result["network_attempts"],
        "log_filename": log_name,
        "captured_log_flow_count": flow_count,
        "candidate_links_file": correlation_file.name,
        "candidate_matching_attempts": correlation["candidate_match_count"],
        "unmatched_attempts": correlation["unmatched_probe_count"],
        "research_report_filename": blue_result["report_file"] if blue_result else None,
        "research_candidate_count": blue_result["research_candidate_count"] if blue_result else None,
        "ssh_fetch_performed": True,
        "fresh_guest_snapshot_export_performed": fresh_guest_snapshot,
        "blue_research_scoring_performed": blue_result is not None,
        "source_to_log_correlation_verified": False,
        "vmware_isolation_verified": False,
        "attack_executed": False,
        "operational_detection_verified": False,
        "automated_soc_alerts": False,
        "full_one_click_dual_ai": False,
    }


def _make_stop_checker(stop_file: Path | None, output_dir: Path):
    """Bind an optional STOP marker to the exact private evidence directory.

    Only the literal DA005_STOP.flag name is supported. Never read file bytes,
    resolve shell commands, or allow an arbitrary destination.
    """
    if stop_file is None:
        return None
    if not stop_file.is_absolute() or stop_file.name != "DA005_STOP.flag":
        raise ValueError("STOP marker must be the pinned absolute DA005_STOP.flag")
    private_dir = stimulus._private_dir(output_dir)
    if stop_file.parent.resolve(strict=True) != private_dir or stop_file.is_symlink():
        raise ValueError("STOP marker must be inside the exact private evidence directory")

    def check() -> bool:
        # A newly created marker or a tampered symlink requests an immediate
        # refusal at the next boundary, without reading it or following links.
        return stop_file.is_symlink() or stop_file.exists()

    return check


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--cidr", required=True)
    parser.add_argument("--scenario", required=True, choices=tuple(stimulus.SCENARIOS))
    parser.add_argument("--user", required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path,
                        help="Operator-owned SSH key outside Git")
    parser.add_argument("--remote-path", default=collector.REMOTE_PATHS[0],
                        help="Original Zeek path or tightly allowlisted snapshot")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--fresh-guest-snapshot", action="store_true",
                        help="Opt in to the fixed, root-owned da005 helper for a post-probe snapshot, then SCP. No Blue model.")
    parser.add_argument("--attempts", type=int, default=2)
    parser.add_argument("--settle-s", type=int, default=2)
    parser.add_argument("--zeek-wait-s", type=int, default=0,
                        help="Additional 0..180 second bounded cooperative wait for delayed conn.log before ONE fresh export")
    parser.add_argument("--model", type=Path)
    parser.add_argument("--expected-model-sha256")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--operator-confirmed-hostonly", action="store_true")
    parser.add_argument("--stop-file", type=Path,
                        help="Optional fixed private DA005_STOP.flag marker checked between phases")
    parser.add_argument("--progress-jsonl", action="store_true",
                        help="Stream provenance-limited JSONL stage events to stdout, not verified live AI alerts")
    options = parser.parse_args(argv)
    try:
        report = run_sequence(
            source_ip=options.source_ip,
            target_ip=options.target_ip,
            cidr=options.cidr,
            scenario_id=options.scenario,
            username=options.user,
            known_hosts=options.known_hosts,
            identity_file=options.identity_file,
            remote_path=options.remote_path,
            fresh_guest_snapshot=options.fresh_guest_snapshot,
            output_dir=options.output_dir,
            attempts=options.attempts,
            settle_s=options.settle_s,
            zeek_wait_s=options.zeek_wait_s,
            model_path=options.model,
            expected_model_sha256=options.expected_model_sha256,
            execute=options.execute,
            operator_confirmed_hostonly=options.operator_confirmed_hostonly,
            stop_requested=_make_stop_checker(options.stop_file, options.output_dir),
            progress_sink=(
                (lambda event: print(json.dumps(event, ensure_ascii=False,
                                                allow_nan=False), flush=True))
                if options.progress_jsonl else None
            ),
        )
    except (ValueError, OSError, RuntimeError, TypeError, KeyboardInterrupt):
        if options.progress_jsonl:
            print(json.dumps({
                "kind": "da005_vmware_stepwise_terminal_v1",
                "status": "refused",
                "attack_executed": False,
                "operational_ai_detection_verified": False,
                "soc_alerts_created": False,
            }, ensure_ascii=False), flush=True)
        print(
            "VMware stepwise experiment refused. Check local authorized Host-only "
            "scope, evidence, Zeek path, SSH host key and Zeek model.",
            file=sys.stderr,
        )
        return 1
    if options.progress_jsonl:
        print(json.dumps({
            "kind": "da005_vmware_stepwise_terminal_v1",
            "status": "completed" if report["mode"] != "DRY_RUN_EXECUTION_OFF" else "dry_run",
            "result": {
                "mode": report["mode"],
                "network_attempts": report.get("traffic_attempts", report.get("traffic", {}).get("network_attempts", 0)),
                "captured_log_flow_count": report.get("captured_log_flow_count"),
                "research_candidate_count": report.get("research_candidate_count"),
                "ssh_fetch_performed": report.get("ssh_fetch_performed", False),
                "fresh_guest_snapshot_export_performed": report.get("fresh_guest_snapshot_export_performed", False),
                "blue_research_scoring_performed": report.get("blue_research_scoring_performed", False),
                "vmware_isolation_verified": False,
                "attack_executed": False,
                "operational_ai_detection_verified": False,
                "soc_alerts_created": False,
            },
        }, ensure_ascii=False, allow_nan=False), flush=True)
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
