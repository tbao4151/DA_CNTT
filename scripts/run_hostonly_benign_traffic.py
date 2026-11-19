"""Bounded BENIGN network-stimulus generator for an operator-owned VMware Host-only lab.

Not an attack/exploit engine, AI planner, or detector. No automatic target scan.
Offline DRY-RUN by default. The --execute gate requires a real bind address
on the Windows Host-only adapter, a single pinned guest, and human confirmation.
Only three fixed non-destructive scenarios can run. No credential attempts.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parents[1]
RFC1918 = tuple(ipaddress.ip_network(s) for s in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
class OperatorStopRequested(RuntimeError):
    """A cooperative lab stop was requested before another network attempt."""


SCENARIOS = {
    "baseline_web": {"protocol": "tcp", "port": 8080, "purpose": "HTTP HEAD to owned lab-only web service"},
    "dns_variation": {"protocol": "udp", "port": 53, "purpose": "Nonrecursive A query for da005.invalid"},
    "connection_shift": {"protocol": "tcp", "port": 22, "purpose": "TCP connect/close to owned lab SSH service; no auth"},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_scope(*, source_ip: str, target_ip: str, cidr: str) -> dict[str, str]:
    """Require distinct usable IPv4 hosts on exactly one private /24-or-narrower lab subnet."""
    try:
        network = ipaddress.ip_network(cidr, strict=True)
        source = ipaddress.ip_address(source_ip)
        target = ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise ValueError("Invalid canonical Host-only CIDR, source, or target") from exc
    if (
        not isinstance(network, ipaddress.IPv4Network)
        or not isinstance(source, ipaddress.IPv4Address)
        or not isinstance(target, ipaddress.IPv4Address)
        or network.prefixlen < 24
        or not any(network.subnet_of(block) for block in RFC1918)
        or source not in network or target not in network
        or source == target
        or source in (network.network_address, network.broadcast_address)
        or target in (network.network_address, network.broadcast_address)
    ):
        raise ValueError("Both distinct endpoints must be usable IPv4 hosts of one private /24-or-narrower CIDR")
    return {"source_ip": str(source), "target_ip": str(target), "cidr": str(network)}


def _private_dir(path: Path) -> Path:
    if path.is_symlink() or not path.is_absolute():
        raise ValueError("Evidence directory must be absolute and not a symlink")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir() or resolved.is_relative_to(ROOT):
        raise ValueError("Evidence directory must exist outside Git repository")
    return resolved


def _dns_message() -> bytes:
    # One fixed, nonrecursive A question for .invalid (RFC-reserved).
    # No resolver or external DNS call on the Windows host; bytes go to the
    # exact guest IP specified and constrained by validate_scope.
    question = b"\x05da005\x07invalid\x00\x00\x01\x00\x01"
    return b"\xda\x05\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question


def send_benign_probe(*, scenario_id: str, source_ip: str, target_ip: str,
                      timeout_s: float = 1.0) -> dict[str, object]:
    """Perform ONE fixed benign probe; no destination discovery or retries.

    An unsuccessful probe may still produce Zeek network events; never infer
    packet capture or AI detection from a successful socket call alone.
    """
    if scenario_id not in SCENARIOS:
        raise ValueError("Unknown fixed benign scenario")
    if not isinstance(timeout_s, (float, int)) or not 0.25 <= timeout_s <= 2.0:
        raise ValueError("Invalid bounded timeout")
    spec = SCENARIOS[scenario_id]
    destination = (target_ip, spec["port"])
    result: dict[str, object] = {
        "scenario_id": scenario_id, "protocol": spec["protocol"], "port": spec["port"],
        "attempted_at_utc": _now(), "socket_operation_success": False,
        "network_capture_verified": False, "ai_detection_performed": False,
    }
    try:
        if spec["protocol"] == "tcp":
            with socket.create_connection(
                destination, timeout=timeout_s, source_address=(source_ip, 0)
            ) as connection:
                connection.settimeout(timeout_s)
                if scenario_id == "baseline_web":
                    # HEAD does not modify guest files; require an independently
                    # started test web service on port 8080.
                    connection.sendall(
                        b"HEAD / HTTP/1.0\r\nHost: da005.invalid\r\nConnection: close\r\n\r\n"
                    )
                    # Read at most a small response fragment; do not retain data.
                    connection.recv(64)
            result["socket_operation_success"] = True
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                connection.bind((source_ip, 0))
                connection.settimeout(timeout_s)
                connection.connect(destination)
                connection.send(_dns_message())
                # An unanswered UDP query is still an attempted probe; record
                # missing response as a separate result, never a detected attack.
                try:
                    response = connection.recv(512)
                    result["socket_operation_success"] = bool(response)
                except socket.timeout:
                    result["socket_operation_success"] = False
    except OSError as exc:
        # Local, private receipt only. Do not preserve raw exception strings
        # that may include environment paths or private endpoint details.
        result["socket_error_type"] = type(exc).__name__
    return result


def run(
    *, source_ip: str, target_ip: str, cidr: str,
    scenario_id: str, count: int = 1, delay_ms: int = 500,
    timeout_s: float = 1.0, execute: bool = False,
    operator_confirmed_hostonly: bool = False,
    output_dir: Path | None = None,
    stop_requested=None,
) -> dict[str, object]:
    if stop_requested is not None and not callable(stop_requested):
        raise ValueError("Stop checker must be callable")
    scope = validate_scope(source_ip=source_ip, target_ip=target_ip, cidr=cidr)
    if scenario_id not in SCENARIOS:
        raise ValueError("Unknown fixed scenario")
    if type(count) is not int or not 1 <= count <= 4:
        raise ValueError("Bounded probe count must be 1..4")
    if type(delay_ms) is not int or not 500 <= delay_ms <= 3000:
        raise ValueError("Probe interval must be 500..3000 milliseconds")
    if type(timeout_s) not in (int, float) or not 0.25 <= timeout_s <= 2.0:
        raise ValueError("Probe timeout must be 0.25..2 seconds")
    if execute:
        if operator_confirmed_hostonly is not True:
            raise ValueError("Execution requires explicit confirmation of VERIFIED local VMware Host-only isolation")
        if output_dir is None:
            raise ValueError("Execution requires a private receipt directory")
        evidence_dir = _private_dir(output_dir)
    else:
        if operator_confirmed_hostonly:
            raise ValueError("No execution confirmation is needed for dry-run")
        evidence_dir = None
    report: dict[str, object] = {
        "kind": "da005_benign_vmware_hostonly_network_stimulus",
        "mode": "BENIGN_LAB_EXECUTION" if execute else "DRY_RUN_EXECUTION_OFF",
        "scope": scope,
        "scenario_id": scenario_id,
        "purpose": SCENARIOS[scenario_id]["purpose"],
        "protocol": SCENARIOS[scenario_id]["protocol"],
        "fixed_destination_port": SCENARIOS[scenario_id]["port"],
        "planned_attempts": count,
        "interval_ms": delay_ms,
        "started_at_utc": _now() if execute else None,
        "ended_at_utc": None,
        "events": [],
        "network_attempts": 0,
        "network_capture_verified": False,
        "attack_executed": False,
        "ai_decision_made": False,
        "ai_detection_performed": False,
        "model_metrics_computed": False,
        "hostonly_isolation_verified_by_software": False,
    }
    if not execute:
        return report
    for index in range(count):
        # Cooperative cancellation is checked before *each* new socket.
        # It cannot interrupt a socket already in flight.
        if stop_requested is not None and stop_requested():
            raise OperatorStopRequested("Operator requested stop before network probe")
        event = send_benign_probe(
            scenario_id=scenario_id,
            source_ip=scope["source_ip"], target_ip=scope["target_ip"],
            timeout_s=timeout_s,
        )
        report["events"].append(event)
        report["network_attempts"] = index + 1
        if index + 1 < count:
            time.sleep(delay_ms / 1000)
    report["ended_at_utc"] = _now()
    assert evidence_dir is not None
    receipt = evidence_dir / (
        "da005_benign_"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "_" + uuid.uuid4().hex[:12] + ".json"
    )
    # Exclusive create; do not overwrite another experiment's evidence.
    with receipt.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    report["private_receipt_filename"] = receipt.name
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-ip", required=True, help="Pinned Windows VMnet Host-only IPv4")
    parser.add_argument("--target-ip", required=True, help="Pinned owned Ubuntu Host-only IPv4")
    parser.add_argument("--cidr", required=True, help="Declared canonical RFC1918 Host-only CIDR")
    parser.add_argument("--scenario", required=True, choices=tuple(SCENARIOS))
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--delay-ms", type=int, default=500)
    parser.add_argument("--timeout-s", type=float, default=1.0)
    parser.add_argument("--execute", action="store_true", help="Opt in to actual bounded traffic; default is OFF")
    parser.add_argument("--operator-confirmed-hostonly", action="store_true",
                        help="Operator has independently verified interface/route/isolation")
    parser.add_argument("--output-dir", type=Path, help="Existing absolute PRIVATE folder outside Git")
    args = parser.parse_args(argv)
    try:
        report = run(
            source_ip=args.source_ip, target_ip=args.target_ip, cidr=args.cidr,
            scenario_id=args.scenario, count=args.count, delay_ms=args.delay_ms,
            timeout_s=args.timeout_s, execute=args.execute,
            operator_confirmed_hostonly=args.operator_confirmed_hostonly,
            output_dir=args.output_dir,
        )
    except (ValueError, OSError, TypeError):
        print("Benign Host-only probe refused; verify pinned source, target and isolation.", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
