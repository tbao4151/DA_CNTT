"""Operator-assisted fresh Zeek export on owned VMware guest, followed by pinned SCP.

The guest helper must be separately installed root-owned with a narrowly
scoped sudoers entry. Dry-run opens no sockets. This does NOT prove that
newly exported Zeek flows correspond to the last Red probes, nor Blue AI.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import fetch_zeek_hostonly as collector

class ZeekCurrentLogNotReady(RuntimeError):
    """Expected guest readiness condition; no snapshot or SCP was performed."""


REMOTE_HELPER = "/usr/local/sbin/da005-export-zeek-snapshot"
_HELPER_OUTPUT = re.compile(
    r"DA005_ZEEK_SNAPSHOT_V1 "
    r"(/home/da005/da005-private-logs/conn-[0-9]{8}T[0-9]{6}[.]log) "
    r"([0-9a-f]{64})"
)


def export_and_fetch(
    *, host: str, cidr: str, username: str,
    known_hosts: Path, identity_file: Path, output_dir: Path,
    execute: bool = False, operator_confirmed_hostonly: bool = False,
    timeout: int = 45,
) -> dict[str, object]:
    """Run only the fixed audited helper; compare guest hash with SCP bytes."""
    ip, network = collector.validate_guest(host, cidr)
    if username != "da005":
        raise ValueError("Fresh Zeek helper is restricted to the da005 guest")
    if type(timeout) is not int or not 5 <= timeout <= 120:
        raise ValueError("Invalid bounded SSH timeout")
    known = collector._private_path(known_hosts, must_be_file=True)
    key = collector._private_path(identity_file, must_be_file=True)
    output = collector._private_path(output_dir, must_be_file=False)
    if not 0 < known.stat().st_size <= collector.MAX_KNOWN_HOSTS:
        raise ValueError("Invalid private known_hosts file")
    if not 0 < key.stat().st_size <= collector.MAX_SSH_IDENTITY_BYTES:
        raise ValueError("Invalid bounded private SSH identity")

    if not execute:
        if operator_confirmed_hostonly:
            raise ValueError("No Host-only confirmation on a non-executing dry-run")
        return {
            "mode": "DRY_RUN_GUEST_ZEEK_EXPORT_OFF",
            "ssh_executed": False,
            "scp_executed": False,
            "network_activity_performed": False,
            "attack_detection_verified": False,
        }
    if not operator_confirmed_hostonly:
        raise ValueError("Operator must independently confirm Host-only isolation")

    # No shell interpolation. Only the fixed root-owned helper can be run.
    command = [
        "ssh", "-F", "none", "-T", "-p", "22",
        "-i", str(key),
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known}",
        "-o", "GlobalKnownHostsFile=none",
        "-o", "ForwardAgent=no",
        "-o", "ClearAllForwardings=yes",
        f"{username}@{ip}",
        f"sudo -n {REMOTE_HELPER}",
    ]
    proc = subprocess.run(
        command, capture_output=True, text=True,
        encoding="utf-8", errors="strict", timeout=timeout,
        check=False,
    )
    if (
        proc.returncode == 66
        and proc.stderr.strip() == "DA005_ZEEK_CURRENT_LOG_NOT_READY"
    ):
        raise ZeekCurrentLogNotReady(
            "Zeek current conn.log is absent; check Zeek status and generate "
            "an authorized fresh lab connection before retrying."
        )
    if proc.returncode != 0 or len(proc.stdout) > 512:
        # Never print SSH stderr, credentials, guest paths or raw command.
        raise RuntimeError("Bounded guest Zeek export refused")
    line = proc.stdout.rstrip("\n")
    matched = _HELPER_OUTPUT.fullmatch(line)
    if matched is None:
        raise ValueError("Guest exporter returned invalid single-line receipt")
    remote_path, guest_sha = matched.groups()
    collector.validate_remote_path(remote_path, username)

    receipt = collector.fetch(
        host=ip, cidr=network, username=username,
        known_hosts=known, identity_file=key, output_dir=output,
        remote_path=remote_path, timeout=timeout,
    )
    if receipt["log_sha256"] != guest_sha:
        raise RuntimeError(
            "Guest-exported SHA-256 differs from SCP bytes; preserve private "
            "receipt for investigation and do not claim a verified transfer"
        )
    return {
        "mode": "operator_assisted_guest_zeek_export_then_scp",
        "guest_export_command_executed": True,
        "scp_executed": True,
        "remote_snapshot_path": remote_path,
        "local_log_filename": receipt["local_log_filename"],
        "log_sha256": receipt["log_sha256"],
        "flow_count": receipt["flow_count"],
        "guest_export_and_scp_sha256_consistent": True,
        "guest_capture_origin_independently_verified": False,
        "fresh_relative_to_probe_utc_independently_verified": False,
        "zeek_flow_causality_verified": False,
        "vmware_isolation_verified": False,
        "attack_detection_verified": False,
        "blue_ai_executed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cidr", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--execute", action="store_true",
                        help="Opt in to SSH + fixed privileged Zeek export + SCP")
    parser.add_argument("--operator-confirmed-hostonly", action="store_true")
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args(argv)
    try:
        result = export_and_fetch(
            host=args.host, cidr=args.cidr, username=args.user,
            known_hosts=args.known_hosts, identity_file=args.identity_file,
            output_dir=args.output_dir, execute=args.execute,
            operator_confirmed_hostonly=args.operator_confirmed_hostonly,
            timeout=args.timeout,
        )
    except ZeekCurrentLogNotReady:
        print(
            "Guest Zeek current conn.log is not ready. Check Zeek status "
            "and wait for a fresh authorized Host-only flow.",
            file=sys.stderr,
        )
        return 1
    except (ValueError, OSError, RuntimeError, UnicodeError,
            subprocess.SubprocessError):
        print(
            "Guest Zeek export and SCP refused. Check local scope, private "
            "SSH identity, root-owned helper and narrow sudoers rule.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
