"""Read-only, host-key-pinned Zeek ASCII fetch from an authorized Host-only VM.

Does NOT validate physical VMware isolation, operate a Red Team executor,
perform AI inference, or certify a capture as authentic. All evidence stays
outside Git and requires independent student G1-G8 verification.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.lab_scope import inspect_zeek_lab_scope
from blue_team_ai.zeek import MAX_LOG_BYTES

REMOTE_PATHS = (
    "/opt/zeek/logs/current/conn.log",
    "/usr/local/zeek/logs/current/conn.log",
)
# Only the dedicated operator-exported Zeek snapshots are permitted outside
# original Zeek install paths. Reject shell tokens, traversal and other users.
_OPERATOR_SNAPSHOT = re.compile(
    r"/home/([a-z_][a-z0-9_-]{0,31})/da005-private-logs/"
    r"conn-[0-9]{8}T[0-9]{6}\\.log\\Z"
)
MAX_SSH_IDENTITY_BYTES = 64 * 1024
MAX_KNOWN_HOSTS = 1024 * 1024
RFC1918 = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def validate_guest(host: str, cidr: str) -> tuple[str, str]:
    """Limit SCP to one explicitly declared private IPv4 Host-only subnet."""
    try:
        ip = ipaddress.ip_address(host)
        network = ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        raise ValueError("Invalid VM address or canonical subnet") from exc
    if (
        not isinstance(ip, ipaddress.IPv4Address)
        or not isinstance(network, ipaddress.IPv4Network)
        or network.prefixlen < 24
        or not any(network.subnet_of(block) for block in RFC1918)
        or ip not in network
        or ip in (network.network_address, network.broadcast_address)
    ):
        raise ValueError("VM address must be a usable IPv4 host in a private /24-or-narrower CIDR")
    return str(ip), str(network)


def validate_remote_path(remote_path: str, username: str) -> str:
    """Allow only original Zeek files or one user's exact private copy."""
    if not isinstance(remote_path, str):
        raise ValueError("Remote Zeek path must be a string")
    if remote_path in REMOTE_PATHS:
        return remote_path
    match = _OPERATOR_SNAPSHOT.fullmatch(remote_path)
    if match is None or match.group(1) != username:
        raise ValueError("Remote Zeek path is not allowlisted")
    return remote_path


def _private_path(path: Path, *, must_be_file: bool) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Use an absolute, non-symlink private path")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT):
        raise ValueError("Private evidence must stay outside the Git repository")
    if must_be_file and not resolved.is_file():
        raise ValueError("Expected private file")
    if not must_be_file and not resolved.is_dir():
        raise ValueError("Expected existing private directory")
    return resolved


def fetch(
    *,
    host: str,
    cidr: str,
    username: str,
    known_hosts: Path,
    output_dir: Path,
    remote_path: str = REMOTE_PATHS[0],
    identity_file: Path | None = None,
    timeout: int = 45,
) -> dict[str, object]:
    """Fetch and verify a bounded snapshot, writing no files in the repo."""
    ip, network = validate_guest(host, cidr)
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise ValueError("Invalid Linux SSH user")
    remote_path = validate_remote_path(remote_path, username)
    if type(timeout) is not int or not 5 <= timeout <= 120:
        raise ValueError("Invalid bounded timeout")
    known_hosts = _private_path(known_hosts, must_be_file=True)
    output_dir = _private_path(output_dir, must_be_file=False)
    if not 0 < known_hosts.stat().st_size <= MAX_KNOWN_HOSTS:
        raise ValueError("Invalid private SSH known_hosts file")
    if identity_file is not None:
        identity_file = _private_path(identity_file, must_be_file=True)
        if not 0 < identity_file.stat().st_size <= MAX_SSH_IDENTITY_BYTES:
            raise ValueError("Invalid bounded SSH private identity file")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = uuid.uuid4().hex[:12]
    target = output_dir / f"zeek_conn_{stamp}_{suffix}.log"
    receipt_path = output_dir / f"zeek_conn_{stamp}_{suffix}.receipt.json"
    descriptor, tmp_name = tempfile.mkstemp(prefix=".da005-fetch-", dir=output_dir)
    os.close(descriptor)
    temporary = Path(tmp_name)
    published = False
    completed = False
    try:
        # No shell. -F none disables inherited SSH config/proxies; the
        # pinned known_hosts file must be prepared out of band by the student.
        argv = [
            "scp", "-q", "-F", "none", "-P", "22",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "GlobalKnownHostsFile=none",
            "-o", "ConnectTimeout=8",
            *(
                ["-i", str(identity_file), "-o", "IdentitiesOnly=yes"]
                if identity_file is not None else []
            ),
            f"{username}@{ip}:{remote_path}", str(temporary),
        ]
        subprocess.run(argv, check=True, timeout=timeout, capture_output=True)
        with temporary.open("rb") as stream:
            raw = stream.read(MAX_LOG_BYTES + 1)
        if not raw or len(raw) > MAX_LOG_BYTES:
            raise ValueError("Missing or oversized Zeek log")
        # Strict source-format and declared-CIDR checks; these do not prove
        # isolation, authenticity or any model accuracy.
        scope = inspect_zeek_lab_scope(raw, [network])
        os.link(temporary, target)  # atomic, refuses competing target
        published = True
        receipt = {
            "version": 1,
            "capture_kind": "read_only_vmware_scp_snapshot_unverified",
            "remote_host": ip,
            "declared_cidr": network,
            "remote_path": remote_path,
            "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
            "local_log_filename": target.name,
            "log_sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "flow_count": scope["flow_count"],
            "first_event_utc": scope["first_event_utc"],
            "last_event_utc": scope["last_event_utc"],
            "scope_screen_passed": scope["all_endpoints_within_declared_scope"],
            "host_only_isolation_verified": False,
            "capture_authenticity_verified": False,
            "attack_detection_performed": False,
            "red_team_execution_performed": False,
        }
        with receipt_path.open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
        completed = True
        return receipt
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise RuntimeError("Strict SSH/SCP download refused; check Host-only VM SSH, host key, path and permissions") from exc
    finally:
        if not completed:
            receipt_path.unlink(missing_ok=True)
            if published:
                target.unlink(missing_ok=True)
        temporary.unlink(missing_ok=True)



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="Pinned IPv4 address of the VMware Ubuntu guest")
    parser.add_argument("--cidr", required=True, help="Actual Host-only CIDR, such as 192.168.77.0/24")
    parser.add_argument("--user", required=True, help="Read-only SSH account on the guest")
    parser.add_argument("--known-hosts", type=Path, required=True, help="Previously verified SSH host key file")
    parser.add_argument("--output-dir", type=Path, required=True, help="Existing PRIVATE directory outside repository")
    parser.add_argument("--remote-path", default=REMOTE_PATHS[0],
                        help="Original Zeek conn.log or bounded operator-owned snapshot filename")
    parser.add_argument("--identity-file", type=Path,
                        help="Optional existing private ED25519 identity outside the Git repository")
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args(argv)
    try:
        result = fetch(
            host=args.host, cidr=args.cidr, username=args.user,
            known_hosts=args.known_hosts, output_dir=args.output_dir,
            remote_path=args.remote_path, identity_file=args.identity_file,
            timeout=args.timeout,
        )
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"Zeek read-only fetch failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
