"""Read-only Windows host network evidence snapshot for a private VMware lab.

Runs only local, allowlisted diagnostic commands. The output is sensitive,
operator-owned evidence, NOT an isolation check or a network capture.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
MAX_COMMAND_BYTES = 256 * 1024
COMMANDS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("ipconfig", ("ipconfig.exe", "/all"), "host-ipconfig-all.txt"),
    ("ipv4_routes", ("route.exe", "print", "-4"), "host-route-ipv4.txt"),
    (
        "ipv4_interfaces",
        ("netsh.exe", "interface", "ipv4", "show", "interfaces"),
        "host-ipv4-interfaces.txt",
    ),
)
REPORT_NAME = "host-network-preflight.json"


def validate_preflight_directory(directory: Path) -> Path:
    """Reject in-repository, missing, symlinked or pre-populated outputs."""
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise ValueError("Use an existing private absolute directory (not a symlink)")
    resolved = directory.resolve(strict=True)
    if resolved.is_relative_to(REPO_ROOT):
        raise ValueError("Private evidence must be outside the Git repository")
    for name in (REPORT_NAME, *(item[2] for item in COMMANDS)):
        if (resolved / name).exists() or (resolved / name).is_symlink():
            raise ValueError("Refusing to overwrite existing private evidence")
    return resolved


def collect_windows_host_preflight(
    output_dir: Path,
    *,
    platform_name: str | None = None,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, object]:
    """Save host-only *context*, not proof of guest isolation.

    No shell, socket, network probe, adapter modification, or VM action.
    All commands finish successfully before any file is written.
    """
    if (platform_name if platform_name is not None else sys.platform) != "win32":
        raise ValueError("This read-only evidence helper runs on Windows only")
    directory = validate_preflight_directory(output_dir)
    snapshots: dict[str, bytes] = {}
    for role, argv, filename in COMMANDS:
        try:
            completed = runner(
                list(argv), shell=False, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"Local diagnostic command failed: {role}") from exc
        raw = completed.stdout
        if (completed.returncode != 0 or not isinstance(raw, bytes)
                or not 0 < len(raw) <= MAX_COMMAND_BYTES):
            raise ValueError(f"Local diagnostic output refused: {role}")
        snapshots[filename] = raw

    inventory = {
        "schema_version": 1,
        "mode": "windows_host_read_only_network_preflight",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": "Windows",
        "files": {
            role: {
                "filename": filename,
                "sha256": hashlib.sha256(snapshots[filename]).hexdigest(),
                "byte_size": len(snapshots[filename]),
            }
            for role, _, filename in COMMANDS
        },
        "host_only_isolation_verified": False,
        "guest_adapters_verified": False,
        "guest_routes_verified": False,
        "network_traffic_generated": False,
        "attack_detection_performed": False,
        "interpretation": (
            "Read-only host configuration evidence supplied by Windows tools. "
            "Review original private outputs and every guest adapter/route "
            "manually. No VMware Host-only isolation or authorization proof."
        ),
    }
    payload = (json.dumps(inventory, ensure_ascii=False, indent=2, allow_nan=False)
               + "\n").encode("utf-8")
    # Exclusive creation: no silent overwrite of evidence, including symlinks.
    for filename, raw in snapshots.items():
        with (directory / filename).open("xb") as handle:
            handle.write(raw)
    with (directory / REPORT_NAME).open("xb") as handle:
        handle.write(payload)
    return inventory
