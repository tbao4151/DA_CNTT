"""Read-only, SHA-256-pinned comparison of Windows host and guest snapshots."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.paired_network_preflight import assess_paired_network_snapshots

MAX_BYTES = 64 * 1024


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON key")
        obj[key] = value
    return obj


def _load_private_pinned_snapshot(path: Path, pin: str) -> dict:
    if not isinstance(pin, str) or re.fullmatch(r"[0-9a-f]{64}", pin) is None:
        raise ValueError("Invalid independent SHA-256")
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Require absolute, non-symlink evidence path")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT):
        raise ValueError("Evidence must remain outside repository")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected a regular file")
        raw = stream.read(MAX_BYTES + 1)
    if not 0 < len(raw) <= MAX_BYTES or hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError("Snapshot missing, oversized or SHA-256 mismatch")
    obj = json.loads(
        raw.decode("utf-8-sig"), object_pairs_hook=_unique_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
    )
    if not isinstance(obj, dict):
        raise ValueError("Snapshot must be a JSON object")
    return obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-snapshot", type=Path, required=True)
    parser.add_argument("--expected-host-sha256", required=True)
    parser.add_argument("--host-adapter", required=True)
    parser.add_argument("--guest-snapshot", type=Path, required=True)
    parser.add_argument("--expected-guest-sha256", required=True)
    parser.add_argument("--guest-adapter", required=True)
    parser.add_argument("--cidr", required=True)
    args = parser.parse_args(argv)
    try:
        if args.host_snapshot.resolve(strict=True) == args.guest_snapshot.resolve(strict=True):
            raise ValueError("Host and guest evidence must be separate")
        host = _load_private_pinned_snapshot(args.host_snapshot, args.expected_host_sha256)
        guest = _load_private_pinned_snapshot(args.guest_snapshot, args.expected_guest_sha256)
        result = assess_paired_network_snapshots(
            host, guest, host_adapter=args.host_adapter,
            guest_adapter=args.guest_adapter, expected_cidr=args.cidr,
        )
        result["host_snapshot_sha256"] = args.expected_host_sha256
        result["guest_snapshot_sha256"] = args.expected_guest_sha256
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, StopIteration):
        print("Offline paired network configuration preflight refused.", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
