"""Verify a pinned, private Windows guest configuration snapshot offline."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from blue_team_ai.guest_network_preflight import assess_guest_network_snapshot

MAX_BYTES = 64 * 1024


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--expected-snapshot-sha256", required=True)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--cidr", required=True)
    args = parser.parse_args(argv)
    try:
        pin = args.expected_snapshot_sha256
        if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
            raise ValueError("Invalid independent pin")
        if args.snapshot.is_symlink():
            raise ValueError("Symlink snapshot refused")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(args.snapshot, flags)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Regular snapshot file required")
            raw = stream.read(MAX_BYTES + 1)
        if not 0 < len(raw) <= MAX_BYTES or hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("Snapshot size or pin mismatch")
        snapshot = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite")))
        report = assess_guest_network_snapshot(
            snapshot, expected_adapter=args.adapter, expected_cidr=args.cidr,
        )
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        print("Offline guest configuration preflight refused.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
