"""Offline host-side VMware lab adapter preflight; does not prove isolation."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from blue_team_ai.host_only_preflight import LabPreflightError, assess_host_only_snapshot

MAX_SNAPSHOT_BYTES = 64 * 1024


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
        if len(pin) != 64 or any(ch not in "0123456789abcdef" for ch in pin):
            raise ValueError("Invalid SHA-256 pin")
        with args.snapshot.open("rb") as handle:
            raw = handle.read(MAX_SNAPSHOT_BYTES + 1)
        if len(raw) > MAX_SNAPSHOT_BYTES or hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError("Snapshot too large or digest mismatch")
        snapshot = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_pairs)
        result = assess_host_only_snapshot(
            snapshot, expected_adapter=args.adapter, expected_cidr=args.cidr
        )
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, LabPreflightError):
        print("Offline host adapter configuration preflight refused.", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
