"""Read-only, independently SHA-pinned PCAP/Zeek tuple presence check.

No network access, Zeek execution, model inference, alerts or SOC writes.
Only private original files outside the public repository are accepted.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.offline_pcap import _private_path
from blue_team_ai.pcap_structure import MAX_CLASSIC_PCAP_BYTES
from blue_team_ai.pcap_zeek_tuple import corroborate_pcap_zeek_tuples
from blue_team_ai.zeek import MAX_LOG_BYTES


def _pinned_private_bytes(path: Path, digest: str, *, limit: int) -> bytes:
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("Independent lowercase SHA-256 pin is required")
    private = _private_path(path, must_exist=True)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(private, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Private input must be a regular file")
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ValueError("Private input missing or exceeds bounded size")
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest):
        raise ValueError("Original evidence SHA-256 does not match independent pin")
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--expected-pcap-sha256", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument(
        "--require-timestamp-corroboration", action="store_true",
        help="Opt-in: require a same-tuple PCAP packet within 1 second of every Zeek flow start",
    )
    args = parser.parse_args(argv)
    try:
        pcap_path = _private_path(args.pcap, must_exist=True)
        log_path = _private_path(args.log, must_exist=True)
        if pcap_path == log_path:
            raise ValueError("PCAP and Zeek log must be different private files")
        pcap = _pinned_private_bytes(pcap_path, args.expected_pcap_sha256,
                                     limit=MAX_CLASSIC_PCAP_BYTES)
        log = _pinned_private_bytes(log_path, args.expected_log_sha256,
                                    limit=MAX_LOG_BYTES)
        result = corroborate_pcap_zeek_tuples(
            pcap, log, require_timestamp_corroboration=args.require_timestamp_corroboration,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(f"PCAP/Zeek tuple corroboration refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
