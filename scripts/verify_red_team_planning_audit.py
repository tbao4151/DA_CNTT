"""Read-only private Red Team audit export verifier; no traffic or SOC writes."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from red_team_ai.audit_verify import MAX_AUDIT_BYTES, verify_planning_audit_bytes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--expected-sha256",
                        help="Optional independently preserved SHA-256 of exact export bytes")
    args = parser.parse_args(argv)
    try:
        if args.audit.is_symlink():
            raise ValueError("Symlink input refused")
        source = args.audit.resolve(strict=True)
        if source.is_relative_to(ROOT) or not source.is_file():
            raise ValueError("Use a private regular file outside repository")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(source, flags)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Expected regular file")
            raw = stream.read(MAX_AUDIT_BYTES + 1)
        result = verify_planning_audit_bytes(raw, expected_sha256=args.expected_sha256)
    except (ValueError, OSError, TypeError, UnicodeError, OverflowError):
        print("Private offline Red Team audit verification refused.", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
