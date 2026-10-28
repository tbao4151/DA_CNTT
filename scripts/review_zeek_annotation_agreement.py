"""Compare two private independently completed Zeek annotation files offline.

Never produces consensus labels or confirms ground truth. Keep all input/output
outside the public repository; output contains only aggregate counts and hashes.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.annotation_agreement import (
    MAX_ANNOTATION_BYTES, review_zeek_annotator_agreement,
)
from blue_team_ai.zeek import MAX_LOG_BYTES


def _private_file(path: Path, max_bytes: int) -> tuple[Path, bytes]:
    if path.is_symlink():
        raise ValueError("Symlink inputs are not allowed")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT) or not resolved.is_file():
        raise ValueError("Input must be an existing private regular file")
    with resolved.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Input must be a regular file")
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("Input exceeds byte limit")
    return resolved, raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--annotation-a", required=True, type=Path)
    parser.add_argument("--annotation-b", required=True, type=Path)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--expected-a-sha256", required=True)
    parser.add_argument("--expected-b-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        log, source = _private_file(args.log, MAX_LOG_BYTES)
        a_path, a = _private_file(args.annotation_a, MAX_ANNOTATION_BYTES)
        b_path, b = _private_file(args.annotation_b, MAX_ANNOTATION_BYTES)
        if len({log, a_path, b_path}) != 3:
            raise ValueError("Log and annotation files must be distinct")
        output = args.output.absolute()
        if (
            output.suffix.lower() != ".json"
            or output.is_symlink() or output.exists()
            or output.parent.resolve(strict=True) != log.parent
            or output.is_relative_to(ROOT)
            or output in {log, a_path, b_path}
        ):
            raise ValueError("Output must be a new private JSON beside the original log")
        report = review_zeek_annotator_agreement(
            source, a, b,
            expected_log_sha256=args.expected_log_sha256,
            expected_a_sha256=args.expected_a_sha256,
            expected_b_sha256=args.expected_b_sha256,
        )
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError):
        print("Private annotation agreement review refused; inspect inputs locally.", file=sys.stderr)
        return 1
    print("Offline agreement summary written; no ground truth or independence verified.")
    print("flow_count=" + str(report["flow_count"]))
    print("disagreement_count=" + str(report["disagreement_count"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
