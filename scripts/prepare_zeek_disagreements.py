"""Create an explicitly requested private UID disagreement worksheet offline.

This does not adjudicate labels or create consensus. The existing aggregate
agreement CLI remains unchanged and does not expose any UID.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.annotation_agreement import MAX_ANNOTATION_BYTES
from blue_team_ai.disagreement_review import (
    MAX_WORKSHEET_BYTES, build_private_disagreement_template,
)
from blue_team_ai.zeek import MAX_LOG_BYTES
from review_zeek_annotation_agreement import _private_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--annotation-a", required=True, type=Path)
    parser.add_argument("--annotation-b", required=True, type=Path)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--expected-a-sha256", required=True)
    parser.add_argument("--expected-b-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--acknowledge-private-uids", action="store_true",
        help="Explicitly permit private UID-level output (never commit this JSON).",
    )
    args = parser.parse_args(argv)
    try:
        if not args.acknowledge_private_uids:
            raise ValueError("Explicit private UID output acknowledgement required")
        log_path, source = _private_file(args.log, MAX_LOG_BYTES)
        a_path, a = _private_file(args.annotation_a, MAX_ANNOTATION_BYTES)
        b_path, b = _private_file(args.annotation_b, MAX_ANNOTATION_BYTES)
        if len({log_path, a_path, b_path}) != 3:
            raise ValueError("Original log and reviewer inputs must be distinct")
        output = args.output.absolute()
        if (
            output.suffix.lower() != ".json"
            or output.is_symlink() or output.exists()
            or output.parent.resolve(strict=True) != log_path.parent
            or output.parent.resolve(strict=True).is_relative_to(ROOT)
            or output in {log_path, a_path, b_path}
        ):
            raise ValueError("Output must be a new private JSON beside the original log")
        report = build_private_disagreement_template(
            source, a, b,
            expected_log_sha256=args.expected_log_sha256,
            expected_a_sha256=args.expected_a_sha256,
            expected_b_sha256=args.expected_b_sha256,
        )
        payload = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if len(payload.encode("utf-8")) > MAX_WORKSHEET_BYTES:
            raise ValueError("Private disagreement worksheet exceeds size limit")
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError):
        print("Private disagreement worksheet refused; inspect inputs locally.", file=sys.stderr)
        return 1
    print("Private disagreement worksheet created; no labels adjudicated.")
    print("disagreement_count=" + str(report["disagreement_count"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
