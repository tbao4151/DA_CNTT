"""Verify private finalized Zeek labels against pinned manual-review originals.

Read-only, offline and aggregate-only; never prints UIDs, IPs or private paths.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.annotation_agreement import MAX_ANNOTATION_BYTES
from blue_team_ai.disagreement_review import MAX_WORKSHEET_BYTES
from blue_team_ai.final_label_verify import verify_finalized_annotation_chain
from blue_team_ai.zeek import MAX_LOG_BYTES
from review_zeek_annotation_agreement import _private_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--annotation-a", required=True, type=Path)
    parser.add_argument("--annotation-b", required=True, type=Path)
    parser.add_argument("--worksheet", required=True, type=Path)
    parser.add_argument("--final-annotation", required=True, type=Path)
    for name in ("log", "a", "b", "worksheet", "final"):
        parser.add_argument(f"--expected-{name}-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        inputs = (
            (args.log, MAX_LOG_BYTES),
            (args.annotation_a, MAX_ANNOTATION_BYTES),
            (args.annotation_b, MAX_ANNOTATION_BYTES),
            (args.worksheet, MAX_WORKSHEET_BYTES),
            (args.final_annotation, MAX_ANNOTATION_BYTES),
        )
        originals = [_private_file(path, limit) for path, limit in inputs]
        if len({path for path, _ in originals}) != len(originals):
            raise ValueError("All five private original files must be distinct")
        if len({path.parent for path, _ in originals}) != 1:
            raise ValueError("All original evidence must be in one private capture directory")
        result = verify_finalized_annotation_chain(
            *(raw for _, raw in originals),
            expected_log_sha256=args.expected_log_sha256,
            expected_a_sha256=args.expected_a_sha256,
            expected_b_sha256=args.expected_b_sha256,
            expected_worksheet_sha256=args.expected_worksheet_sha256,
            expected_final_sha256=args.expected_final_sha256,
        )
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        print("Private final-label chain verification refused; inspect evidence locally.", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
