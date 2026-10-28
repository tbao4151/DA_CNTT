"""Finalize a manually adjudicated private Zeek worksheet into annotation-v1.

The output is NOT authenticated ground truth. This command never writes into
the repository, overwrites reviewer inputs, scores AI or accesses a network.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.annotation_agreement import MAX_ANNOTATION_BYTES
from blue_team_ai.adjudicated_labels import finalize_private_adjudication
from blue_team_ai.disagreement_review import MAX_WORKSHEET_BYTES
from blue_team_ai.zeek import MAX_LOG_BYTES
from review_zeek_annotation_agreement import _private_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--annotation-a", required=True, type=Path)
    parser.add_argument("--annotation-b", required=True, type=Path)
    parser.add_argument("--worksheet", required=True, type=Path)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--expected-a-sha256", required=True)
    parser.add_argument("--expected-b-sha256", required=True)
    parser.add_argument("--expected-worksheet-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--confirm-manual-evidence-review", action="store_true",
        help="Confirm independent evidence was reviewed for every disagreement.",
    )
    args = parser.parse_args(argv)
    try:
        if not args.confirm_manual_evidence_review:
            raise ValueError("Explicit evidence review confirmation required")
        log_path, source = _private_file(args.log, MAX_LOG_BYTES)
        a_path, a = _private_file(args.annotation_a, MAX_ANNOTATION_BYTES)
        b_path, b = _private_file(args.annotation_b, MAX_ANNOTATION_BYTES)
        worksheet_path, worksheet = _private_file(args.worksheet, MAX_WORKSHEET_BYTES)
        inputs = {log_path, a_path, b_path, worksheet_path}
        if len(inputs) != 4:
            raise ValueError("Four distinct original inputs required")
        output = args.output.absolute()
        private_parent = output.parent.resolve(strict=True)
        if (
            output.suffix.lower() != ".json"
            or output.exists() or output.is_symlink()
            or private_parent != log_path.parent
            or private_parent.is_relative_to(ROOT)
            or private_parent / output.name in inputs
        ):
            raise ValueError("Output must be a new private JSON beside the original log")
        result = finalize_private_adjudication(
            source, a, b, worksheet,
            expected_log_sha256=args.expected_log_sha256,
            expected_a_sha256=args.expected_a_sha256,
            expected_b_sha256=args.expected_b_sha256,
            expected_worksheet_sha256=args.expected_worksheet_sha256,
        )
        payload = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if len(payload.encode("utf-8")) > MAX_ANNOTATION_BYTES:
            raise ValueError("Final annotation-v1 exceeds experiment size limit")
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        print("Private adjudication refused; inspect original evidence locally.", file=sys.stderr)
        return 1
    print("Private annotation-v1 created from manual review; ground truth NOT verified.")
    print("flow_count=" + str(len(result["labels_by_uid"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
