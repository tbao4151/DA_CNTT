"""Prepare or validate private, offline Zeek UID annotations without inventing labels.

The template intentionally contains nulls, so the research experiment cannot run
until an operator independently assigns every label. No capture or model I/O.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.zeek import load_zeek_conn_log

MAX_ANNOTATION_BYTES = 2 * 1024 * 1024  # Must match evaluate_zeek_lab.MAX_LABEL_BYTES.


def _unique_log_uids(log_path: Path) -> tuple[str, list[str]]:
    events = load_zeek_conn_log(log_path)
    uids = [event["uid"] for event in events]
    if len(uids) != len(set(uids)):
        raise ValueError("Duplicate Zeek UIDs cannot be independently annotated")
    return events[0]["source_sha256"], uids


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate annotation JSON key")
        obj[key] = value
    return obj


def _invalid_constant(_value: str) -> None:
    raise ValueError("Invalid JSON numeric constant")


def prepare_template(log_path: Path, output_path: Path) -> int:
    """Write an exclusive, private annotation template with null labels only."""
    log = Path(log_path).resolve(strict=True)
    output = Path(output_path).resolve()
    if output.is_relative_to(ROOT) or output == log:
        raise ValueError("Annotation output must be outside the repository and source log")
    digest, uids = _unique_log_uids(log)
    payload = json.dumps(
        {"source_sha256": digest, "labels_by_uid": dict.fromkeys(uids)},
        ensure_ascii=False, indent=2, allow_nan=False,
    ) + "\n"
    encoded = payload.encode("utf-8")
    if len(encoded) > MAX_ANNOTATION_BYTES:
        raise ValueError("Annotation template exceeds experiment input size limit")
    # x mode refuses existing files, including symlinks; no overwrite of evidence.
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)
    return len(uids)


def verify_annotations(log_path: Path, labels_path: Path) -> int:
    """Verify exact UID coverage and strict binary labels; not label authenticity."""
    digest, uids = _unique_log_uids(Path(log_path))
    with Path(labels_path).open("rb") as stream:
        raw = stream.read(MAX_ANNOTATION_BYTES + 1)
    if len(raw) > MAX_ANNOTATION_BYTES:
        raise ValueError("Annotation JSON exceeds experiment input size limit")
    annotation = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
        parse_constant=_invalid_constant,
    )
    if not isinstance(annotation, dict) or set(annotation) != {"source_sha256", "labels_by_uid"}:
        raise ValueError("Expected exact annotation v1 contract")
    if annotation["source_sha256"] != digest:
        raise ValueError("Annotation does not match original Zeek bytes")
    labels = annotation["labels_by_uid"]
    if not isinstance(labels, dict) or set(labels) != set(uids):
        raise ValueError("Annotation UIDs must match the log exactly")
    if any(type(value) is not int or value not in (0, 1) for value in labels.values()):
        raise ValueError("All UIDs need independently assigned binary 0/1 labels")
    return len(uids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="Original Zeek ASCII conn.log")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="Create new private labels.json with null labels")
    mode.add_argument("--verify-labels", type=Path, help="Check completed private labels.json")
    args = parser.parse_args(argv)
    try:
        if args.output is not None:
            count = prepare_template(args.log, args.output)
            print(f"Prepared {count} unlabeled UIDs; independently assign all labels before experiment.")
        else:
            count = verify_annotations(args.log, args.verify_labels)
            print(f"Validated {count} binary UID entries and source digest; label truth is not authenticated.")
        return 0
    except (OSError, ValueError, UnicodeError, TypeError):
        # Avoid printing private file paths, UID values or lab contents.
        print("Offline Zeek annotation operation refused; inspect private inputs locally.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
