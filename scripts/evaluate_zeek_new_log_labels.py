"""Read-only evaluation of a NEW pinned Zeek log against private external labels.

Requires original pre-registered TRAIN/VALIDATION/TEST manifest and all
original captures. Synthetic CI is not evidence of genuine lab detection.
No network, training, model selection, file output, or SOC case writes.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.new_log_evaluation import (
    MAX_NEW_ANNOTATION_BYTES, evaluate_new_log_operator_labels,
)
from blue_team_ai.new_log_review import MAX_NEW_LOG_REPORT_BYTES
from blue_team_ai.partition_guard import verify_declared_partition_exclusion
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from blue_team_ai.zeek import MAX_LOG_BYTES
from check_zeek_partition_exclusion import (
    _check_digest, _private_regular_file, _read_bounded,
)
from evaluate_zeek_lab import MAX_MANIFEST_BYTES, load_experiment_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--expected-model-sha256", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--annotations", type=Path, required=True)
    parser.add_argument("--expected-annotations-sha256", required=True)
    parser.add_argument("--cidr", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        paths = [
            _private_regular_file(path) for path in (
                args.model, args.manifest, args.log, args.report, args.annotations,
            )
        ]
        if len(set(paths)) != len(paths):
            raise ValueError("All private inputs must be distinct")
        model_path, manifest_path, log_path, report_path, annotations_path = paths
        _check_digest(
            _read_bounded(manifest_path, MAX_MANIFEST_BYTES),
            args.expected_manifest_sha256,
        )
        source_data = _read_bounded(log_path, MAX_LOG_BYTES)
        _check_digest(source_data, args.expected_log_sha256)
        annotation_data = _read_bounded(annotations_path, MAX_NEW_ANNOTATION_BYTES)
        _check_digest(annotation_data, args.expected_annotations_sha256)
        report_data = _read_bounded(report_path, MAX_NEW_LOG_REPORT_BYTES)
        model = load_pinned_zeek_research_model(
            model_path, expected_sha256=args.expected_model_sha256,
        )
        captures, manifest_sha256 = load_experiment_manifest(
            manifest_path, lab_cidrs=args.cidr,
            require_label_sha256=True,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
        dataset = build_labeled_lab_dataset(captures)
        guard = verify_declared_partition_exclusion(
            model, dataset, manifest_sha256=manifest_sha256,
            new_capture_sha256=args.expected_log_sha256,
            declared_captures=captures, new_source_data=source_data,
        )
        if guard["declared_flow_identity_nonreuse_checked"] is not True:
            raise ValueError("Original capture identity screening required")
        evaluation = evaluate_new_log_operator_labels(
            source_data, model, report_data, annotation_data,
            expected_log_sha256=args.expected_log_sha256,
            expected_annotation_sha256=args.expected_annotations_sha256,
            model_sha256=args.expected_model_sha256,
            lab_cidrs=args.cidr,
        )
        # Scope of this claim: checks against supplied, pinned manifest only.
        evaluation["declared_partition_screen"] = {
            "manifest_sha256": manifest_sha256,
            "exact_byte_and_normalized_identity_nonreuse": True,
            "capture_counts": guard["declared_capture_counts"],
            "independent_partition_history_verified": False,
        }
    except (
        ValueError, OSError, TypeError, UnicodeError, KeyError,
        OverflowError, RecursionError,
    ):
        print(
            "Private NEW-log labeled evaluation refused; inspect local evidence.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(evaluation, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
