"""Read-only cross-check of a private Zeek research trace against ALL original captures.

Unlike the single-log Streamlit reviewer, this explicitly requires the original
TRAIN/VALIDATION/TEST Zeek logs and UID annotations from one pinned manifest.
No training, network traffic, alerts, SQLite writes, or report files are created.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.labeled_dataset import SPLITS, build_labeled_lab_dataset
from blue_team_ai.offline_baseline import evaluate_offline_zeek_baseline
from blue_team_ai.trace_review import MAX_PRIVATE_TRACE_BYTES, review_private_zeek_trace
from evaluate_zeek_lab import (
    _invalid_constant,
    _no_duplicate_keys,
    load_experiment_manifest,
)


def verify_original_capture_chain(
    manifest_path: str | Path, trace_path: str | Path, *,
    require_label_sha256: bool = False,
    recompute_model_predictions: bool = False,
) -> dict[str, object]:
    """Verify source bytes, split metadata, and TEST labels/UIDs, without writes.

    SHA-256 and operator annotations are consistency evidence, not independent
    authentication of capture provenance, ground truth, or model training.
    """
    if type(require_label_sha256) is not bool:
        raise ValueError("Annotation pin requirement must be boolean")
    if type(recompute_model_predictions) is not bool:
        raise ValueError("Model replay requirement must be boolean")
    manifest = Path(manifest_path).resolve(strict=True)
    trace = Path(trace_path).resolve(strict=True)
    if not manifest.is_file() or not trace.is_file() or not trace.is_relative_to(manifest.parent):
        raise ValueError("Private trace must be a regular file within the manifest directory")
    captures, manifest_digest = load_experiment_manifest(
        manifest, require_label_sha256=require_label_sha256,
    )
    dataset = build_labeled_lab_dataset(captures)
    with trace.open("rb") as stream:
        trace_bytes = stream.read(MAX_PRIVATE_TRACE_BYTES + 1)
    if not 0 < len(trace_bytes) <= MAX_PRIVATE_TRACE_BYTES:
        raise ValueError("Private trace exceeds bounded input size")
    report = json.loads(
        trace_bytes.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
        parse_constant=_invalid_constant,
    )
    if not isinstance(report, dict) or report.get("input_manifest_sha256") != manifest_digest:
        raise ValueError("Private trace does not match original manifest SHA-256")
    expected_provenance = {
        split: {
            "flows": len(dataset.labels[split]),
            "source_sha256": sorted({
                row["source_sha256"] for row in dataset.provenance[split]
            }),
            "host_groups": len({
                row["host_group"] for row in dataset.provenance[split]
            }),
            "sessions": len({
                row["session_id"] for row in dataset.provenance[split]
            }),
        }
        for split in SPLITS
    }
    if report.get("provenance") != expected_provenance:
        raise ValueError("Private trace split provenance differs from original captures")

    private_trace = report.get("private_test_trace")
    rows = private_trace.get("flows") if isinstance(private_trace, dict) else None
    if not isinstance(rows, list):
        raise ValueError("Missing private held-out TEST trace")
    original_labels = {
        (row["source_sha256"], row["uid"]): label
        for row, label in zip(
            dataset.provenance["test"], dataset.labels["test"], strict=True,
        )
    }
    trace_labels: dict[tuple[str, str], int] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid private TEST trace row")
        if not isinstance(row.get("source_sha256"), str) or not isinstance(row.get("uid"), str):
            raise ValueError("Invalid private TEST source/UID")
        key = (row["source_sha256"], row["uid"])
        if key in trace_labels:
            raise ValueError("Duplicate private TEST source/UID")
        if key not in original_labels or type(row.get("operator_supplied_label")) is not int:
            raise ValueError("Private TEST trace source/UID or label mismatch")
        trace_labels[key] = row["operator_supplied_label"]
    if trace_labels != original_labels:
        raise ValueError("Private TEST trace labels/UIDs differ from original annotations")

    verified_test_sources = 0
    for capture in captures:
        if capture["split"] == "test":
            # The existing reviewer also verifies per-flow probability, verdict,
            # confusion matrix, Wilson diagnostics, and exact original UID join.
            review_private_zeek_trace(capture["log_bytes"], trace_bytes)
            verified_test_sources += 1
    if recompute_model_predictions:
        # This is a separate opt-in scientific reproducibility check. Fit a
        # fresh Zeek-only model using the original TRAIN captures, select the
        # threshold on VALIDATION, and compare held-out TEST probabilities.
        # The standard source-consistency mode never trains a model.
        if type(report.get("report_version")) is not int or report["report_version"] != 6:
            raise ValueError("Model replay requires current Zeek research report v6")
        replay = evaluate_offline_zeek_baseline(dataset, include_private_test_trace=True)
        for field in (
            "model", "preprocessing", "threshold_selection", "feature_schema_version",
            "feature_columns", "selected_threshold",
        ):
            if report.get(field) != replay[field]:
                raise ValueError("Private trace differs from recomputed model protocol")
        for split in ("validation", "test"):
            expected = replay[f"{split}_metrics"]
            observed = report.get(f"{split}_metrics")
            if not isinstance(observed, dict) or set(observed) != set(expected):
                raise ValueError("Private trace differs from recomputed model metrics")
            for name, value in expected.items():
                current = observed[name]
                if name in ("tp", "fp", "tn", "fn", "support"):
                    matched = type(current) is int and current == value
                else:
                    matched = (
                        type(current) in (int, float)
                        and math.isfinite(current)
                        and math.isclose(current, value, rel_tol=0.0, abs_tol=1e-8)
                    )
                if not matched:
                    raise ValueError("Private trace differs from recomputed model metrics")
        expected_flows = {
            (row["source_sha256"], row["uid"]): row
            for row in replay["private_test_trace"]["flows"]
        }
        if len(expected_flows) != len(rows):
            raise ValueError("Private trace differs from recomputed model coverage")
        for row in rows:
            original = expected_flows.get((row["source_sha256"], row["uid"]))
            if (
                original is None
                or row["predicted_attack"] is not original["predicted_attack"]
                or not math.isclose(
                    row["attack_probability"], original["attack_probability"],
                    rel_tol=0.0, abs_tol=1e-8,
                )
            ):
                raise ValueError("Private trace differs from recomputed model probabilities")
    return {
        "mode": "offline_all_split_original_capture_trace_review",
        "original_capture_sources_verified": len(captures),
        "heldout_test_sources_verified": verified_test_sources,
        "heldout_test_flows_verified": len(original_labels),
        "all_original_source_hashes_verified": True,
        "declared_split_metadata_matches_originals": True,
        "test_labels_match_original_annotations": True,
        "annotation_sha256_pins_required": require_label_sha256,
        "model_predictions_recomputed": recompute_model_predictions,
        "capture_authenticity_verified": False,
        "independent_ground_truth_verified": False,
        "model_provenance_authenticated": False,
        "host_only_isolation_verified": False,
        "live_capture": False,
        "automated_alerts": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--require-label-sha256", action="store_true")
    parser.add_argument("--recompute-model-predictions", action="store_true",
                        help="Opt in to refit Zeek-only research baseline and verify held-out probabilities")
    args = parser.parse_args(argv)
    try:
        result = verify_original_capture_chain(
            args.manifest, args.trace,
            require_label_sha256=args.require_label_sha256,
            recompute_model_predictions=args.recompute_model_predictions,
        )
    except (OSError, ValueError, UnicodeError, TypeError, KeyError) as exc:
        # Never echo user-supplied paths, IPs, UIDs or labels to stdout.
        print(f"Offline verification refused: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
