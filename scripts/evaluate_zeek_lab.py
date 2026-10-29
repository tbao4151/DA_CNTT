"""Run an explicitly labeled Zeek research experiment entirely offline.

Inputs must be local, bounded and pre-partitioned. The command does not
capture traffic, authenticate ground truth, persist a model or create alerts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from collections.abc import Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.labeled_dataset import MAX_CAPTURES, SPLITS, build_labeled_lab_dataset
from blue_team_ai.cross_split_overlap import screen_uid_independent_cross_split_overlap
from blue_team_ai.lab_scope import inspect_zeek_lab_scope
from blue_team_ai.offline_baseline import evaluate_offline_zeek_baseline
from blue_team_ai.telemetry_quality import inspect_zeek_telemetry_quality
from blue_team_ai.zeek import MAX_LOG_BYTES

MAX_MANIFEST_BYTES = 256 * 1024
MAX_LABEL_BYTES = 2 * 1024 * 1024
CAPTURE_KEYS = frozenset({
    "log_path", "labels_path", "source_sha256", "session_id", "host_group",
    "split", "label_method", "label_reference",
})
PINNED_CAPTURE_KEYS = CAPTURE_KEYS | {"labels_sha256"}


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("Invalid JSON numeric constant")


def _read_json(path: Path, limit: int, *, expected_sha256: str | None = None) -> object:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Input JSON exceeds size limit")
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Annotation file SHA-256 mismatch")
    return json.loads(
        raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
        parse_constant=_invalid_constant,
    )


def _local_path(root: Path, name: object) -> Path:
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("Expected nonempty relative POSIX input path")
    candidate = Path(name)
    if candidate.is_absolute() or any(part in ("..", ".") for part in name.split("/")):
        raise ValueError("Absolute or traversal input path refused")
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("Input path escapes manifest directory")
    if not resolved.is_file():
        raise ValueError("Input must be a regular file")
    return resolved


def _sha256(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("Expected lowercase SHA-256")
    return value



def _summarize_telemetry_quality(
    captures: list[dict[str, object]], lab_cidrs: Sequence[str] | None,
) -> dict[str, object]:
    """Screen every already-pinned log before fitting; export fixed aggregates only.

    This opt-in quality screen is descriptive. Missing Zeek measurements and
    short sessions remain warnings, not synthetic attack labels or zeros.
    """
    if lab_cidrs is None:
        raise ValueError("Telemetry quality screening requires explicit lab CIDRs")
    buckets = ("tcp", "udp", "icmp", "other")
    missing_fields = (
        "service", "duration_s", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    )
    partitions: dict[str, dict[str, object]] = {
        split: {
            "captures": 0,
            "flows": 0,
            "protocol_bucket_counts": {key: 0 for key in buckets},
            "missing_optional_feature_counts": {key: 0 for key in missing_fields},
            "out_of_order_timestamp_pairs": 0,
            "warning_capture_counts": {},
        }
        for split in SPLITS
    }
    for capture in captures:
        raw = capture["log_bytes"]
        if not isinstance(raw, bytes):
            raise ValueError("Expected pinned Zeek log bytes")
        quality = inspect_zeek_telemetry_quality(
            raw, expected_sha256=hashlib.sha256(raw).hexdigest(),
            lab_cidrs=lab_cidrs,
        )
        split = capture["split"]
        if split not in partitions:
            raise ValueError("Unexpected capture split")
        part = partitions[split]
        part["captures"] += 1
        part["flows"] += quality["flow_count"]
        part["out_of_order_timestamp_pairs"] += quality["out_of_order_timestamp_pairs"]
        for key in buckets:
            part["protocol_bucket_counts"][key] += quality["protocol_bucket_counts"][key]
        for key in missing_fields:
            part["missing_optional_feature_counts"][key] += quality["missing_optional_feature_counts"][key]
        for warning in quality["warnings"]:
            counts = part["warning_capture_counts"]
            counts[warning] = counts.get(warning, 0) + 1
    return {
        "mode": "offline_pinned_zeek_manifest_quality_only",
        "screened_captures": len(captures),
        "partitions": partitions,
        "declared_cidr_membership_checked": True,
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "independent_ground_truth_verified": False,
        "real_attack_detection_validated": False,
        "live_capture": False,
        "interpretation": (
            "Only descriptive aggregates of already-pinned offline Zeek inputs. "
            "CIDR membership does not establish physical isolation, capture authenticity, "
            "label validity or detection accuracy. No warnings are used to tune the model."
        ),
    }


def load_experiment_manifest(
    manifest_path: str | Path, *, lab_cidrs: Sequence[str] | None = None,
    require_label_sha256: bool = False,
    expected_manifest_sha256: str | None = None,
) -> tuple[list[dict[str, object]], str]:
    """Resolve bounded inputs from one private manifest directory, no network I/O."""
    manifest = Path(manifest_path).resolve(strict=True)
    if not manifest.is_file():
        raise ValueError("Manifest must be a regular file")
    root = manifest.parent
    with manifest.open("rb") as stream:
        manifest_raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(manifest_raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Manifest exceeds size limit")
    manifest_digest = hashlib.sha256(manifest_raw).hexdigest()
    if expected_manifest_sha256 is not None:
        expected = _sha256(expected_manifest_sha256)
        if manifest_digest != expected:
            raise ValueError("Experiment manifest SHA-256 mismatch")
    spec = json.loads(
        manifest_raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
        parse_constant=_invalid_constant,
    )
    if not isinstance(spec, dict) or set(spec) != {"manifest_version", "captures"} or type(spec["manifest_version"]) is not int or spec["manifest_version"] != 1:
        raise ValueError("Unsupported exact experiment manifest v1")
    entries = spec["captures"]
    if not isinstance(entries, list) or not 3 <= len(entries) <= MAX_CAPTURES:
        raise ValueError("Expected 3 to 30 capture entries")
    captures: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) not in (CAPTURE_KEYS, PINNED_CAPTURE_KEYS):
            raise ValueError("Unexpected capture manifest fields")
        if require_label_sha256 and "labels_sha256" not in entry:
            raise ValueError("Strict annotation pinning requires labels_sha256 for every capture")
        log_path = _local_path(root, entry["log_path"])
        label_path = _local_path(root, entry["labels_path"])
        with log_path.open("rb") as stream:
            raw = stream.read(MAX_LOG_BYTES + 1)
        if len(raw) > MAX_LOG_BYTES:
            raise ValueError("Zeek capture exceeds size limit")
        digest = _sha256(entry["source_sha256"])
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("Zeek capture SHA-256 mismatch")
        # Optional, explicit and fail-closed: every capture must fit the same
        # operator-declared private scope before labels/model are consulted.
        # This is NOT a VMware isolation or authorization attestation.
        if lab_cidrs is not None:
            inspect_zeek_lab_scope(raw, lab_cidrs)
        annotation = _read_json(
            label_path, MAX_LABEL_BYTES,
            expected_sha256=_sha256(entry["labels_sha256"])
            if "labels_sha256" in entry else None,
        )
        if not isinstance(annotation, dict) or set(annotation) != {"source_sha256", "labels_by_uid"}:
            raise ValueError("Expected exact annotation v1 fields")
        if _sha256(annotation["source_sha256"]) != digest:
            raise ValueError("Annotation source SHA-256 mismatch")
        captures.append({
            "log_bytes": raw,
            "session_id": entry["session_id"],
            "host_group": entry["host_group"],
            "split": entry["split"],
            "label_method": entry["label_method"],
            "label_reference": entry["label_reference"],
            "labels_by_uid": annotation["labels_by_uid"],
        })
    return captures, manifest_digest



def inspect_offline_experiment(
    manifest_path: str | Path, *, lab_cidrs: Sequence[str] | None = None,
    require_label_sha256: bool = False, require_telemetry_quality: bool = False,
    require_uid_independent_overlap: bool = False,
    expected_manifest_sha256: str | None = None,
) -> dict[str, object]:
    """Validate a private experiment's inputs without fitting or scoring a model.

    This checks file hashes, exact UID annotations, explicit split assignments,
    and host/session separation. It cannot verify labeling truth or isolation.
    Only aggregate counts and the manifest digest are returned, never raw UIDs,
    IPs, host identifiers, paths, or evidence-reference strings.
    """
    if require_telemetry_quality and lab_cidrs is None:
        raise ValueError("Telemetry quality screening requires explicit lab CIDRs")
    captures, manifest_sha256 = load_experiment_manifest(
        manifest_path, lab_cidrs=lab_cidrs, require_label_sha256=require_label_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    dataset = build_labeled_lab_dataset(captures)
    overlap = (
        screen_uid_independent_cross_split_overlap(captures)
        if require_uid_independent_overlap else None
    )
    quality = _summarize_telemetry_quality(captures, lab_cidrs) if require_telemetry_quality else None
    partitions: dict[str, dict[str, int]] = {}
    warnings: list[str] = []
    for split in SPLITS:
        labels = dataset.labels[split]
        provenance = dataset.provenance[split]
        groups = len({row["host_group"] for row in provenance})
        attacks = labels.count(1)
        normals = labels.count(0)
        partitions[split] = {
            "flows": len(labels),
            "normal": normals,
            "attack": attacks,
            "host_groups": groups,
            "sessions": len({row["session_id"] for row in provenance}),
        }
        if len(labels) < 100:
            warnings.append(f"{split}: fewer than 100 labeled flows")
        if groups < 2:
            warnings.append(f"{split}: only one host group; within-split host variability unavailable")
        if min(attacks, normals) < 30:
            warnings.append(f"{split}: fewer than 30 flows in a class")
    return {
        "mode": "offline_zeek_structural_preflight_only",
        "input_manifest_sha256": manifest_sha256,
        **({"manifest_sha256_pin_verified": True} if expected_manifest_sha256 is not None else {}),
        "capture_count": len(captures),
        "partitions": partitions,
        "structural_validation_passed": True,
        "all_annotation_sha256_pins_required": require_label_sha256,
        "annotation_chain_verified": False,
        "declared_scope_screened": lab_cidrs is not None,
        "all_endpoints_within_declared_scope": True if lab_cidrs is not None else None,
        "label_truth_verified": False,
        "host_only_isolation_verified": False,
        "model_fitted": False,
        "test_scored": False,
        "warnings": warnings,
        **({"telemetry_quality": quality} if quality is not None else {}),
        **({"uid_independent_overlap_screen": overlap} if overlap is not None else {}),
        "interpretation": (
            "Input consistency only; operator-provided labels, host groups and "
            "lab isolation are not independently authenticated. Optional declared "
            "CIDR screening is not physical isolation proof. No model or "
            "detection metric was computed."
        ),
    }


def run_offline_experiment(
    manifest_path: str | Path, *, lab_cidrs: Sequence[str] | None = None,
    include_private_test_trace: bool = False,
    require_label_sha256: bool = False, require_telemetry_quality: bool = False,
    require_uid_independent_overlap: bool = False,
    expected_manifest_sha256: str | None = None,
) -> dict[str, object]:
    if require_telemetry_quality and lab_cidrs is None:
        raise ValueError("Telemetry quality screening requires explicit lab CIDRs")
    captures, manifest_sha256 = load_experiment_manifest(
        manifest_path, lab_cidrs=lab_cidrs, require_label_sha256=require_label_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    dataset = build_labeled_lab_dataset(captures)
    overlap = (
        screen_uid_independent_cross_split_overlap(captures)
        if require_uid_independent_overlap else None
    )
    quality = _summarize_telemetry_quality(captures, lab_cidrs) if require_telemetry_quality else None
    report = evaluate_offline_zeek_baseline(
        dataset, include_private_test_trace=include_private_test_trace,
    )
    return {
        **report,
        "input_manifest_sha256": manifest_sha256,
        **({"manifest_sha256_pin_verified": True} if expected_manifest_sha256 is not None else {}),
        "all_annotation_sha256_pins_required": require_label_sha256,
        "annotation_chain_verified": False,
        "declared_scope_screened": lab_cidrs is not None,
        "all_endpoints_within_declared_scope": True if lab_cidrs is not None else None,
        "evaluation_protocol": "operator_assigned_host_disjoint_train_validation_test",
        **({"telemetry_quality": quality} if quality is not None else {}),
        **({"uid_independent_overlap_screen": overlap} if overlap is not None else {}),
        "evidence_warning": "Capture isolation and ground-truth authenticity require independent student verification.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="Private experiment manifest v1 JSON")
    parser.add_argument("--cidr", action="append", default=None,
                        help="Optional strict RFC1918 lab CIDR; repeat 1-4 times to screen ALL captures")
    parser.add_argument("--require-label-sha256", action="store_true",
                        help="Require independently recorded labels_sha256 for EVERY capture before fit")
    parser.add_argument("--require-telemetry-quality", action="store_true",
                        help="Opt in to aggregate quality screening for EVERY capture; requires --cidr")
    parser.add_argument("--require-uid-independent-overlap", action="store_true",
                        help="Refuse cross-split reuse of timestamp/five-tuple even if Zeek UID differs")
    parser.add_argument("--expected-manifest-sha256", type=str,
                        help="Optional independently recorded lowercase SHA-256 of exact manifest bytes; refuse changes before parsing/fitting")
    parser.add_argument("--strict-input-gates", action="store_true",
                        help="Bundle label SHA-256 pinning, per-capture quality and UID-independent split-overlap checks; requires --cidr")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="New aggregate report JSON (must not exist)")
    mode.add_argument("--trace-output", type=Path,
                      help="New PRIVATE held-out test prediction trace JSON (must not exist)")
    mode.add_argument("--preflight", action="store_true", help="Validate inputs and print aggregate counts; no model or file writes")
    args = parser.parse_args(argv)
    # One explicit opt-in avoids accidentally omitting a research-input gate.
    # It does NOT certify capture authenticity, label truth or Host-only isolation.
    require_label_sha256 = args.require_label_sha256 or args.strict_input_gates
    require_telemetry_quality = args.require_telemetry_quality or args.strict_input_gates
    require_uid_independent_overlap = args.require_uid_independent_overlap or args.strict_input_gates
    try:
        manifest = args.manifest.resolve(strict=True)
        if args.preflight:
            print(json.dumps(inspect_offline_experiment(
                manifest, lab_cidrs=args.cidr,
                require_label_sha256=require_label_sha256,
                require_telemetry_quality=require_telemetry_quality,
                require_uid_independent_overlap=require_uid_independent_overlap,
                expected_manifest_sha256=args.expected_manifest_sha256,
            ), indent=2, ensure_ascii=False, allow_nan=False))
            return 0
        output = (args.trace_output or args.output).resolve()
        if not output.is_relative_to(manifest.parent) or output == manifest:
            raise ValueError("Report output must remain inside private manifest directory")
        if args.trace_output is not None and output.is_relative_to(ROOT):
            raise ValueError("Private prediction trace must stay outside the Git repository")
        if output.exists():
            raise FileExistsError("Report already exists; refusing overwrite")
        report = run_offline_experiment(
            manifest, lab_cidrs=args.cidr,
            include_private_test_trace=args.trace_output is not None,
            require_label_sha256=require_label_sha256,
            require_telemetry_quality=require_telemetry_quality,
            require_uid_independent_overlap=require_uid_independent_overlap,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
        payload = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        # Exclusive creation: no partial report is written if validation or fit fails.
        with output.open("x", encoding="utf-8") as stream:
            stream.write(payload)
        print(
            "Private held-out test prediction trace written; no model, alerts or live capture created."
            if args.trace_output is not None else
            "Offline Zeek research report written. No model, alerts or live capture created."
        )
        return 0
    except (ValueError, OSError, UnicodeError, TypeError):
        # Do not print raw filenames, UIDs or annotation content to shared logs.
        print("Offline Zeek experiment refused; inspect private inputs locally.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
