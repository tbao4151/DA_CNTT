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
from blue_team_ai.lab_scope import inspect_zeek_lab_scope
from blue_team_ai.offline_baseline import evaluate_offline_zeek_baseline
from blue_team_ai.zeek import MAX_LOG_BYTES

MAX_MANIFEST_BYTES = 256 * 1024
MAX_LABEL_BYTES = 2 * 1024 * 1024
CAPTURE_KEYS = frozenset({
    "log_path", "labels_path", "source_sha256", "session_id", "host_group",
    "split", "label_method", "label_reference",
})


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("Invalid JSON numeric constant")


def _read_json(path: Path, limit: int) -> object:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Input JSON exceeds size limit")
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


def load_experiment_manifest(
    manifest_path: str | Path, *, lab_cidrs: Sequence[str] | None = None,
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
        if not isinstance(entry, dict) or set(entry) != CAPTURE_KEYS:
            raise ValueError("Unexpected capture manifest fields")
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
        annotation = _read_json(label_path, MAX_LABEL_BYTES)
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
) -> dict[str, object]:
    """Validate a private experiment's inputs without fitting or scoring a model.

    This checks file hashes, exact UID annotations, explicit split assignments,
    and host/session separation. It cannot verify labeling truth or isolation.
    Only aggregate counts and the manifest digest are returned, never raw UIDs,
    IPs, host identifiers, paths, or evidence-reference strings.
    """
    captures, manifest_sha256 = load_experiment_manifest(manifest_path, lab_cidrs=lab_cidrs)
    dataset = build_labeled_lab_dataset(captures)
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
        "capture_count": len(captures),
        "partitions": partitions,
        "structural_validation_passed": True,
        "declared_scope_screened": lab_cidrs is not None,
        "all_endpoints_within_declared_scope": True if lab_cidrs is not None else None,
        "label_truth_verified": False,
        "host_only_isolation_verified": False,
        "model_fitted": False,
        "test_scored": False,
        "warnings": warnings,
        "interpretation": (
            "Input consistency only; operator-provided labels, host groups and "
            "lab isolation are not independently authenticated. Optional declared "
            "CIDR screening is not physical isolation proof. No model or "
            "detection metric was computed."
        ),
    }


def run_offline_experiment(
    manifest_path: str | Path, *, lab_cidrs: Sequence[str] | None = None,
) -> dict[str, object]:
    captures, manifest_sha256 = load_experiment_manifest(manifest_path, lab_cidrs=lab_cidrs)
    dataset = build_labeled_lab_dataset(captures)
    report = evaluate_offline_zeek_baseline(dataset)
    return {
        **report,
        "input_manifest_sha256": manifest_sha256,
        "declared_scope_screened": lab_cidrs is not None,
        "all_endpoints_within_declared_scope": True if lab_cidrs is not None else None,
        "evaluation_protocol": "operator_assigned_host_disjoint_train_validation_test",
        "evidence_warning": "Capture isolation and ground-truth authenticity require independent student verification.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="Private experiment manifest v1 JSON")
    parser.add_argument("--cidr", action="append", default=None,
                        help="Optional strict RFC1918 lab CIDR; repeat 1-4 times to screen ALL captures")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="New report JSON (must not exist)")
    mode.add_argument("--preflight", action="store_true", help="Validate inputs and print aggregate counts; no model or file writes")
    args = parser.parse_args(argv)
    try:
        manifest = args.manifest.resolve(strict=True)
        if args.preflight:
            print(json.dumps(inspect_offline_experiment(manifest, lab_cidrs=args.cidr), indent=2, ensure_ascii=False, allow_nan=False))
            return 0
        output = args.output.resolve()
        if not output.is_relative_to(manifest.parent) or output == manifest:
            raise ValueError("Report output must remain inside private manifest directory")
        if output.exists():
            raise FileExistsError("Report already exists; refusing overwrite")
        report = run_offline_experiment(manifest, lab_cidrs=args.cidr)
        payload = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        # Exclusive creation: no partial report is written if validation or fit fails.
        with output.open("x", encoding="utf-8") as stream:
            stream.write(payload)
        print("Offline Zeek research report written. No model, alerts or live capture created.")
        return 0
    except (ValueError, OSError, UnicodeError, TypeError):
        # Do not print raw filenames, UIDs or annotation content to shared logs.
        print("Offline Zeek experiment refused; inspect private inputs locally.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
