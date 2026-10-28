"""Offline exact-byte partition non-reuse check for a pinned Zeek research model.

Conditional on an operator-supplied experiment manifest; not a guarantee of
independent lab provenance or actual attack detection.
"""
from __future__ import annotations

from collections.abc import Mapping

from .labeled_dataset import LabeledLabDataset, SPLITS
from .model_artifact import validate_zeek_research_artifact

_HEX = frozenset("0123456789abcdef")


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in _HEX for c in value)


def verify_declared_partition_exclusion(
    model: Mapping[str, object], dataset: LabeledLabDataset, *,
    manifest_sha256: str, new_capture_sha256: str,
) -> dict[str, object]:
    """Reject exact-byte reuse across declared TRAIN, VALIDATION and TEST.

    Caller must pin and verify model, manifest and new capture independently,
    then load the original annotated experiment captures using the existing
    bounded manifest loader and labeled-dataset structural validator.
    """
    validate_zeek_research_artifact(model)
    if not _digest(manifest_sha256) or not _digest(new_capture_sha256):
        raise ValueError("Expected independently pinned lowercase SHA-256")
    if model["input_manifest_sha256"] != manifest_sha256:
        raise ValueError("Model was exported from a different experiment manifest")
    if not isinstance(dataset, LabeledLabDataset):
        raise ValueError("Expected structurally validated labeled dataset")
    sources: dict[str, set[str]] = {}
    for split in SPLITS:
        provenance = dataset.provenance[split]
        digests = {row["source_sha256"] for row in provenance}
        if not digests or not all(_digest(d) for d in digests):
            raise ValueError("Missing or invalid source digests in declared split")
        sources[split] = digests
    if (
        sources["train"] & sources["validation"]
        or sources["train"] & sources["test"]
        or sources["validation"] & sources["test"]
    ):
        raise ValueError("Declared source reused across experiment partitions")
    if sources["train"] != set(model["train_source_sha256"]):
        raise ValueError("Model TRAIN sources differ from pinned experiment")
    if sources["validation"] != set(model["validation_source_sha256"]):
        raise ValueError("Model VALIDATION sources differ from pinned experiment")
    if new_capture_sha256 in set.union(*sources.values()):
        raise ValueError("New capture is an exact-byte reuse of an experiment partition")
    return {
        "mode": "offline_zeek_declared_partition_nonreuse_check_only",
        "manifest_sha256": manifest_sha256,
        "new_capture_sha256": new_capture_sha256,
        "model_manifest_digest_matches": True,
        "model_train_validation_sources_match": True,
        "new_capture_not_in_declared_train_validation_test": True,
        "declared_capture_counts": {split: len(sources[split]) for split in SPLITS},
        "independent_partition_history_verified": False,
        "semantic_flow_nonreuse_verified": False,
        "host_only_isolation_verified": False,
        "label_truth_verified": False,
        "model_authorship_verified": False,
        "operational_attack_detection_verified": False,
        "interpretation": (
            "Exact-byte non-reuse against operator-declared pinned experiment "
            "sources only. This cannot prove capture history, flow-level "
            "independence, physical isolation, label truth or detection quality."
        ),
    }
