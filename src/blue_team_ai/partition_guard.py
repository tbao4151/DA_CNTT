"""Offline exact-byte partition non-reuse check for a pinned Zeek research model.

Conditional on an operator-supplied experiment manifest; not a guarantee of
independent lab provenance or actual attack detection.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib

from .labeled_dataset import LabeledLabDataset, MAX_CAPTURES, SPLITS
from .flow_identity import flow_identity as _flow_identity
from .zeek import parse_zeek_conn_log
from .model_artifact import validate_zeek_research_artifact

_HEX = frozenset("0123456789abcdef")


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in _HEX for c in value)


def _check_declared_flow_identity_nonreuse(
    declared_captures: Sequence[Mapping[str, object]],
    new_source_data: bytes,
    *,
    new_capture_sha256: str,
    sources: Mapping[str, set[str]],
) -> None:
    """Reject reused normalized UID/time/five-tuple despite changed log bytes.

    Check every original capture against the already validated dataset source
    sets. A changed UID, timestamp, or endpoint can evade this narrow screen.
    """
    if (
        not isinstance(declared_captures, Sequence)
        or isinstance(declared_captures, (str, bytes, bytearray))
        or not 3 <= len(declared_captures) <= MAX_CAPTURES
        or not isinstance(new_source_data, bytes)
        or hashlib.sha256(new_source_data).hexdigest() != new_capture_sha256
    ):
        raise ValueError("Invalid pinned flow identity screening inputs")

    observed: dict[str, set[str]] = {split: set() for split in SPLITS}
    identities: set[tuple[object, ...]] = set()
    for capture in declared_captures:
        if not isinstance(capture, Mapping):
            raise ValueError("Invalid declared flow identity capture")
        split = capture.get("split")
        raw = capture.get("log_bytes")
        if not isinstance(split, str) or split not in SPLITS or not isinstance(raw, bytes):
            raise ValueError("Invalid declared flow identity capture")
        digest = hashlib.sha256(raw).hexdigest()
        if digest not in sources[split] or digest in observed[split]:
            raise ValueError("Declared flow identity source differs from validated dataset")
        observed[split].add(digest)
        for event in parse_zeek_conn_log(raw):
            identity = _flow_identity(event)
            if identity in identities:
                raise ValueError("Flow identity reused across declared captures")
            identities.add(identity)
    if observed != sources:
        raise ValueError("Declared flow identity sources do not cover validated dataset")
    for event in parse_zeek_conn_log(new_source_data):
        if _flow_identity(event) in identities:
            raise ValueError("New capture has a declared flow identity overlap")


def verify_declared_partition_exclusion(
    model: Mapping[str, object], dataset: LabeledLabDataset, *,
    manifest_sha256: str, new_capture_sha256: str,
    declared_captures: Sequence[Mapping[str, object]] | None = None,
    new_source_data: bytes | None = None,
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
    if (declared_captures is None) != (new_source_data is None):
        raise ValueError("Original captures and new bytes must be provided together")
    if declared_captures is not None:
        _check_declared_flow_identity_nonreuse(
            declared_captures, new_source_data,
            new_capture_sha256=new_capture_sha256, sources=sources,
        )
    return {
        "mode": "offline_zeek_declared_partition_nonreuse_check_only",
        "manifest_sha256": manifest_sha256,
        "new_capture_sha256": new_capture_sha256,
        "model_manifest_digest_matches": True,
        "model_train_validation_sources_match": True,
        "new_capture_not_in_declared_train_validation_test": True,
        "declared_capture_counts": {split: len(sources[split]) for split in SPLITS},
        "independent_partition_history_verified": False,
        "declared_flow_identity_nonreuse_checked": declared_captures is not None,
        "semantic_flow_nonreuse_verified": False,
        "host_only_isolation_verified": False,
        "label_truth_verified": False,
        "model_authorship_verified": False,
        "operational_attack_detection_verified": False,
        "interpretation": (
            "Exact-byte non-reuse against operator-declared pinned experiment "
            "sources only. When original bytes are supplied, a conservative "
            "UID/time/five-tuple overlap screen also runs. This cannot prove "
            "capture history, semantic flow independence, physical isolation, "
            "label truth or detection quality."
        ),
    }
