"""Offline, independently labeled Zeek dataset contract for future Blue Team AI.

The caller supplies raw Zeek bytes and external per-UID labels, plus an explicit
capture/session/host split. No model inference, training, attack generation or
network I/O occurs. A claimed label reference is metadata, not proof of truth.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .features import LAB_FEATURE_COLUMNS, LAB_FEATURE_SCHEMA_VERSION, extract_zeek_feature_rows
from .zeek import parse_zeek_conn_log

SPLITS = ("train", "validation", "test")
LABEL_METHODS = frozenset({"controlled_scenario_record", "manual_analyst_review"})
MAX_CAPTURES = 30
MAX_TOTAL_FLOWS = 30_000
_CAPTURE_FIELDS = frozenset({
    "log_bytes", "session_id", "host_group", "split", "label_method",
    "label_reference", "labels_by_uid",
})


@dataclass(frozen=True)
class LabeledLabDataset:
    """Separate feature matrices, binary labels and audit metadata per split."""

    feature_schema_version: int
    feature_columns: tuple[str, ...]
    features: dict[str, list[dict[str, object]]]
    labels: dict[str, list[int]]
    provenance: dict[str, list[dict[str, str]]]


def _identifier(value: object, field: str) -> str:
    if (
        not isinstance(value, str) or not 1 <= len(value) <= 128
        or value.strip() != value
        or any(ord(ch) < 33 or ord(ch) == 127 for ch in value)
    ):
        raise ValueError(f"Invalid {field}")
    return value


def build_labeled_lab_dataset(captures: Sequence[Mapping[str, object]]) -> LabeledLabDataset:
    """Validate external labels and explicit session/host-disjoint partitions.

    Every UID in each raw Zeek file must have exactly one external binary label.
    All three partitions must contain both classes; host groups cannot appear
    in multiple partitions. This is a fail-closed research input contract, NOT
    authentication of lab captures, annotators or independent ground truth.
    """
    if (
        not isinstance(captures, Sequence)
        or isinstance(captures, (str, bytes, bytearray))
        or not 3 <= len(captures) <= MAX_CAPTURES
    ):
        raise ValueError("Expected 3 to 30 explicitly partitioned lab captures")

    features: dict[str, list[dict[str, object]]] = {split: [] for split in SPLITS}
    labels: dict[str, list[int]] = {split: [] for split in SPLITS}
    provenance: dict[str, list[dict[str, str]]] = {split: [] for split in SPLITS}
    seen_sessions: set[str] = set()
    seen_digests: set[str] = set()
    host_splits: dict[str, str] = {}
    total_flows = 0

    for capture in captures:
        if not isinstance(capture, Mapping) or set(capture) != _CAPTURE_FIELDS:
            raise ValueError("Expected exact lab capture contract fields")
        session = _identifier(capture["session_id"], "session_id")
        host = _identifier(capture["host_group"], "host_group")
        split = capture["split"]
        method = capture["label_method"]
        reference = _identifier(capture["label_reference"], "label_reference")
        if not isinstance(split, str) or split not in SPLITS:
            raise ValueError("Invalid explicit split")
        if not isinstance(method, str) or method not in LABEL_METHODS:
            raise ValueError("Invalid external label method")
        if session in seen_sessions:
            raise ValueError("Duplicate session_id")
        if host in host_splits and host_splits[host] != split:
            raise ValueError("Host group leaked across splits")
        raw = capture["log_bytes"]
        if not isinstance(raw, bytes):
            raise ValueError("Expected raw Zeek bytes")
        events = parse_zeek_conn_log(raw)
        digest = events[0]["source_sha256"]
        if digest in seen_digests:
            raise ValueError("Identical source log reused across captures")
        uids = [event["uid"] for event in events]
        if len(uids) != len(set(uids)):
            raise ValueError("Duplicate Zeek UID within capture")
        supplied = capture["labels_by_uid"]
        if (
            not isinstance(supplied, Mapping)
            or set(supplied) != set(uids)
            or any(type(label) is not int or label not in (0, 1) for label in supplied.values())
        ):
            raise ValueError("External labels must exactly match UIDs and be binary integers")
        projected = extract_zeek_feature_rows(events)
        total_flows += len(projected)
        if total_flows > MAX_TOTAL_FLOWS:
            raise ValueError("Lab dataset exceeds total flow limit")
        features[split].extend(projected)
        labels[split].extend(supplied[uid] for uid in uids)
        provenance[split].extend({
            "source_sha256": digest,
            "session_id": session,
            "host_group": host,
            "uid": uid,
            "label_method": method,
            "label_reference": reference,
        } for uid in uids)
        seen_sessions.add(session)
        seen_digests.add(digest)
        host_splits[host] = split

    for split in SPLITS:
        if set(labels[split]) != {0, 1}:
            raise ValueError(f"Split {split} must contain independently labeled Normal and Attack")
    return LabeledLabDataset(
        feature_schema_version=LAB_FEATURE_SCHEMA_VERSION,
        feature_columns=LAB_FEATURE_COLUMNS,
        features=features, labels=labels, provenance=provenance,
    )
