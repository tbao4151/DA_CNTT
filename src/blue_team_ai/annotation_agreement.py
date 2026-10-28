"""Offline agreement audit for two separately prepared Zeek UID annotations.

Agreement is a quality diagnostic, not independent proof of attack ground truth,
annotator independence, Host-only isolation or model accuracy. No network, model
or SOC operations are performed.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from .zeek import MAX_LOG_BYTES, parse_zeek_conn_log

MAX_ANNOTATION_BYTES = 2 * 1024 * 1024


def _digest(raw: bytes, expected: str, name: str, limit: int) -> str:
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise ValueError(f"Invalid or oversized {name}")
    if (
        not isinstance(expected, str) or len(expected) != 64
        or any(c not in "0123456789abcdef" for c in expected)
    ):
        raise ValueError(f"Expected independently pinned lowercase SHA-256 for {name}")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise ValueError(f"Original {name} differs from pinned SHA-256")
    return actual


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate annotation JSON key")
        result[key] = value
    return result


def _bad_constant(_value: str) -> None:
    raise ValueError("Non-finite JSON constant is forbidden")


def _annotations(raw: bytes, source_sha: str, expected_uids: set[str]) -> dict[str, int]:
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_keys,
            parse_constant=_bad_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid annotation JSON") from exc
    if not isinstance(document, dict) or set(document) != {"source_sha256", "labels_by_uid"}:
        raise ValueError("Expected exact annotation v1 contract")
    if document["source_sha256"] != source_sha:
        raise ValueError("Annotation source SHA-256 differs from original log")
    labels = document["labels_by_uid"]
    if not isinstance(labels, Mapping) or set(labels) != expected_uids:
        raise ValueError("Annotation UID coverage differs from original log")
    if any(type(value) is not int or value not in (0, 1) for value in labels.values()):
        raise ValueError("Annotation labels must be independently assigned binary integers")
    return labels


def review_zeek_annotator_agreement(
    source_data: bytes,
    annotation_a_data: bytes,
    annotation_b_data: bytes,
    *,
    expected_log_sha256: str,
    expected_a_sha256: str,
    expected_b_sha256: str,
) -> dict[str, object]:
    """Compare complete UID-aligned independent inputs without exporting any UID.

    Cohen's kappa is undefined when expected chance agreement equals one.
    No consensus labels are generated, even when annotators disagree.
    """
    source_sha = _digest(source_data, expected_log_sha256, "Zeek log", MAX_LOG_BYTES)
    a_sha = _digest(annotation_a_data, expected_a_sha256, "annotation A", MAX_ANNOTATION_BYTES)
    b_sha = _digest(annotation_b_data, expected_b_sha256, "annotation B", MAX_ANNOTATION_BYTES)
    events = parse_zeek_conn_log(source_data)
    uids = [row["uid"] for row in events]
    if len(uids) != len(set(uids)):
        raise ValueError("Duplicate Zeek UID in source log")
    expected = set(uids)
    a = _annotations(annotation_a_data, source_sha, expected)
    b = _annotations(annotation_b_data, source_sha, expected)

    counts = {(x, y): 0 for x in (0, 1) for y in (0, 1)}
    for uid in uids:
        counts[(a[uid], b[uid])] += 1
    total = len(uids)
    agreed = counts[(0, 0)] + counts[(1, 1)]
    observed = agreed / total
    a_attack = counts[(1, 0)] + counts[(1, 1)]
    b_attack = counts[(0, 1)] + counts[(1, 1)]
    pa = a_attack / total
    pb = b_attack / total
    chance = pa * pb + (1 - pa) * (1 - pb)
    kappa = None if chance == 1 else (observed - chance) / (1 - chance)
    return {
        "report_version": 1,
        "mode": "offline_two_annotator_agreement_only",
        "source_sha256": source_sha,
        "annotation_a_sha256": a_sha,
        "annotation_b_sha256": b_sha,
        "flow_count": total,
        "agreement_count": agreed,
        "disagreement_count": total - agreed,
        "observed_agreement": observed,
        "chance_agreement": chance,
        "cohen_kappa": kappa,
        "a_attack_count": a_attack,
        "b_attack_count": b_attack,
        "counts": {
            "a0_b0": counts[(0, 0)], "a0_b1": counts[(0, 1)],
            "a1_b0": counts[(1, 0)], "a1_b1": counts[(1, 1)],
        },
        "ground_truth_verified": False,
        "annotator_independence_verified": False,
        "host_only_isolation_verified": False,
        "consensus_labels_generated": False,
        "interpretation": (
            "Descriptive agreement on operator-supplied labels only. "
            "Kappa is undefined when chance agreement is one. "
            "Investigate disagreements using independent scenario evidence; "
            "do not infer or silently overwrite ground truth."
        ),
    }
