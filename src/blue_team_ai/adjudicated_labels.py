"""Explicitly finalize a private Zeek adjudication worksheet into annotation-v1.

No model predictions, ground-truth inference, network activity or SOC writes.
Agreed labels are copied from both reviewers; disagreements require a manually
entered binary decision and a nonempty private evidence reference.
"""
from __future__ import annotations

import json

from .annotation_agreement import (
    MAX_ANNOTATION_BYTES, _annotations, _bad_constant, _digest, _unique_keys,
)
from .disagreement_review import MAX_WORKSHEET_BYTES, build_private_disagreement_template
from .zeek import MAX_LOG_BYTES, parse_zeek_conn_log


def finalize_private_adjudication(
    source_data: bytes,
    annotation_a_data: bytes,
    annotation_b_data: bytes,
    worksheet_data: bytes,
    *,
    expected_log_sha256: str,
    expected_a_sha256: str,
    expected_b_sha256: str,
    expected_worksheet_sha256: str,
) -> dict[str, object]:
    """Require complete manual decisions, then emit only the annotation-v1 schema.

    The worksheet is checked against an independently reconstructed template.
    This protects reviewer labels and the UID set from worksheet edits, but
    cannot authenticate the underlying evidence or prove labels are true.
    """
    source_sha = _digest(source_data, expected_log_sha256, "Zeek log", MAX_LOG_BYTES)
    _digest(annotation_a_data, expected_a_sha256, "annotation A", MAX_ANNOTATION_BYTES)
    _digest(annotation_b_data, expected_b_sha256, "annotation B", MAX_ANNOTATION_BYTES)
    _digest(worksheet_data, expected_worksheet_sha256, "worksheet", MAX_WORKSHEET_BYTES)

    template = build_private_disagreement_template(
        source_data, annotation_a_data, annotation_b_data,
        expected_log_sha256=expected_log_sha256,
        expected_a_sha256=expected_a_sha256,
        expected_b_sha256=expected_b_sha256,
    )
    try:
        worksheet = json.loads(
            worksheet_data.decode("utf-8"),
            object_pairs_hook=_unique_keys,
            parse_constant=_bad_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid private adjudication JSON") from exc
    if not isinstance(worksheet, dict) or set(worksheet) != set(template):
        raise ValueError("Unexpected private worksheet contract")
    for key, expected in template.items():
        if key == "disagreements_by_uid":
            continue
        value = worksheet[key]
        if type(value) is not type(expected) or value != expected:
            raise ValueError("Worksheet provenance or safety fields were modified")

    decisions = worksheet["disagreements_by_uid"]
    originals = template["disagreements_by_uid"]
    if not isinstance(decisions, dict) or set(decisions) != set(originals):
        raise ValueError("Worksheet disagreement UID coverage changed")
    for uid, original in originals.items():
        decision = decisions[uid]
        if not isinstance(decision, dict) or set(decision) != set(original):
            raise ValueError("Invalid adjudication entry contract")
        for key in ("reviewer_a_label", "reviewer_b_label"):
            if type(decision[key]) is not int or decision[key] != original[key]:
                raise ValueError("Reviewer label in worksheet was modified")
        label = decision["adjudicated_label"]
        if type(label) is not int or label not in (0, 1):
            raise ValueError("Every disagreement requires a manual binary adjudication")
        evidence = decision["evidence_reference"]
        if (
            not isinstance(evidence, str)
            or not 1 <= len(evidence) <= 512
            or evidence != evidence.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in evidence)
        ):
            raise ValueError("Every disagreement requires a private evidence reference")

    events = parse_zeek_conn_log(source_data)
    uids = [event["uid"] for event in events]
    if len(uids) != len(set(uids)):
        raise ValueError("Duplicate Zeek UID")
    expected_uids = set(uids)
    a = _annotations(annotation_a_data, source_sha, expected_uids)
    b = _annotations(annotation_b_data, source_sha, expected_uids)
    labels = {
        uid: a[uid] if a[uid] == b[uid] else decisions[uid]["adjudicated_label"]
        for uid in uids
    }
    return {"source_sha256": source_sha, "labels_by_uid": labels}
