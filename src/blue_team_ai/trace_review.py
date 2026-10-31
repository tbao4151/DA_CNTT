"""Read-only review of a PRIVATE held-out Zeek research prediction trace.

This validates internal consistency and joins one supplied original conn.log to
the trace. It does NOT authenticate model training, label truth or VM isolation,
and must never generate operational alerts or SOC cases.
"""
from __future__ import annotations

import hashlib
import json
import math

from .features import LAB_FEATURE_SCHEMA_VERSION
from .zeek import parse_zeek_conn_log

MAX_PRIVATE_TRACE_BYTES = 16 * 1024 * 1024
_HEX = frozenset("0123456789abcdef")
_FLOW_KEYS = frozenset({
    "source_sha256", "uid", "attack_probability", "predicted_attack",
    "operator_supplied_label", "outcome_against_supplied_label",
})
_OUTCOMES = {
    (True, 1): "true_positive",
    (True, 0): "false_positive",
    (False, 1): "false_negative",
    (False, 0): "true_negative",
}


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate private trace JSON key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("Non-finite private trace JSON value")


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in _HEX for c in value)


def review_private_zeek_trace(source_data: bytes, trace_data: bytes) -> dict[str, object]:
    """Validate a private experiment trace and expose only label-free local rows.

    Every flow in the supplied original log must be represented exactly once.
    A trace can contain other test captures; their source bytes are not checked
    by this function, so no verification claim is made for those captures.
    """
    if not isinstance(trace_data, bytes) or not 0 < len(trace_data) <= MAX_PRIVATE_TRACE_BYTES:
        raise ValueError("Private trace exceeds bounded input size or is not bytes")
    report = json.loads(
        trace_data.decode("utf-8"), object_pairs_hook=_unique_keys,
        parse_constant=_invalid_constant,
    )
    if (not isinstance(report, dict)
            or type(report.get("report_version")) is not int
            or report["report_version"] not in (4, 5, 6)
            or report.get("mode") != "offline_labeled_zeek_research_only"):
        raise ValueError("Unsupported offline Zeek research report")
    if not _digest(report.get("input_manifest_sha256")):
        raise ValueError("Missing private manifest provenance digest")
    if type(report.get("feature_schema_version")) is not int or report["feature_schema_version"] != LAB_FEATURE_SCHEMA_VERSION:
        raise ValueError("Private report feature schema mismatch")
    trace = report.get("private_test_trace")
    if not isinstance(trace, dict) or (
        trace.get("trace_version") != 1
        or trace.get("mode") != "offline_zeek_heldout_test_predictions_only"
        or trace.get("feature_schema_version") != LAB_FEATURE_SCHEMA_VERSION
        or trace.get("label_authenticity") != "operator_supplied_not_verified"
        or trace.get("live_capture") is not False
        or trace.get("automated_alerts") is not False
        or report.get("live_capture") is not False
        or report.get("automated_alerts") is not False
    ):
        raise ValueError("Unsupported or operational private trace")
    threshold = trace.get("selected_threshold")
    if (type(threshold) not in (int, float) or not math.isfinite(threshold)
            or not 0 < threshold < 1 or type(report.get("selected_threshold")) not in (int, float)
            or threshold != report["selected_threshold"]):
        raise ValueError("Private trace threshold mismatch")
    flows = trace.get("flows")
    if not isinstance(flows, list) or not 1 <= len(flows) <= 30_000:
        raise ValueError("Invalid bounded private trace flows")
    metrics = report.get("test_metrics")
    if not isinstance(metrics, dict) or any(
        type(metrics.get(key)) is not int or metrics[key] < 0
        for key in ("tp", "fp", "tn", "fn", "support")
    ) or metrics["support"] != len(flows):
        raise ValueError("Private trace/test report support mismatch")

    # A trace may be internally consistent yet refer to a different held-out
    # capture than the one declared in the experiment's aggregate provenance.
    # Check the full TEST source set and count before exposing any candidates.
    provenance = report.get("provenance")
    test_provenance = provenance.get("test") if isinstance(provenance, dict) else None
    if not isinstance(test_provenance, dict) or set(test_provenance) != {
        "flows", "source_sha256", "host_groups", "sessions",
    }:
        raise ValueError("Missing exact held-out test provenance")
    declared_sources = test_provenance["source_sha256"]
    if (
        type(test_provenance["flows"]) is not int
        or test_provenance["flows"] != len(flows)
        or any(type(test_provenance[key]) is not int or not 1 <= test_provenance[key] <= 30
               for key in ("host_groups", "sessions"))
        or not isinstance(declared_sources, list)
        or not 1 <= len(declared_sources) <= 30
        or any(not _digest(source) for source in declared_sources)
        or declared_sources != sorted(set(declared_sources))
    ):
        raise ValueError("Invalid held-out test provenance")

    seen: set[tuple[str, str]] = set()
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    rows_by_source: dict[str, dict[str, dict[str, object]]] = {}
    for flow in flows:
        if not isinstance(flow, dict) or set(flow) != _FLOW_KEYS:
            raise ValueError("Unexpected private trace flow fields")
        digest, uid = flow["source_sha256"], flow["uid"]
        probability, predicted = flow["attack_probability"], flow["predicted_attack"]
        label = flow["operator_supplied_label"]
        if (not _digest(digest) or not isinstance(uid, str) or not 1 <= len(uid) <= 256
                or type(probability) not in (int, float) or not math.isfinite(probability)
                or not 0 <= probability <= 1 or type(predicted) is not bool
                or predicted != (probability >= threshold)
                or type(label) is not int or label not in (0, 1)
                or flow["outcome_against_supplied_label"] != _OUTCOMES[(predicted, label)]):
            raise ValueError("Invalid or inconsistent private trace prediction")
        key = (digest, uid)
        if key in seen:
            raise ValueError("Duplicate private trace source/UID")
        seen.add(key)
        outcome = flow["outcome_against_supplied_label"]
        counts[{"true_positive": "tp", "false_positive": "fp",
                "true_negative": "tn", "false_negative": "fn"}[outcome]] += 1
        rows_by_source.setdefault(digest, {})[uid] = flow
    if any(counts[key] != metrics[key] for key in counts):
        raise ValueError("Private trace confusion counts mismatch")
    # The research report also exposes derived TEST rates. Recompute these
    # solely from the private trace confusion counts, not from untrusted
    # floating-point fields in the supplied JSON. This is an integrity check,
    # not authentication of the model, source capture or operator labels.
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    expected_rates = {
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
    }
    for name, expected in expected_rates.items():
        observed = metrics.get(name)
        if (type(observed) not in (int, float)
                or not math.isfinite(observed) or not 0 <= observed <= 1
                or not math.isclose(observed, expected, rel_tol=0.0, abs_tol=1e-12)):
            raise ValueError("Private trace/test report rate mismatch")
    if set(rows_by_source) != set(declared_sources):
        raise ValueError("Private trace sources differ from held-out test provenance")

    events = parse_zeek_conn_log(source_data)
    source_digest = hashlib.sha256(source_data).hexdigest()
    matched = rows_by_source.get(source_digest)
    if matched is None:
        raise ValueError("No private trace predictions for the supplied Zeek source")
    uids = [event["uid"] for event in events]
    if len(uids) != len(set(uids)) or set(uids) != set(matched):
        raise ValueError("Private trace UID coverage does not match original Zeek source")
    visible_rows = [
        {
            "record_index": index,
            "uid": uid,
            "attack_probability": float(matched[uid]["attack_probability"]),
            "predicted_attack": matched[uid]["predicted_attack"],
        }
        for index, uid in enumerate(uids)
    ]
    return {
        "mode": "read_only_private_heldout_trace_review",
        "source_sha256": source_digest,
        "selected_threshold": float(threshold),
        "flow_count": len(visible_rows),
        "candidate_count": sum(row["predicted_attack"] for row in visible_rows),
        "rows": visible_rows,
        "source_join_verified": True,
        "other_sources_verified": False,
        "model_provenance_authenticated": False,
        "label_truth_verified": False,
        "live_capture": False,
        "automated_alerts": False,
    }
