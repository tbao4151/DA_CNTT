"""TRAIN/VALIDATION label-to-host confounding screen for offline Zeek research.

Only operator-supplied labels and host/session declarations are inspected.
Never inspect TEST, model features, raw IP/UID, or fit a classifier.
"""
from __future__ import annotations

from collections.abc import Mapping

from .features import LAB_FEATURE_COLUMNS, LAB_FEATURE_SCHEMA_VERSION
from .labeled_dataset import LabeledLabDataset


def _identifier(value: object) -> bool:
    return (
        isinstance(value, str) and 1 <= len(value) <= 128
        and value.strip() == value
        and all(ord(ch) >= 33 and ord(ch) != 127 for ch in value)
    )



def _dominant_fraction(group_counts: Mapping[str, list[int]], label: int) -> float:
    """Largest share of one class held by any declared group (not independence)."""
    counts = [values[label] for values in group_counts.values()]
    return max(counts) / sum(counts)


def summarize_train_validation_label_group_confounding(
    dataset: LabeledLabDataset,
) -> dict[str, object]:
    """Describe whether operator labels are segregated by declared host/session.

    All results are aggregate counts, never group identifiers or small-group
    confusion cells. No significance test or independent ground truth claim.
    """
    if (
        not isinstance(dataset, LabeledLabDataset)
        or dataset.feature_schema_version != LAB_FEATURE_SCHEMA_VERSION
        or tuple(dataset.feature_columns) != LAB_FEATURE_COLUMNS
        or not isinstance(dataset.labels, Mapping)
        or not isinstance(dataset.provenance, Mapping)
    ):
        raise ValueError("Expected validated Zeek v1 labeled dataset")

    partitions: dict[str, dict[str, object]] = {}
    warnings: list[str] = []
    seen_hosts: dict[str, str] = {}
    seen_sessions: dict[str, tuple[str, str]] = {}
    for split in ("train", "validation"):
        labels = dataset.labels.get(split)
        provenance = dataset.provenance.get(split)
        if (
            not isinstance(labels, (list, tuple))
            or not isinstance(provenance, (list, tuple))
            or not labels or len(labels) != len(provenance)
            or any(type(label) is not int or label not in (0, 1) for label in labels)
            or set(labels) != {0, 1}
        ):
            raise ValueError("TRAIN/VALIDATION labels and provenance must align with both classes")
        host_classes: dict[str, set[int]] = {}
        session_classes: dict[str, set[int]] = {}
        host_sessions: dict[str, set[str]] = {}
        host_label_counts: dict[str, list[int]] = {}
        session_label_counts: dict[str, list[int]] = {}
        for label, meta in zip(labels, provenance):
            if not isinstance(meta, Mapping):
                raise ValueError("Invalid Zeek provenance")
            host = meta.get("host_group")
            session = meta.get("session_id")
            if not _identifier(host) or not _identifier(session):
                raise ValueError("Invalid host/session declaration")
            if host in seen_hosts and seen_hosts[host] != split:
                raise ValueError("Host group reused across TRAIN and VALIDATION")
            if session in seen_sessions and seen_sessions[session] != (split, host):
                raise ValueError("Session reused across host groups or splits")
            seen_hosts[host] = split
            seen_sessions[session] = (split, host)
            host_classes.setdefault(host, set()).add(label)
            session_classes.setdefault(session, set()).add(label)
            host_sessions.setdefault(host, set()).add(session)
            host_label_counts.setdefault(host, [0, 0])[label] += 1
            session_label_counts.setdefault(session, [0, 0])[label] += 1

        host_mixed = sum(classes == {0, 1} for classes in host_classes.values())
        session_mixed = sum(classes == {0, 1} for classes in session_classes.values())
        normal_hosts = sum(0 in classes for classes in host_classes.values())
        attack_hosts = sum(1 in classes for classes in host_classes.values())
        normal_sessions = sum(0 in classes for classes in session_classes.values())
        attack_sessions = sum(1 in classes for classes in session_classes.values())
        host_dominance = {label: _dominant_fraction(host_label_counts, label) for label in (0, 1)}
        session_dominance = {label: _dominant_fraction(session_label_counts, label) for label in (0, 1)}
        partitions[split] = {
            "normal_max_host_flow_share": round(host_dominance[0], 4),
            "attack_max_host_flow_share": round(host_dominance[1], 4),
            "normal_max_session_flow_share": round(session_dominance[0], 4),
            "attack_max_session_flow_share": round(session_dominance[1], 4),
            "host_groups": len(host_classes),
            "sessions": len(session_classes),
            "host_groups_with_both_classes": host_mixed,
            "host_groups_normal_only": sum(classes == {0} for classes in host_classes.values()),
            "host_groups_attack_only": sum(classes == {1} for classes in host_classes.values()),
            "normal_host_group_coverage": normal_hosts,
            "attack_host_group_coverage": attack_hosts,
            "sessions_with_both_classes": session_mixed,
            "sessions_normal_only": sum(classes == {0} for classes in session_classes.values()),
            "sessions_attack_only": sum(classes == {1} for classes in session_classes.values()),
            "labels_fully_separated_by_host_group": host_mixed == 0,
            "labels_fully_separated_by_session": session_mixed == 0,
            "normal_session_coverage": normal_sessions,
            "attack_session_coverage": attack_sessions,
            "host_groups_with_multiple_sessions": sum(
                len(sessions) > 1 for sessions in host_sessions.values()
            ),
        }
        if len(host_classes) < 2:
            warnings.append(f"{split}:only_one_declared_host_group")
        if host_mixed == 0:
            warnings.append(f"{split}:labels_fully_separated_by_host_group")
        if len(session_classes) < 2:
            warnings.append(f"{split}:only_one_declared_session")
        if session_mixed == 0:
            warnings.append(f"{split}:labels_fully_separated_by_session")
        if len(host_classes) > 1 and all(
            len(sessions) == 1 for sessions in host_sessions.values()
        ):
            warnings.append(f"{split}:host_and_session_one_to_one")
        if len(host_classes) > 1 and attack_hosts == 1:
            warnings.append(f"{split}:attack_labels_in_one_host_group")
        if len(host_classes) > 1 and normal_hosts == 1:
            warnings.append(f"{split}:normal_labels_in_one_host_group")
        if len(session_classes) > 1 and attack_sessions == 1:
            warnings.append(f"{split}:attack_labels_in_one_session")
        if len(session_classes) > 1 and normal_sessions == 1:
            warnings.append(f"{split}:normal_labels_in_one_session")
        # Fixed descriptive screen, not a learned cutoff or hypothesis test.
        # Require at least 10 class flows and 2 groups to avoid small-sample
        # noise and redundant one-group warnings. Never consult TEST.
        for scope, groups, fractions in (
            ("host_group", host_label_counts, host_dominance),
            ("session", session_label_counts, session_dominance),
        ):
            if len(groups) > 1:
                for label, name in ((0, "normal"), (1, "attack")):
                    if labels.count(label) >= 10 and fractions[label] >= 0.8:
                        warnings.append(f"{split}:{name}_flows_dominated_by_one_{scope}")

    return {
        "diagnostic_version": 2,
        "mode": "offline_zeek_train_validation_label_group_screen_only",
        "reference_splits": ["train", "validation"],
        "partitions": partitions,
        "test_labels_used_in_diagnostic": False,
        "test_features_used_in_diagnostic": False,
        "feature_values_used": False,
        "model_fitted": False,
        "threshold_selected": False,
        "label_truth_verified": False,
        "host_only_isolation_verified": False,
        "warnings": warnings,
        "interpretation": (
            "Declared host/session-to-label concentration is descriptive only. "
            "Host/session concentration, fixed 80-percent class-flow dominance " 
            "(minimum 10 class flows), and one-to-one nesting can flag possible "
            "scenario confounding but cannot establish causal "
            "leakage, genuine ground truth, host independence or attack detection. "
            "TEST is deliberately excluded; never tune using held-out TEST."
        ),
    }
