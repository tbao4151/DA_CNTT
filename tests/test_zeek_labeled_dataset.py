"""Synthetic-only regression tests: labels are supplied, never inferred."""
import copy
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from blue_team_ai.labeled_dataset import build_labeled_lab_dataset


def capture(split, suffix):
    raw = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
        "\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
        f"1630000000.25\tN{suffix}\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp"
        "\t-\t1.25\t100\t-\t2\t-\n"
        f"1630000001.0\tA{suffix}\t192.168.56.11\t52345\t192.168.56.21\t53\tudp"
        "\tdns\t-\t0\t25\t-\t1\n"
    ).encode("utf-8")
    return {
        "log_bytes": raw, "session_id": f"session-{suffix}",
        "host_group": f"host-{split}", "split": split,
        "label_method": "controlled_scenario_record",
        "label_reference": f"operator-evidence-{suffix}",
        "labels_by_uid": {f"N{suffix}": 0, f"A{suffix}": 1},
    }


def samples():
    return [capture(split, i) for i, split in enumerate(("train", "validation", "test"))]


def test_contract_preserves_order_features_and_separate_ground_truth():
    source = samples()
    before = copy.deepcopy(source)
    result = build_labeled_lab_dataset(source)
    assert source == before
    assert result.feature_schema_version == 1
    assert len(result.feature_columns) == 9
    assert result.labels == {s: [0, 1] for s in ("train", "validation", "test")}
    assert result.features["train"][0]["duration_s"] == 1.25
    assert result.features["train"][1]["duration_s"] is None
    assert result.features["train"][1]["orig_bytes"] == 0
    for split in ("train", "validation", "test"):
        for row in result.features[split]:
            assert "label" not in row and "uid" not in row and "src_ip" not in row
        assert result.provenance[split][0]["source_sha256"] == hashlib.sha256(
            next(x["log_bytes"] for x in source if x["split"] == split)
        ).hexdigest()


@pytest.mark.parametrize("mutate,match", [
    (lambda c: c[0].update(labels_by_uid={"N0": 0}), "exactly match"),
    (lambda c: c[0]["labels_by_uid"].update(A0=True), "binary integers"),
    (lambda c: c[0]["labels_by_uid"].update(A0=2), "binary integers"),
    (lambda c: c[0]["labels_by_uid"].update(A0="Attack"), "binary integers"),
    (lambda c: c[0].update(split="evaluation"), "Invalid explicit split"),
    (lambda c: c[0].update(label_method="model_prediction"), "Invalid external label method"),
    (lambda c: c[0].update(label_reference=""), "Invalid label_reference"),
    (lambda c: c[0].update(session_id="bad session"), "Invalid session_id"),
    (lambda c: c[1].update(session_id=c[0]["session_id"]), "Duplicate session_id"),
    (lambda c: c[1].update(host_group=c[0]["host_group"]), "Host group leaked"),
    (lambda c: c[1].update(log_bytes=c[0]["log_bytes"]), "Identical source"),
    (lambda c: c[0].update(log_bytes="not bytes"), "raw Zeek bytes"),
    (lambda c: c[0].update(attack_cat="x"), "exact lab capture"),
    (lambda c: c[0]["labels_by_uid"].update(N0=1), "Normal and Attack"),
])
def test_rejects_leakage_invalid_labels_and_untrusted_metadata(mutate, match):
    rows = samples()
    mutate(rows)
    with pytest.raises(ValueError, match=match):
        build_labeled_lab_dataset(rows)


def test_rejects_duplicate_uid_within_one_log():
    rows = samples()
    rows[0]["log_bytes"] = rows[0]["log_bytes"].replace(b"A0\t", b"N0\t")
    with pytest.raises(ValueError, match="Duplicate Zeek UID"):
        build_labeled_lab_dataset(rows)


def test_rejects_missing_partition_and_non_sequence():
    with pytest.raises(ValueError, match="3 to 30"):
        build_labeled_lab_dataset(samples()[:2])
    with pytest.raises(ValueError, match="3 to 30"):
        build_labeled_lab_dataset("not captures")
    rows = samples() + [capture("train", 99)]
    rows[2]["split"] = "train"
    with pytest.raises(ValueError, match="Split test"):
        build_labeled_lab_dataset(rows)


def test_reencoded_flow_reuse_across_splits_is_rejected_before_training():
    rows = samples()
    original = rows[0]
    # Re-encoding changes file SHA-256, not the normalized UID/time/5-tuple.
    rows[2]["log_bytes"] = original["log_bytes"].replace(
        b"#fields\\t", b"# innocuous header comment\\n#fields\\t", 1
    )
    rows[2]["labels_by_uid"] = original["labels_by_uid"].copy()
    assert hashlib.sha256(rows[2]["log_bytes"]).hexdigest() != hashlib.sha256(
        original["log_bytes"]
    ).hexdigest()
    with pytest.raises(ValueError, match="Normalized Zeek flow identity reused"):
        build_labeled_lab_dataset(rows)


def test_reencoded_flow_reuse_within_one_split_is_also_rejected():
    rows = samples()
    duplicate = capture("train", 99)
    duplicate["log_bytes"] = rows[0]["log_bytes"].replace(
        b"#fields\\t", b"# other comment\\n#fields\\t", 1
    )
    duplicate["labels_by_uid"] = rows[0]["labels_by_uid"].copy()
    rows.append(duplicate)
    with pytest.raises(ValueError, match="Normalized Zeek flow identity reused"):
        build_labeled_lab_dataset(rows)


def test_reused_uid_at_distinct_event_times_is_not_a_false_overlap():
    rows = samples()
    raw = rows[0]["log_bytes"]
    rows[2]["log_bytes"] = raw.replace(
        b"1630000000.25", b"1630000010.25"
    ).replace(b"1630000001.0", b"1630000011.0")
    rows[2]["labels_by_uid"] = rows[0]["labels_by_uid"].copy()
    result = build_labeled_lab_dataset(rows)
    assert result.labels["test"] == [0, 1]
    assert len(result.features["test"]) == 2
