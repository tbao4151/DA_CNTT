"""Synthetic-only prospective Zeek evaluation; no real VMware attack evidence."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.new_log_evaluation import evaluate_new_log_operator_labels
from blue_team_ai.new_log_inference import score_new_zeek_log
from test_zeek_partition_guard import _inputs

CIDRS = ["192.168.56.0/24"]


@pytest.fixture
def inputs(tmp_path):
    manifest, _, model, new = _inputs(tmp_path)
    private = manifest.parent
    # Match the strict, independently pinned annotation contract of NEW-log
    # scoring and SOC handoff. Synthetic labels are not genuine ground truth.
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    for capture in spec["captures"]:
        label_path = private / capture["labels_path"]
        capture["labels_sha256"] = hashlib.sha256(label_path.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(spec, allow_nan=False), encoding="utf-8")
    model["input_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    raw = new.read_bytes()
    model_bytes = json.dumps(model, allow_nan=False).encode("utf-8")
    model_path = private / "model.json"
    model_path.write_bytes(model_bytes)
    model_sha = hashlib.sha256(model_bytes).hexdigest()
    log_sha = hashlib.sha256(raw).hexdigest()
    report = score_new_zeek_log(
        raw, model, expected_log_sha256=log_sha,
        lab_cidrs=CIDRS, model_sha256=model_sha,
    )
    report_bytes = json.dumps(report, allow_nan=False).encode("utf-8")
    report_path = private / "predictions.json"
    report_path.write_bytes(report_bytes)
    labels = {"source_sha256": log_sha, "labels_by_uid": {
        row["uid"]: index % 2 for index, row in enumerate(report["predictions"])
    }}
    annotation_bytes = json.dumps(labels, allow_nan=False).encode("utf-8")
    annotation_path = private / "new-labels.json"
    annotation_path.write_bytes(annotation_bytes)
    return {
        "manifest": manifest, "model": model, "model_path": model_path,
        "model_sha": model_sha, "new": new, "raw": raw, "log_sha": log_sha,
        "report": report, "report_path": report_path,
        "report_bytes": report_bytes, "annotations": labels,
        "annotation_path": annotation_path, "annotation_bytes": annotation_bytes,
        "annotation_sha": hashlib.sha256(annotation_bytes).hexdigest(),
    }


def _evaluate(i, **changes):
    values = dict(
        source_data=i["raw"], model=i["model"],
        report_data=i["report_bytes"], annotation_data=i["annotation_bytes"],
        expected_log_sha256=i["log_sha"],
        expected_annotation_sha256=i["annotation_sha"],
        model_sha256=i["model_sha"], lab_cidrs=CIDRS,
    )
    values.update(changes)
    return evaluate_new_log_operator_labels(**values)


def test_metrics_are_exactly_from_supplied_labels_not_claimed_truth(inputs):
    result = _evaluate(inputs)
    predictions = inputs["report"]["predictions"]
    labels = inputs["annotations"]["labels_by_uid"]
    tp = sum(row["research_candidate"] and labels[row["uid"]] == 1 for row in predictions)
    fp = sum(row["research_candidate"] and labels[row["uid"]] == 0 for row in predictions)
    tn = sum(not row["research_candidate"] and labels[row["uid"]] == 0 for row in predictions)
    fn = sum(not row["research_candidate"] and labels[row["uid"]] == 1 for row in predictions)
    assert result["confusion_matrix"] == {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "support": len(predictions),
    }
    assert result["metrics"]["attack_recall"] == (tp / (tp + fn) if tp + fn else None)
    assert result["metrics"]["false_positive_rate"] == (fp / (fp + tn) if fp + tn else None)
    assert result["flow_level_uncertainty"]["unit_of_analysis"] == "network_flow"
    ranking = result["threshold_free_ranking_metrics"]
    assert ranking["positive_support"] == sum(labels.values())
    assert ranking["negative_support"] == len(labels) - sum(labels.values())
    assert ranking["positive_prevalence"] == sum(labels.values()) / len(labels)
    assert ranking["threshold_selection_performed"] is False
    assert result["label_authenticity_verified"] is False
    assert result["independent_partition_history_verified"] is False
    assert result["detection_latency_measured"] is False
    assert result["automated_alerts"] is False
    assert "labels_by_uid" not in json.dumps(result)
    assert "NEW1" not in json.dumps(result)


@pytest.mark.parametrize("change", [
    "missing_uid", "extra_uid", "nonbinary", "bool_label", "wrong_source",
    "duplicate_json_key", "nan", "wrong_pin", "tampered_report",
])
def test_fail_closed_on_untrusted_annotation_or_prediction(inputs, change):
    labels = json.loads(inputs["annotation_bytes"])
    report = inputs["report_bytes"]
    if change == "missing_uid":
        labels["labels_by_uid"].pop(next(iter(labels["labels_by_uid"])))
    elif change == "extra_uid":
        labels["labels_by_uid"]["EXTRA"] = 0
    elif change == "nonbinary":
        labels["labels_by_uid"][next(iter(labels["labels_by_uid"]))] = 2
    elif change == "bool_label":
        labels["labels_by_uid"][next(iter(labels["labels_by_uid"]))] = True
    elif change == "wrong_source":
        labels["source_sha256"] = "0" * 64
    if change == "duplicate_json_key":
        data = b'{"source_sha256":"x","source_sha256":"y","labels_by_uid":{}}'
    elif change == "nan":
        data = b'{"source_sha256":NaN,"labels_by_uid":{}}'
    else:
        data = json.dumps(labels, allow_nan=False).encode("utf-8")
    changes = {
        "annotation_data": data,
        "expected_annotation_sha256": hashlib.sha256(data).hexdigest(),
    }
    if change == "wrong_pin":
        changes["expected_annotation_sha256"] = "0" * 64
    if change == "tampered_report":
        modified = json.loads(report)
        modified["predictions"][0]["attack_probability"] = 0.123
        changes["report_data"] = json.dumps(modified).encode()
    with pytest.raises(ValueError):
        _evaluate(inputs, **changes)


def _command(i):
    return [
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_new_log_labels.py"),
        "--model", str(i["model_path"]),
        "--expected-model-sha256", i["model_sha"],
        "--manifest", str(i["manifest"]),
        "--expected-manifest-sha256", hashlib.sha256(i["manifest"].read_bytes()).hexdigest(),
        "--log", str(i["new"]),
        "--expected-log-sha256", i["log_sha"],
        "--report", str(i["report_path"]),
        "--annotations", str(i["annotation_path"]),
        "--expected-annotations-sha256", i["annotation_sha"],
        "--cidr", CIDRS[0],
    ]


def test_cli_evaluates_only_private_pinned_inputs_without_writes(inputs):
    cmd = _command(inputs)
    files = [p for p in inputs["manifest"].parent.iterdir() if p.is_file()]
    before = {p.name: p.read_bytes() for p in files}
    run = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)
    assert result["declared_partition_screen"]["exact_byte_and_normalized_identity_nonreuse"]
    assert result["declared_partition_screen"]["independent_partition_history_verified"] is False
    assert result["confusion_matrix"]["support"] == 2
    assert result["fixed_always_attack_reference"]["confusion_matrix"]["support"] == 2
    assert before == {p.name: p.read_bytes() for p in files}
    assert not (inputs["manifest"].parent / "soc_cases.sqlite3").exists()


def test_cli_refuses_reserved_test_and_mismatched_annotation_pin(inputs):
    cmd = _command(inputs)
    broken = cmd.copy()
    broken[broken.index("--expected-annotations-sha256") + 1] = "0" * 64
    run = subprocess.run(broken, capture_output=True, text=True, check=False)
    assert run.returncode == 1
    assert not run.stdout
    assert str(inputs["new"]) not in run.stderr

    # Reuse exact held-out TEST bytes, with an independently updated log pin.
    test_bytes = (inputs["manifest"].parent / "host-2.log").read_bytes()
    inputs["new"].write_bytes(test_bytes)
    broken = cmd.copy()
    broken[broken.index("--expected-log-sha256") + 1] = hashlib.sha256(test_bytes).hexdigest()
    run = subprocess.run(broken, capture_output=True, text=True, check=False)
    assert run.returncode == 1
    assert not run.stdout
    assert "192.168.56" not in run.stderr



def test_cli_refuses_missing_annotation_pin_even_after_manifest_and_model_repin(inputs):
    spec = json.loads(inputs["manifest"].read_text(encoding="utf-8"))
    del spec["captures"][0]["labels_sha256"]
    inputs["manifest"].write_text(json.dumps(spec), encoding="utf-8")
    # An operator can re-hash both manifest and model. The strict CLI must
    # still refuse an unpinned source annotation before publishing metrics.
    model = json.loads(inputs["model_path"].read_text(encoding="utf-8"))
    model["input_manifest_sha256"] = hashlib.sha256(
        inputs["manifest"].read_bytes()
    ).hexdigest()
    inputs["model_path"].write_text(json.dumps(model), encoding="utf-8")
    cmd = _command(inputs)
    cmd[cmd.index("--expected-model-sha256") + 1] = hashlib.sha256(
        inputs["model_path"].read_bytes()
    ).hexdigest()
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert not result.stdout
    assert str(inputs["manifest"]) not in result.stderr
    assert not list(inputs["manifest"].parent.glob("*.sqlite3"))


def test_cli_refuses_modified_original_split_annotations(inputs):
    spec = json.loads(inputs["manifest"].read_text(encoding="utf-8"))
    path = inputs["manifest"].parent / spec["captures"][1]["labels_path"]
    path.write_bytes(path.read_bytes() + b"\\n")
    result = subprocess.run(
        _command(inputs), capture_output=True, text=True, check=False,
    )
    assert result.returncode == 1
    assert not result.stdout
    assert str(path) not in result.stderr
    assert not list(inputs["manifest"].parent.glob("*.sqlite3"))


def test_predeclared_always_normal_reference_has_no_model_selection(inputs):
    result = _evaluate(inputs)
    observed = result["confusion_matrix"]
    reference = result["fixed_always_normal_reference"]
    assert reference["policy"] == "always_normal_fixed_a_priori"
    assert reference["confusion_matrix"] == {
        "tp": 0, "fp": 0,
        "tn": observed["tn"] + observed["fp"],
        "fn": observed["tp"] + observed["fn"],
        "support": observed["support"],
    }
    assert reference["metrics"]["attack_precision"] is None
    assert reference["metrics"]["attack_recall"] == (
        0.0 if observed["tp"] + observed["fn"] else None
    )
    assert reference["metrics"]["false_positive_rate"] == (
        0.0 if observed["fp"] + observed["tn"] else None
    )
    assert reference["flow_level_uncertainty"]["unit_of_analysis"] == "network_flow"
    assert "labels_by_uid" not in json.dumps(reference)


@pytest.mark.parametrize("label", [0, 1])
def test_always_normal_reference_preserves_undefined_single_class_rates(inputs, label):
    labels = json.loads(inputs["annotation_bytes"])
    labels["labels_by_uid"] = {
        uid: label for uid in labels["labels_by_uid"]
    }
    data = json.dumps(labels, allow_nan=False).encode("utf-8")
    result = _evaluate(
        inputs, annotation_data=data,
        expected_annotation_sha256=hashlib.sha256(data).hexdigest(),
    )
    reference = result["fixed_always_normal_reference"]
    assert reference["confusion_matrix"]["support"] == len(labels["labels_by_uid"])
    assert reference["metrics"]["attack_precision"] is None
    assert reference["metrics"]["attack_recall"] == (None if label == 0 else 0.0)
    assert reference["metrics"]["false_positive_rate"] == (0.0 if label == 0 else None)
    assert reference["metrics"]["attack_f1"] == (None if label == 0 else 0.0)


def test_predeclared_always_attack_reference_counts_and_rates(inputs):
    result = _evaluate(inputs)
    observed = result["confusion_matrix"]
    reference = result["fixed_always_attack_reference"]
    attacks = observed["tp"] + observed["fn"]
    normals = observed["fp"] + observed["tn"]
    support = observed["support"]
    assert reference["policy"] == "always_attack_fixed_a_priori"
    assert reference["confusion_matrix"] == {
        "tp": attacks, "fp": normals, "tn": 0, "fn": 0,
        "support": support,
    }
    assert reference["metrics"] == {
        "attack_precision": attacks / support,
        "attack_recall": 1.0 if attacks else None,
        "false_positive_rate": 1.0 if normals else None,
        "attack_f1": 2 * attacks / (2 * attacks + normals) if attacks else 0.0,
    }
    assert reference["flow_level_uncertainty"]["unit_of_analysis"] == "network_flow"
    assert reference["flow_level_uncertainty"]["attack_precision"]["trials"] == support
    assert "labels_by_uid" not in json.dumps(reference)
    assert "NEW1" not in json.dumps(reference)


@pytest.mark.parametrize("label", [0, 1])
def test_always_attack_reference_preserves_single_class_denominators(inputs, label):
    labels = json.loads(inputs["annotation_bytes"])
    labels["labels_by_uid"] = {uid: label for uid in labels["labels_by_uid"]}
    data = json.dumps(labels, allow_nan=False).encode("utf-8")
    result = _evaluate(
        inputs, annotation_data=data,
        expected_annotation_sha256=hashlib.sha256(data).hexdigest(),
    )
    reference = result["fixed_always_attack_reference"]
    support = len(labels["labels_by_uid"])
    assert reference["confusion_matrix"] == {
        "tp": support if label == 1 else 0,
        "fp": support if label == 0 else 0,
        "tn": 0, "fn": 0, "support": support,
    }
    assert reference["metrics"]["attack_precision"] == float(label)
    assert reference["metrics"]["attack_recall"] == (1.0 if label else None)
    assert reference["metrics"]["false_positive_rate"] == (None if label else 1.0)
    assert reference["metrics"]["attack_f1"] == float(label)
    assert reference["flow_level_uncertainty"]["attack_recall"]["trials"] == (
        support if label else 0
    )
    assert reference["flow_level_uncertainty"]["false_positive_rate"]["trials"] == (
        0 if label else support
    )
