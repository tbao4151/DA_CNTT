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
