"""Synthetic-only Zeek JSON research artifact tests; NOT genuine detection evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.model_artifact import (
    build_zeek_research_artifact, score_zeek_research_rows,
    validate_zeek_research_artifact,
)
from blue_team_ai.offline_baseline import (
    THRESHOLDS, _frame, _scores, make_zeek_research_pipeline,
)
from test_zeek_offline_baseline import _dataset
from test_zeek_lab_cli import _lab_files

DIGEST = "a" * 64


def test_data_only_export_matches_actual_sklearn_predictions():
    dataset = _dataset()
    artifact = build_zeek_research_artifact(dataset, input_manifest_sha256=DIGEST)
    assert artifact["test_scored"] is False
    assert artifact["executable_serialization"] is False
    assert artifact["automated_alerts"] is False
    assert artifact["feature_schema_version"] == 1
    assert artifact["feature_columns"] == list(dataset.feature_columns)
    assert artifact["train_source_sha256"] != artifact["validation_source_sha256"]
    assert "test_metrics" not in artifact
    assert "test_source_sha256" not in artifact
    assert "operator-note-" not in json.dumps(artifact)
    assert "192.168.56." not in json.dumps(artifact)
    assert "N0" not in json.dumps(artifact)

    reference = make_zeek_research_pipeline()
    reference.fit(_frame(dataset.features["train"]), dataset.labels["train"])
    validation = reference.predict_proba(_frame(dataset.features["validation"]))[:, 1]
    candidates = {
        t: _scores(dataset.labels["validation"], validation, t)
        for t in THRESHOLDS
    }
    selected = max(THRESHOLDS, key=lambda t: (candidates[t]["f1"], -candidates[t]["fp"], t))
    assert artifact["selected_threshold"] == selected

    for split in ("train", "validation", "test"):
        expected = reference.predict_proba(_frame(dataset.features[split]))[:, 1]
        actual = score_zeek_research_rows(artifact, dataset.features[split])
        for row, probability in zip(actual, expected, strict=True):
            assert row["attack_probability"] == pytest.approx(float(probability), abs=1e-12)
            assert row["predicted_attack"] == (probability >= selected)

    # JSON round-trip contains data, not executable Python object serialization.
    restored = json.loads(json.dumps(artifact, allow_nan=False))
    assert score_zeek_research_rows(restored, dataset.features["test"]) == (
        score_zeek_research_rows(artifact, dataset.features["test"])
    )


def test_unknown_categories_missing_measurements_and_test_labels_do_not_change_fit():
    dataset = _dataset()
    artifact = build_zeek_research_artifact(dataset, input_manifest_sha256=DIGEST)
    changed = copy.deepcopy(dataset)
    changed.labels["test"] = [1, 0]
    changed.features["test"][0]["proto"] = "new_protocol"
    changed.features["test"][0]["service"] = "never_seen"
    changed.features["test"][0]["duration_s"] = None
    assert build_zeek_research_artifact(changed, input_manifest_sha256=DIGEST) == artifact
    reference = make_zeek_research_pipeline()
    reference.fit(_frame(dataset.features["train"]), dataset.labels["train"])
    expected = reference.predict_proba(_frame(changed.features["test"]))[:, 1]
    scored = score_zeek_research_rows(artifact, changed.features["test"])
    for item, probability in zip(scored, expected, strict=True):
        assert item["attack_probability"] == pytest.approx(float(probability), abs=1e-12)


@pytest.mark.parametrize("mutation", [
    lambda a: a.update(selected_threshold=True),
    lambda a: a.update(intercept=float("nan")),
    lambda a: a.update(test_scored=True),
    lambda a: a.update(executable_serialization=True),
    lambda a: a.update(feature_schema_version=999),
    lambda a: a.update(input_manifest_sha256="x"),
    lambda a: a["numeric_parameters"]["src_port"].update(scale=0),
    lambda a: a["categorical_adjustments"]["proto"].update(tcp=float("inf")),
    lambda a: a.update(extra_pickle_payload="unsafe"),
    lambda a: a.update(validation_source_sha256=a["train_source_sha256"]),
])
def test_tampered_artifact_rejected(mutation):
    artifact = build_zeek_research_artifact(_dataset(), input_manifest_sha256=DIGEST)
    mutation(artifact)
    with pytest.raises(ValueError):
        validate_zeek_research_artifact(artifact)


def test_score_refuses_label_ip_uid_and_invalid_numeric_values():
    dataset = _dataset()
    artifact = build_zeek_research_artifact(dataset, input_manifest_sha256=DIGEST)
    row = dict(dataset.features["test"][0])
    for key, value in (("label", 1), ("uid", "sensitive"), ("src_ip", "192.168.56.1")):
        modified = {**row, key: value}
        with pytest.raises(ValueError):
            score_zeek_research_rows(artifact, [modified])
    for value in (float("nan"), -1, True, 1e13):
        modified = {**row, "src_port": value}
        with pytest.raises(ValueError):
            score_zeek_research_rows(artifact, [modified])


def test_export_cli_is_private_scope_checked_exclusive_and_never_scores_test(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    output = manifest.parent / "zeek-model.json"
    command = [
        sys.executable, str(ROOT / "scripts" / "export_zeek_model.py"),
        "--manifest", str(manifest), "--output", str(output),
        "--cidr", "192.168.56.0/24",
    ]
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    artifact = json.loads(output.read_text(encoding="utf-8"))
    validate_zeek_research_artifact(artifact)
    assert artifact["input_manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert artifact["test_scored"] is False
    assert artifact["live_capture"] is False
    assert artifact["automated_alerts"] is False
    assert "artifact_sha256=" + hashlib.sha256(output.read_bytes()).hexdigest() in proc.stdout
    for private in ("192.168.56.", "N2", "A2", "private-operator-note"):
        assert private not in output.read_text(encoding="utf-8")
    assert subprocess.run(command, capture_output=True).returncode == 1
    assert artifact == json.loads(output.read_text(encoding="utf-8"))

    blocked = manifest.parent / "blocked.json"
    wrong_scope = command[:-1] + ["10.42.0.0/16"]
    wrong_scope[wrong_scope.index(str(output))] = str(blocked)
    assert subprocess.run(wrong_scope, capture_output=True).returncode == 1
    assert not blocked.exists()
    outside = tmp_path / "outside.json"
    wrong_path = command.copy()
    wrong_path[wrong_path.index(str(output))] = str(outside)
    assert subprocess.run(wrong_path, capture_output=True).returncode == 1
    assert not outside.exists()
