"""Synthetic-only tests for the NEW-log UI declared partition gate.

No VMware, network traffic, verified labels or operational detection evidence.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.new_log_inference import score_new_zeek_log
from blue_team_ai.new_log_workspace import prepare_new_log_review
from evaluate_zeek_lab import load_experiment_manifest
from test_zeek_partition_guard import _inputs

CIDR = ["192.168.56.0/24"]


def _prepared(tmp_path, *, source_data=None):
    manifest, dataset, model, new_log = _inputs(tmp_path)
    # SOC writes require every private annotation to be pinned independently.
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    for capture in spec["captures"]:
        labels = manifest.parent / capture["labels_path"]
        capture["labels_sha256"] = hashlib.sha256(labels.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    model["input_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    model["selected_threshold"] = 0.000001  # synthetic UI fixture only
    model_path = manifest.parent / "ui-model.json"
    model_path.write_text(json.dumps(model, allow_nan=False), encoding="utf-8")
    raw = new_log.read_bytes() if source_data is None else source_data
    model_sha = hashlib.sha256(model_path.read_bytes()).hexdigest()
    log_sha = hashlib.sha256(raw).hexdigest()
    report = score_new_zeek_log(
        raw, model, expected_log_sha256=log_sha,
        lab_cidrs=CIDR, model_sha256=model_sha,
    )
    captures, manifest_sha = load_experiment_manifest(manifest, lab_cidrs=CIDR)
    return dict(
        source_data=raw, report_data=json.dumps(report, allow_nan=False).encode(),
        model_path=model_path, expected_log_sha256=log_sha,
        expected_model_sha256=model_sha, lab_cidrs=CIDR,
        declared_dataset=dataset, declared_manifest_sha256=manifest_sha,
        declared_captures=captures,
    ), manifest


def test_declared_manifest_gate_accepts_only_new_synthetic_capture(tmp_path):
    values, _ = _prepared(tmp_path)
    result = prepare_new_log_review(**values)
    guard = result["declared_partition_check"]
    assert guard["new_capture_not_in_declared_train_validation_test"] is True
    assert guard["declared_flow_identity_nonreuse_checked"] is True
    assert guard["independent_partition_history_verified"] is False
    assert result["candidate_rows"]
    assert result["review"]["soc_cases_created"] is False
    assert not list(tmp_path.rglob("*.sqlite3"))


@pytest.mark.parametrize("missing", [
    "declared_dataset", "declared_manifest_sha256", "declared_captures",
])
def test_partial_partition_evidence_is_rejected(tmp_path, missing):
    values, _ = _prepared(tmp_path)
    values[missing] = None
    with pytest.raises(ValueError, match="requires dataset"):
        prepare_new_log_review(**values)
    assert not list(tmp_path.rglob("*.sqlite3"))


def test_wrong_manifest_digest_rejected_before_display(tmp_path):
    values, _ = _prepared(tmp_path)
    values["declared_manifest_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="different experiment manifest"):
        prepare_new_log_review(**values)


def test_reserved_test_exact_bytes_rejected_before_display(tmp_path):
    values, manifest = _prepared(tmp_path)
    raw = (manifest.parent / "host-2.log").read_bytes()
    values, _ = _prepared(tmp_path, source_data=raw)
    with pytest.raises(ValueError, match="exact-byte reuse"):
        prepare_new_log_review(**values)
    assert not list(tmp_path.rglob("*.sqlite3"))


def test_reserved_test_reencoded_flow_rejected_before_display(tmp_path):
    values, manifest = _prepared(tmp_path)
    original = (manifest.parent / "host-2.log").read_bytes()
    raw = original.replace(b"#fields\t", b"# harmless encoding comment\n#fields\t", 1)
    assert raw != original
    values, _ = _prepared(tmp_path, source_data=raw)
    with pytest.raises(ValueError, match="flow identity overlap"):
        prepare_new_log_review(**values)


def test_streamlit_page_requires_manifest_fields_without_fabricated_success():
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(
        str(ROOT / "pages" / "3_New_Log_Review.py"), default_timeout=45,
    ).run()
    assert not app.exception, [str(item.message) for item in app.exception]
    assert any("Manifest SHA-256" in field.label for field in app.text_input)
    assert any("manifest TRAIN/VALIDATION/TEST" in field.label for field in app.text_input)
    assert not app.success
