"""Synthetic-only regression for explicit Streamlit NEW-log manual SOC write boundary.

No VMware capture, physical isolation, independent label truth or attack
detection is established by these software tests.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.new_log_workspace import prepare_new_log_review
from blue_team_ai.research_alerts import build_verified_research_alert_bundle
from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from evaluate_zeek_lab import load_experiment_manifest
from siem_ai.core import list_cases, case_history
from triage_zeek_new_log import create_ui_candidate_case
from test_zeek_new_log_ui_partition import _prepared


def _ui_args(tmp_path, *, source_data=None):
    values, manifest = _prepared(tmp_path, source_data=source_data)
    review = prepare_new_log_review(**values)
    index = review["candidate_rows"][0]["Zeek row"] - 1
    args = dict(
        db_path=tmp_path / "private-soc.sqlite3",
        model_path=values["model_path"],
        manifest_path=manifest,
        expected_manifest_sha256=values["declared_manifest_sha256"],
        source_data=values["source_data"],
        report_data=values["report_data"],
        expected_log_sha256=values["expected_log_sha256"],
        expected_model_sha256=values["expected_model_sha256"],
        lab_cidrs=values["lab_cidrs"],
        record_index=index,
        analyst_confirmed=True,
        operator_confirmed_authorized=True,
        operator_confirmed_new_capture=True,
    )
    return args


def test_explicit_ui_case_reuses_existing_unclassified_case(tmp_path):
    args = _ui_args(tmp_path)
    case_id = create_ui_candidate_case(**args)
    assert create_ui_candidate_case(**args) == case_id
    cases = list_cases(args["db_path"])
    assert len(cases) == 1
    assert cases.iloc[0]["verdict"] == "Unclassified"
    assert cases.iloc[0]["state"] == "New"
    assert len(case_history(args["db_path"], case_id)) == 1
    assert "pinned manifest_sha256=" in cases.iloc[0]["analyst_note"]


@pytest.mark.parametrize("missing", [
    "analyst_confirmed", "operator_confirmed_authorized",
    "operator_confirmed_new_capture",
])
def test_ui_write_requires_all_attestations(tmp_path, missing):
    args = _ui_args(tmp_path)
    args[missing] = False
    with pytest.raises(ValueError, match="attestations"):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()


def test_ui_write_reloads_model_and_manifest_instead_of_trusting_preview(tmp_path):
    first = tmp_path / "first"
    first.mkdir()
    args = _ui_args(first)
    args["model_path"].write_text('{"tampered":true}', encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()

    second = tmp_path / "second"
    second.mkdir()
    args = _ui_args(second)
    args["manifest_path"].write_bytes(args["manifest_path"].read_bytes() + b" ")
    with pytest.raises(ValueError, match="manifest SHA-256"):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()


def test_ui_write_rejects_changed_report_and_bad_log_digest(tmp_path):
    args = _ui_args(tmp_path)
    report = json.loads(args["report_data"])
    report["predictions"][0]["attack_probability"] = 0.0
    args["report_data"] = json.dumps(report).encode("utf-8")
    with pytest.raises(ValueError):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()

    args = _ui_args(tmp_path)
    args["expected_log_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="NEW-log SHA-256"):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()


def test_ui_write_rejects_test_partition_reuse_even_with_new_report(tmp_path):
    args = _ui_args(tmp_path)
    test_bytes = (args["manifest_path"].parent / "host-2.log").read_bytes()
    # A separately re-scored report cannot make a reserved test capture new.
    from blue_team_ai.trusted_model import load_pinned_zeek_research_model
    from blue_team_ai.new_log_inference import score_new_zeek_log
    import hashlib
    model = load_pinned_zeek_research_model(
        args["model_path"], expected_sha256=args["expected_model_sha256"],
    )
    args["source_data"] = test_bytes
    args["expected_log_sha256"] = hashlib.sha256(test_bytes).hexdigest()
    args["report_data"] = json.dumps(score_new_zeek_log(
        test_bytes, model,
        expected_log_sha256=args["expected_log_sha256"],
        lab_cidrs=args["lab_cidrs"],
        model_sha256=args["expected_model_sha256"],
    )).encode("utf-8")
    with pytest.raises(ValueError, match="exact-byte reuse"):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()


def test_ui_write_rejects_database_inside_repository(tmp_path):
    args = _ui_args(tmp_path)
    args["db_path"] = ROOT / "tests" / "do-not-create-ui-case.sqlite3"
    with pytest.raises(ValueError, match="private"):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()

@pytest.mark.parametrize("change", ["annotation_modified", "missing_annotation_pin"])
def test_ui_soc_write_refuses_unpinned_or_changed_annotation(tmp_path, change):
    args = _ui_args(tmp_path)
    manifest = args["manifest_path"]
    if change == "annotation_modified":
        labels = manifest.parent / "host-0-labels.json"
        labels.write_bytes(labels.read_bytes() + b"\n")
    else:
        import hashlib
        spec = json.loads(manifest.read_text(encoding="utf-8"))
        del spec["captures"][0]["labels_sha256"]
        manifest.write_text(json.dumps(spec), encoding="utf-8")
        args["expected_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        model_path = args["model_path"]
        model = json.loads(model_path.read_text(encoding="utf-8"))
        model["input_manifest_sha256"] = args["expected_manifest_sha256"]
        model_path.write_text(json.dumps(model), encoding="utf-8")
        args["expected_model_sha256"] = hashlib.sha256(model_path.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()



def _ui_args_with_pinned_queue(tmp_path):
    args = _ui_args(tmp_path)
    captures, manifest_sha = load_experiment_manifest(
        args["manifest_path"], lab_cidrs=args["lab_cidrs"],
        require_label_sha256=True,
        expected_manifest_sha256=args["expected_manifest_sha256"],
    )
    dataset = build_labeled_lab_dataset(captures)
    model = load_pinned_zeek_research_model(
        args["model_path"], expected_sha256=args["expected_model_sha256"],
    )
    bundle = build_verified_research_alert_bundle(
        args["source_data"], model, args["report_data"],
        expected_log_sha256=args["expected_log_sha256"],
        model_sha256=args["expected_model_sha256"],
        lab_cidrs=args["lab_cidrs"],
        manifest_sha256=manifest_sha,
        declared_dataset=dataset, declared_captures=captures,
    )
    selected = next(
        row for row in bundle["research_alerts"]
        if row["record_index"] == args["record_index"]
    )
    raw = json.dumps(bundle, allow_nan=False).encode("utf-8")
    path = tmp_path / "research-alerts.json"
    path.write_bytes(raw)
    args.update(
        research_alert_bundle_path=path,
        expected_research_alert_bundle_sha256=hashlib.sha256(raw).hexdigest(),
        research_alert_ref=selected["research_alert_ref"],
    )
    return args


def test_ui_pinned_queue_creates_bound_unclassified_case(tmp_path):
    args = _ui_args_with_pinned_queue(tmp_path)
    case_id = create_ui_candidate_case(**args)
    assert create_ui_candidate_case(**args) == case_id
    with sqlite3.connect(args["db_path"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 1
        assert conn.execute("SELECT verdict FROM cases").fetchone()[0] == "Unclassified"
        note = conn.execute(
            "SELECT note FROM case_events ORDER BY event_id LIMIT 1"
        ).fetchone()[0]
    assert "bundle_sha256=" + args["expected_research_alert_bundle_sha256"] in note
    assert "research_alert_ref=" + args["research_alert_ref"] in note


@pytest.mark.parametrize("change", [
    "missing_sha", "wrong_sha", "wrong_ref", "modified_queue",
    "duplicate_queue_path", "database_is_queue",
])
def test_ui_pinned_queue_refuses_invalid_binding_before_soc_write(tmp_path, change):
    args = _ui_args_with_pinned_queue(tmp_path)
    if change == "missing_sha":
        args["expected_research_alert_bundle_sha256"] = None
    elif change == "wrong_sha":
        args["expected_research_alert_bundle_sha256"] = "0" * 64
    elif change == "wrong_ref":
        args["research_alert_ref"] = "0" * 64
    elif change == "modified_queue":
        args["research_alert_bundle_path"].write_bytes(
            args["research_alert_bundle_path"].read_bytes() + b" "
        )
    elif change == "duplicate_queue_path":
        args["research_alert_bundle_path"] = args["model_path"]
    else:
        args["db_path"] = args["research_alert_bundle_path"]
    with pytest.raises(ValueError):
        create_ui_candidate_case(**args)
    if change != "database_is_queue":
        assert not args["db_path"].exists()


def test_ui_page_exposes_optional_pinned_queue_inputs():
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(
        str(ROOT / "pages" / "3_New_Log_Review.py"), default_timeout=45,
    ).run()
    assert not app.exception, [str(item.message) for item in app.exception]
    # The manual form appears only after a fully pinned private review; it is
    # intentionally not exposed on the empty page without verified candidates.
    assert not app.success
