"""Synthetic-only regression for explicit Streamlit NEW-log manual SOC write boundary.

No VMware capture, physical isolation, independent label truth or attack
detection is established by these software tests.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.new_log_workspace import prepare_new_log_review
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
    args["db_path"] = ROOT / "runtime" / "do-not-create-ui-case.sqlite3"
    with pytest.raises(ValueError, match="private"):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()
