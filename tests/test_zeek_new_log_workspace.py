"""Synthetic-only checks for pinned NEW-log Blue Team read-only UI."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.model_artifact import build_zeek_research_artifact
from blue_team_ai.new_log_inference import score_new_zeek_log
from blue_team_ai.new_log_workspace import MAX_UI_ROWS, prepare_new_log_review
from test_zeek_new_log_inference import _log
from test_zeek_offline_baseline import _dataset

CIDRS = ["192.168.56.0/24"]


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    folder = tmp_path_factory.mktemp("private-new-log-ui")
    model = build_zeek_research_artifact(_dataset(), input_manifest_sha256="a" * 64)
    # Synthetic display fixture only; not a scientifically selected threshold.
    model["selected_threshold"] = 0.000001
    model_bytes = json.dumps(model, allow_nan=False).encode()
    model_path = folder / "model.json"
    model_path.write_bytes(model_bytes)
    raw = _log()
    model_sha = hashlib.sha256(model_bytes).hexdigest()
    log_sha = hashlib.sha256(raw).hexdigest()
    report = score_new_zeek_log(
        raw, model, expected_log_sha256=log_sha,
        lab_cidrs=CIDRS, model_sha256=model_sha,
    )
    assert report["research_candidate_count"] > 0
    return dict(
        source_data=raw, report_data=json.dumps(report, allow_nan=False).encode(),
        model_path=model_path, expected_log_sha256=log_sha,
        expected_model_sha256=model_sha, lab_cidrs=CIDRS,
    )


def test_read_only_verified_candidates_match_recomputed_report(sample):
    result = prepare_new_log_review(**sample)
    assert result["review"]["report_matches_recomputed_predictions"] is True
    assert result["review"]["soc_cases_created"] is False
    assert result["review"]["operational_attack_detection_verified"] is False
    assert result["visible_flow_count"] <= MAX_UI_ROWS
    assert result["candidate_rows"]
    assert all("label" not in row for row in result["candidate_rows"])
    assert all(1 <= row["Zeek row"] <= MAX_UI_ROWS for row in result["candidate_rows"])
    assert all(
        left["P(Attack) research"] >= right["P(Attack) research"]
        for left, right in zip(result["candidate_rows"], result["candidate_rows"][1:])
    )


@pytest.mark.parametrize("change", ["model_hash", "log_hash", "report", "scope"])
def test_fail_closed_before_any_soc_write(tmp_path, sample, change):
    values = dict(sample)
    if change == "model_hash":
        values["expected_model_sha256"] = "0" * 64
    elif change == "log_hash":
        values["expected_log_sha256"] = "0" * 64
    elif change == "report":
        report = json.loads(values["report_data"])
        report["predictions"][0]["attack_probability"] = 0.0
        values["report_data"] = json.dumps(report).encode()
    else:
        values["lab_cidrs"] = ["10.0.0.0/8"]
    with pytest.raises(ValueError):
        prepare_new_log_review(**values)
    assert not list(tmp_path.glob("*.sqlite3"))


def test_streamlit_new_log_page_starts_without_fabricated_predictions():
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(
        str(ROOT / "pages" / "3_New_Log_Review.py"), default_timeout=45,
    ).run()
    assert not app.exception, [str(item.message) for item in app.exception]
    assert any("NEW-log" in title.value for title in app.title)
    assert not app.success
