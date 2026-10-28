"""Synthetic-only optional pinned PCAP provenance tests for the Blue Team UI.

The Zeek import fixture mocks the Zeek executable. These tests do not prove
physical VMware isolation, PCAP authenticity, attack labels or detection.
"""
from __future__ import annotations

import hashlib

import pytest

from test_offline_pcap_verify import imported  # noqa: F401 - pytest fixture
from test_zeek_new_log_ui_soc import _ui_args
from blue_team_ai.new_log_workspace import prepare_new_log_review
from siem_ai.core import list_cases
from triage_zeek_new_log import create_ui_candidate_case


def _pinned_ui_args(tmp_path, imported):
    source = imported["log"].read_bytes()
    args = _ui_args(tmp_path, source_data=source)
    args.update(
        offline_import_report_path=imported["report"],
        offline_import_report_sha256=imported["pin"],
        offline_import_pcap_path=imported["pcap"],
    )
    return args


def test_ui_pinned_pcap_creates_one_unclassified_case(imported, tmp_path):
    args = _pinned_ui_args(tmp_path, imported)
    case_id = create_ui_candidate_case(**args)
    assert create_ui_candidate_case(**args) == case_id
    cases = list_cases(args["db_path"])
    assert len(cases) == 1
    assert cases.iloc[0]["verdict"] == "Unclassified"
    note = cases.iloc[0]["analyst_note"]
    assert "Pinned original PCAP/import report/Zeek byte integrity" in note
    assert imported["pin"] in note
    assert hashlib.sha256(imported["pcap"].read_bytes()).hexdigest() in note


def test_ui_pcap_changed_after_candidate_preview_blocks_write(imported, tmp_path):
    args = _pinned_ui_args(tmp_path, imported)
    # Preview can succeed on verified model/log/manifest while original PCAP
    # is still intact. Write must independently recheck the original bytes.
    from test_zeek_new_log_ui_partition import _prepared
    values, _ = _prepared(tmp_path / "preview", source_data=imported["log"].read_bytes())
    assert prepare_new_log_review(**values)["candidate_rows"]
    imported["pcap"].write_bytes(imported["pcap"].read_bytes() + b"changed")
    with pytest.raises(ValueError):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()


@pytest.mark.parametrize("missing", [
    "offline_import_report_path", "offline_import_report_sha256",
    "offline_import_pcap_path",
])
def test_ui_partial_pcap_fields_refused_before_sqlite(imported, tmp_path, missing):
    args = _pinned_ui_args(tmp_path, imported)
    args[missing] = None
    with pytest.raises(ValueError, match="All three"):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()


def test_ui_wrong_import_pin_refused_before_sqlite(imported, tmp_path):
    args = _pinned_ui_args(tmp_path, imported)
    args["offline_import_report_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="SHA-256"):
        create_ui_candidate_case(**args)
    assert not args["db_path"].exists()


def test_ui_legacy_mode_is_explicitly_unverified(tmp_path):
    args = _ui_args(tmp_path)
    create_ui_candidate_case(**args)
    note = list_cases(args["db_path"]).iloc[0]["analyst_note"]
    assert "Original PCAP provenance NOT software-checked" in note


def test_streamlit_page_exposes_optional_pcap_fields_without_false_success():
    from pathlib import Path
    from streamlit.testing.v1 import AppTest
    root = Path(__file__).resolve().parents[1]
    app = AppTest.from_file(
        str(root / "pages" / "3_New_Log_Review.py"), default_timeout=45,
    ).run()
    assert not app.exception, [str(item.message) for item in app.exception]
    labels = [field.label for field in app.text_input]
    assert any("offline_import_report.json" in label for label in labels)
    assert any("SHA-256 báo cáo import" in label for label in labels)
    assert any("PCAP gốc" in label for label in labels)
    assert not app.success
