"""Manual Zeek triage: synthetic offline fixtures only; no AI or live traffic."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from blue_team_ai.triage import create_offline_review_case
from siem_ai.case_report import export_case_report
from siem_ai.core import case_evidence, case_history, list_cases, update_case


def sample_log():
    return (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "1630000000.25\tC123\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp\n"
        "1630000001.0\tC124\t192.168.56.11\t52345\t192.168.56.21\t53\tudp\n"
    ).encode("utf-8")


def test_manual_review_creates_unclassified_case_with_original_provenance(tmp_path):
    data = sample_log()
    cyber_db = tmp_path / "cyber_lab_cases.sqlite3"
    dataset_db = tmp_path / "soc_cases.sqlite3"
    assert not cyber_db.exists()
    case_id = create_offline_review_case(cyber_db, source_data=data, record_index=1)

    cases = list_cases(cyber_db)
    assert len(cases) == 1
    assert cases.iloc[0]["case_id"] == case_id
    assert cases.iloc[0]["verdict"] == "Unclassified"
    assert cases.iloc[0]["confidence"] is None or str(cases.iloc[0]["confidence"]) == "nan"
    assert cases.iloc[0]["state"] == "New"
    assert not dataset_db.exists()

    evidence = case_evidence(cyber_db, case_id)
    assert evidence["origin"] == "offline_zeek_log"
    assert evidence["source_sha256"] == hashlib.sha256(data).hexdigest()
    assert evidence["uid"] == "C124"
    assert evidence["event_time_utc"] == "2021-08-26T17:46:41+00:00"
    assert evidence["src_ip"] == "192.168.56.11"
    assert not {"AI_verdict", "AI_attack_probability", "label", "attack_cat"} & evidence.keys()

    update_case(cyber_db, case_id, "Investigating", "Analyst manual review")
    history = case_history(cyber_db, case_id)
    assert history["new_state"].tolist() == ["New", "Investigating"]
    report = json.loads(export_case_report(cyber_db, case_id))
    assert report["case"]["verdict"] == "Unclassified"
    assert report["case"]["confidence"] is None
    assert report["flow_evidence"]["source_sha256"] == hashlib.sha256(data).hexdigest()
    assert report["case_events"][-1]["new_state"] == "Investigating"


@pytest.mark.parametrize("index", [-1, 2, True, 0.5, "0"])
def test_invalid_selection_does_not_create_database(tmp_path, index):
    db = tmp_path / "cyber.sqlite3"
    with pytest.raises(ValueError, match="index"):
        create_offline_review_case(db, source_data=sample_log(), record_index=index)
    assert not db.exists()


def test_invalid_log_does_not_create_database(tmp_path):
    db = tmp_path / "cyber.sqlite3"
    with pytest.raises(ValueError, match="separator"):
        create_offline_review_case(db, source_data=b"not a Zeek log", record_index=0)
    assert not db.exists()


def test_duplicate_uid_fails_before_manual_soc_database_write(tmp_path):
    db = tmp_path / "cyber.sqlite3"
    # Two different source rows claiming the same connection UID are ambiguous.
    ambiguous = sample_log().replace(b"\tC124\t", b"\tC123\t", 1)
    with pytest.raises(ValueError, match="Duplicate Zeek UID"):
        create_offline_review_case(db, source_data=ambiguous, record_index=0)
    assert not db.exists()


def test_same_selection_creates_case_only_on_explicit_invocation(tmp_path):
    db = tmp_path / "cyber.sqlite3"
    assert not db.exists()
    first = create_offline_review_case(db, source_data=sample_log(), record_index=0)
    assert len(list_cases(db)) == 1
    second = create_offline_review_case(db, source_data=sample_log(), record_index=0)
    assert second != first
    assert len(list_cases(db)) == 2
