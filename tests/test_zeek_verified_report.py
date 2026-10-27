"""Type-preserving Cyber Lab case exports from synthetic offline Zeek only."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from blue_team_ai.triage import create_offline_review_case
from blue_team_ai.verified_report import export_verified_offline_case


def sample_log(*, uid="C123"):
    return (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
        "\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
        f"1630000000.25\t{uid}\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp"
        "\t-\t1.25\t100\t-\t2\t-\n"
        "1630000001.0\tC124\t192.168.56.11\t52345\t192.168.56.21\t53\tudp"
        "\tdns\t-\t0\t25\t-\t1\n"
    ).encode("utf-8")


def test_verified_export_preserves_missing_values_numbers_and_audit(tmp_path):
    data = sample_log()
    db = tmp_path / "cyber.sqlite3"
    case_id = create_offline_review_case(db, source_data=data, record_index=0)
    report = json.loads(export_verified_offline_case(
        db, case_id=case_id, source_data=data, record_index=0
    ))
    assert report["schema_version"] == 2
    assert report["case"]["verdict"] == "Unclassified"
    assert report["case"]["confidence"] is None
    assert report["typed_zeek_event"]["service"] is None
    assert report["typed_zeek_event"]["resp_bytes"] is None
    assert report["typed_zeek_event"]["orig_bytes"] == 100
    assert isinstance(report["typed_zeek_event"]["orig_bytes"], int)
    assert report["typed_zeek_event"]["duration_s"] == 1.25
    assert isinstance(report["typed_zeek_event"]["duration_s"], float)
    assert report["flow_evidence"]["resp_bytes"] == "None"  # Legacy string snapshot.
    assert report["typed_event_source"]["source_sha256"] == hashlib.sha256(data).hexdigest()
    assert report["typed_event_source"]["record_index_zero_based"] == 0
    assert report["case_events"][0]["new_state"] == "New"
    assert not (tmp_path / "soc_cases.sqlite3").exists()


def test_export_rejects_wrong_source_or_selection(tmp_path):
    data = sample_log()
    db = tmp_path / "cyber.sqlite3"
    case_id = create_offline_review_case(db, source_data=data, record_index=0)
    with pytest.raises(ValueError, match="does not match"):
        export_verified_offline_case(
            db, case_id=case_id, source_data=sample_log(uid="CHANGED"), record_index=0
        )
    with pytest.raises(ValueError, match="does not match"):
        export_verified_offline_case(db, case_id=case_id, source_data=data, record_index=1)
    with pytest.raises(ValueError, match="out of range"):
        export_verified_offline_case(db, case_id=case_id, source_data=data, record_index=2)


def test_export_rejects_modified_snapshot_and_flow_digest(tmp_path):
    data = sample_log()
    db = tmp_path / "cyber.sqlite3"
    case_id = create_offline_review_case(db, source_data=data, record_index=0)
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT evidence_json FROM cases WHERE case_id=?", (case_id,)).fetchone()
        snapshot = json.loads(row[0])
        snapshot["orig_bytes"] = "999"
        conn.execute("UPDATE cases SET evidence_json=? WHERE case_id=?",
                     (json.dumps(snapshot), case_id))
    with pytest.raises(ValueError, match="does not match"):
        export_verified_offline_case(db, case_id=case_id, source_data=data, record_index=0)


@pytest.mark.parametrize("case_id,index", [(True, 0), (0, 0), (1, True), (1, -1), (1, 0.5)])
def test_invalid_identifiers_rejected_before_database_access(tmp_path, case_id, index):
    db = tmp_path / "cyber.sqlite3"
    with pytest.raises(ValueError):
        export_verified_offline_case(
            db, case_id=case_id, source_data=sample_log(), record_index=index
        )
    assert not db.exists()


def test_invalid_source_rejected_without_creating_db(tmp_path):
    db = tmp_path / "cyber.sqlite3"
    with pytest.raises(ValueError, match="separator"):
        export_verified_offline_case(
            db, case_id=1, source_data=b"not a Zeek log", record_index=0
        )
    assert not db.exists()
