"""Synthetic-only regression for explicit pinned new-log research SOC triage."""
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

from blue_team_ai.model_artifact import build_zeek_research_artifact
from blue_team_ai.new_log_inference import score_new_zeek_log
from blue_team_ai.new_log_triage import create_new_log_candidate_case
from siem_ai.core import case_history, list_cases, case_evidence
from test_zeek_new_log_inference import _log
from test_zeek_offline_baseline import _dataset

CIDR = ["192.168.56.0/24"]


@pytest.fixture(scope="module")
def evidence():
    model = build_zeek_research_artifact(_dataset(), input_manifest_sha256="a" * 64)
    # Synthetic contract fixture: force at least one candidate, NOT a scientific
    # threshold recommendation or a real validation-selected threshold.
    model["selected_threshold"] = 0.000001
    raw = _log()
    model_bytes = json.dumps(model, allow_nan=False).encode("utf-8")
    model_sha = hashlib.sha256(model_bytes).hexdigest()
    source_sha = hashlib.sha256(raw).hexdigest()
    report = score_new_zeek_log(
        raw, model, expected_log_sha256=source_sha,
        lab_cidrs=CIDR, model_sha256=model_sha,
    )
    assert any(p["research_candidate"] for p in report["predictions"])
    return raw, model, model_bytes, report, source_sha, model_sha


def _args(evidence, **overrides):
    raw, model, _, report, source_sha, model_sha = evidence
    values = dict(
        source_data=raw, model=model,
        report_data=json.dumps(report, allow_nan=False).encode("utf-8"),
        expected_log_sha256=source_sha,
        model_sha256=model_sha, lab_cidrs=CIDR,
        record_index=next(i for i, p in enumerate(report["predictions"])
                          if p["research_candidate"]),
        analyst_confirmed=True, operator_confirmed_authorized=True,
        operator_confirmed_new_capture=True,
    )
    values.update(overrides)
    return values


def test_explicit_verified_candidate_creates_one_unclassified_case(tmp_path, evidence):
    db = tmp_path / "cyber.sqlite3"
    case_id = create_new_log_candidate_case(db, **_args(evidence))
    cases = list_cases(db)
    assert len(cases) == 1
    row = cases.iloc[0]
    assert row["case_id"] == case_id
    assert row["verdict"] == "Unclassified"
    assert row["state"] == "New"
    assert row["confidence"] is None or str(row["confidence"]) == "nan"
    note = row["analyst_note"]
    assert "NEW-log OFFLINE research candidate" in note
    assert "NOT a verified attack" in note
    assert evidence[4] in note and evidence[5] in note
    assert hashlib.sha256(_args(evidence)["report_data"]).hexdigest() in note
    assert "ground truth are unverified" in note
    assert len(case_history(db, case_id)) == 1
    assert case_evidence(db, case_id)["uid"] == evidence[3]["predictions"][_args(evidence)["record_index"]]["uid"]


def test_repeat_and_concurrent_selection_deduplicates(tmp_path, evidence):
    from concurrent.futures import ThreadPoolExecutor
    db = tmp_path / "cyber.sqlite3"
    args = _args(evidence)
    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(lambda _: create_new_log_candidate_case(db, **args), range(4)))
    assert len(set(ids)) == 1
    assert len(list_cases(db)) == 1
    assert len(case_history(db, ids[0])) == 1


@pytest.mark.parametrize("change", [
    {"analyst_confirmed": False},
    {"analyst_confirmed": 1},
    {"operator_confirmed_authorized": False},
    {"operator_confirmed_new_capture": False},
    {"record_index": -1},
    {"record_index": 500},
    {"record_index": True},
    {"record_index": 2},
    {"expected_log_sha256": "0" * 64},
    {"model_sha256": "0" * 64},
    {"lab_cidrs": ["10.5.0.0/16"]},
])
def test_invalid_consent_scope_digest_or_index_never_creates_db(tmp_path, evidence, change):
    db = tmp_path / "cyber.sqlite3"
    with pytest.raises(ValueError):
        create_new_log_candidate_case(db, **_args(evidence, **change))
    assert not db.exists()


def test_modified_report_or_original_refused_before_write(tmp_path, evidence):
    db = tmp_path / "cyber.sqlite3"
    tampered = copy.deepcopy(evidence[3])
    tampered["predictions"][0]["attack_probability"] = 0.123
    for kwargs in (
        {"report_data": json.dumps(tampered).encode()},
        {"report_data": b'{"predictions":NaN}'},
        {"source_data": evidence[0] + b" "},
    ):
        with pytest.raises(ValueError):
            create_new_log_candidate_case(db, **_args(evidence, **kwargs))
        assert not db.exists()


def test_valid_non_candidate_is_rejected(tmp_path, evidence):
    raw, model, _, _, source_sha, model_sha = evidence
    altered = copy.deepcopy(model)
    altered["selected_threshold"] = 0.999999999
    altered_bytes = json.dumps(altered, allow_nan=False).encode()
    altered_sha = hashlib.sha256(altered_bytes).hexdigest()
    report = score_new_zeek_log(
        raw, altered, expected_log_sha256=source_sha,
        lab_cidrs=CIDR, model_sha256=altered_sha,
    )
    assert any(not row["research_candidate"] for row in report["predictions"])
    index = next(i for i, row in enumerate(report["predictions"])
                 if not row["research_candidate"])
    db = tmp_path / "cyber.sqlite3"
    with pytest.raises(ValueError, match="Only verified research candidates"):
        create_new_log_candidate_case(
            db, **_args(evidence, model=altered, model_sha256=altered_sha,
                        report_data=json.dumps(report).encode(), record_index=index)
        )
    assert not db.exists()


def _cli(tmp_path, evidence):
    raw, _, model_bytes, report, source_sha, model_sha = evidence
    private = tmp_path / "private"
    private.mkdir()
    (private / "conn.log").write_bytes(raw)
    (private / "model.json").write_bytes(model_bytes)
    (private / "new-predictions.json").write_text(json.dumps(report), encoding="utf-8")
    command = [
        sys.executable, str(ROOT / "scripts" / "triage_zeek_new_log.py"),
        "--model", str(private / "model.json"),
        "--expected-model-sha256", model_sha,
        "--log", str(private / "conn.log"),
        "--expected-log-sha256", source_sha,
        "--report", str(private / "new-predictions.json"),
        "--cidr", CIDR[0],
    ]
    return private, command


def test_cli_read_only_listing_and_explicit_write(tmp_path, evidence):
    private, command = _cli(tmp_path, evidence)
    db = private / "cases.sqlite3"
    before = {p.name: p.read_bytes() for p in private.iterdir()}
    listing = subprocess.run(command + ["--list-candidates"], capture_output=True, text=True)
    assert listing.returncode == 0, listing.stderr
    assert "record_index=" in listing.stdout
    assert not db.exists()
    assert before == {p.name: p.read_bytes() for p in private.iterdir()}
    index = _args(evidence)["record_index"]
    write = command + [
        "--record-index", str(index), "--db", str(db),
        "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture",
    ]
    refused = subprocess.run(write[:-1], capture_output=True, text=True)
    assert refused.returncode == 1 and not db.exists()
    accepted = subprocess.run(write, capture_output=True, text=True)
    assert accepted.returncode == 0, accepted.stderr
    assert "verdict=Unclassified" in accepted.stdout
    assert len(list_cases(db)) == 1
    repeated = subprocess.run(write, capture_output=True, text=True)
    assert repeated.returncode == 0
    assert len(list_cases(db)) == 1
    assert before == {p.name: p.read_bytes() for p in private.iterdir() if p.name != db.name}


def test_cli_rejects_report_tampering_and_public_db(tmp_path, evidence):
    private, command = _cli(tmp_path, evidence)
    db = private / "cases.sqlite3"
    index = _args(evidence)["record_index"]
    write = command + [
        "--record-index", str(index), "--db", str(db),
        "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture",
    ]
    report_path = private / "new-predictions.json"
    changed = json.loads(report_path.read_text())
    changed["predictions"][0]["dst_ip"] = "192.168.56.99"
    report_path.write_text(json.dumps(changed), encoding="utf-8")
    assert subprocess.run(write, capture_output=True).returncode == 1
    assert not db.exists()
    assert subprocess.run(
        command + ["--list-candidates", "--db", str(db)], capture_output=True,
    ).returncode == 1
