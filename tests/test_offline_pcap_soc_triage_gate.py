"""Synthetic-only PCAP provenance regression at manual SOC write boundary.

Zeek import is mocked. Real scorer and triage CLIs run offline; these tests
do not establish VMware isolation, PCAP authenticity or attack detection.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from test_offline_pcap_verify import imported, repin
from test_zeek_offline_baseline import _dataset

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.model_artifact import build_zeek_research_artifact
from blue_team_ai.new_log_triage import create_new_log_candidate_case
from blue_team_ai.soc_evidence_link import verify_new_log_soc_case_link
from siem_ai.core import list_cases


@pytest.fixture
def prepared(imported):
    # The general import fixture deliberately uses a header-only PCAP to test
    # legacy byte-consistency. SOC provenance now requires at least one valid
    # classic-PCAP packet record, without claiming packet-to-Zeek correlation.
    pcap_bytes = (
        bytes.fromhex("d4c3b2a1")
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 100, 123, 4, 4) + b"test"
    )
    imported["pcap"].write_bytes(pcap_bytes)
    import_report = json.loads(imported["report"].read_text(encoding="utf-8"))
    import_report["pcap_sha256"] = hashlib.sha256(pcap_bytes).hexdigest()
    import_report["pcap_size_bytes"] = len(pcap_bytes)
    repin(imported, import_report)
    model = build_zeek_research_artifact(_dataset(), input_manifest_sha256="a" * 64)
    # Fixture-only candidate coverage; not a selected research threshold.
    model["selected_threshold"] = 0.000001
    model_path = imported["pcap"].parent / "model.json"
    model_path.write_text(json.dumps(model, allow_nan=False), encoding="utf-8")
    model_sha = hashlib.sha256(model_path.read_bytes()).hexdigest()
    log_sha = hashlib.sha256(imported["log"].read_bytes()).hexdigest()
    report_path = imported["log"].parent / "new-predictions.json"
    common = [
        "--model", str(model_path), "--expected-model-sha256", model_sha,
        "--log", str(imported["log"]), "--expected-log-sha256", log_sha,
        "--cidr", "192.168.56.0/24",
    ]
    provenance = [
        "--offline-import-report", str(imported["report"]),
        "--expected-offline-import-report-sha256", imported["pin"],
        "--offline-import-pcap", str(imported["pcap"]),
    ]
    score = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "score_zeek_new_log.py"),
         *common, *provenance, "--output", str(report_path)],
        capture_output=True, text=True, check=False,
    )
    assert score.returncode == 0, score.stderr
    report = json.loads(report_path.read_text(encoding="utf-8"))
    index = next(i for i, row in enumerate(report["predictions"])
                 if row["research_candidate"] is True)
    base = [sys.executable, str(ROOT / "scripts" / "triage_zeek_new_log.py"),
            *common, "--report", str(report_path)]
    db = imported["pcap"].parent / "soc.sqlite3"
    return {
        **imported, "model": model, "model_sha": model_sha, "log_sha": log_sha,
        "report_data": report_path.read_bytes(), "prediction": report_path,
        "base": base, "provenance": provenance, "db": db, "index": index,
    }


def run(command):
    return subprocess.run(command, capture_output=True, text=True, check=False)


def write_args(p):
    return [
        "--record-index", str(p["index"]), "--db", str(p["db"]),
        "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture",
    ]


def test_pinned_listing_and_manual_case_preserve_originals(prepared):
    p = prepared
    original = {key: p[key].read_bytes()
                for key in ("pcap", "log", "report", "prediction")}
    listing = run(p["base"] + p["provenance"] + ["--list-candidates"])
    assert listing.returncode == 0, listing.stderr
    assert "offline_pcap_provenance_reverified=true" in listing.stdout
    assert not p["db"].exists()
    accepted = run(p["base"] + p["provenance"] + write_args(p))
    assert accepted.returncode == 0, accepted.stderr
    assert "verdict=Unclassified" in accepted.stdout
    assert "offline_pcap_provenance_reverified=true" in accepted.stdout
    cases = list_cases(p["db"])
    assert len(cases) == 1
    note = cases.iloc[0]["analyst_note"]
    assert "Pinned original PCAP/import report/Zeek byte integrity" in note
    assert "classic PCAP packet framing checked" in note
    assert "NOT packet-to-flow correlation" in note
    assert p["pin"] in note
    assert hashlib.sha256(p["pcap"].read_bytes()).hexdigest() in note
    assert "ground truth are unverified" in note
    assert run(p["base"] + p["provenance"] + write_args(p)).returncode == 0
    assert len(list_cases(p["db"])) == 1
    assert all(p[key].read_bytes() == value for key, value in original.items())


@pytest.mark.parametrize("removed", [
    "--offline-import-report",
    "--expected-offline-import-report-sha256",
    "--offline-import-pcap",
])
def test_partial_pcap_gate_fails_before_soc_write(prepared, removed):
    p = prepared
    flags = p["provenance"].copy()
    index = flags.index(removed)
    del flags[index:index + 2]
    refused = run(p["base"] + flags + write_args(p))
    assert refused.returncode == 1
    assert not p["db"].exists()
    assert str(p["pcap"]) not in refused.stderr


def test_pcap_changed_after_successful_listing_refuses_case(prepared):
    p = prepared
    assert run(p["base"] + p["provenance"] + ["--list-candidates"]).returncode == 0
    p["pcap"].write_bytes(p["pcap"].read_bytes() + b"changed-after-list")
    # The legacy report/model/log check still passes, illustrating why the
    # extra provenance recheck must occur again before creating a case.
    assert run(p["base"] + ["--list-candidates"]).returncode == 0
    refused = run(p["base"] + p["provenance"] + write_args(p))
    assert refused.returncode == 1
    assert not p["db"].exists()


def test_direct_case_api_rechecks_pcap_at_write_boundary(prepared):
    p = prepared
    p["pcap"].write_bytes(p["pcap"].read_bytes() + b"tampered")
    with pytest.raises(ValueError):
        create_new_log_candidate_case(
            p["db"], source_data=p["log"].read_bytes(), model=p["model"],
            report_data=p["report_data"], expected_log_sha256=p["log_sha"],
            model_sha256=p["model_sha"], lab_cidrs=["192.168.56.0/24"],
            record_index=p["index"], analyst_confirmed=True,
            operator_confirmed_authorized=True, operator_confirmed_new_capture=True,
            offline_import_report_path=p["report"],
            offline_import_report_sha256=p["pin"],
            offline_import_pcap_path=p["pcap"],
            offline_import_log_path=p["log"],
        )
    assert not p["db"].exists()


@pytest.mark.parametrize("change", ["bad_pin", "wrong_cidr", "wrong_pcap"])
def test_invalid_provenance_fails_closed(prepared, change):
    p = prepared
    command = p["base"] + p["provenance"] + write_args(p)
    if change == "bad_pin":
        command[command.index("--expected-offline-import-report-sha256") + 1] = "0" * 64
    elif change == "wrong_cidr":
        command[command.index("--cidr") + 1] = "192.168.57.0/24"
    else:
        command[command.index("--offline-import-pcap") + 1] = str(p["report"])
    assert run(command).returncode == 1
    assert not p["db"].exists()




def test_soc_link_audit_accepts_new_framing_claim_and_legacy_note(prepared):
    p = prepared
    created = run(p["base"] + p["provenance"] + write_args(p))
    assert created.returncode == 0, created.stderr
    case_id = int(list_cases(p["db"]).iloc[0]["case_id"])
    def check_link():
        return verify_new_log_soc_case_link(
            p["db"], source_data=p["log"].read_bytes(), model=p["model"],
            report_data=p["report_data"], expected_log_sha256=p["log_sha"],
            model_sha256=p["model_sha"], lab_cidrs=["192.168.56.0/24"],
            record_index=p["index"], case_id=case_id,
            expected_import_report_sha256=p["pin"],
            expected_pcap_sha256=hashlib.sha256(p["pcap"].read_bytes()).hexdigest(),
        )
    assert check_link()["initial_audit_matches_recomputed_inference"] is True
    with sqlite3.connect(p["db"]) as conn:
        note = conn.execute(
            "SELECT note FROM case_events WHERE case_id=? ORDER BY event_id LIMIT 1",
            (case_id,),
        ).fetchone()[0]
        # Simulate a case created by the previous release. The historical
        # audit wording remains verifiable without asserting framing.
        legacy = note.replace(
            "classic PCAP packet framing checked (NOT packet-to-flow correlation); ", ""
        )
        assert legacy != note
        conn.execute(
            "UPDATE case_events SET note=? WHERE case_id=? AND event_id=("
            "SELECT MIN(event_id) FROM case_events WHERE case_id=?)",
            (legacy, case_id, case_id),
        )
    assert check_link()["initial_audit_matches_recomputed_inference"] is True
    with sqlite3.connect(p["db"]) as conn:
        forged = note.replace(
            "NOT packet-to-flow correlation", "packet-to-flow correlation verified"
        )
        conn.execute(
            "UPDATE case_events SET note=? WHERE case_id=? AND event_id=("
            "SELECT MIN(event_id) FROM case_events WHERE case_id=?)",
            (forged, case_id, case_id),
        )
    with pytest.raises(ValueError, match="Invalid PCAP provenance claim"):
        check_link()


def _repin_pcap(p, raw):
    p["pcap"].write_bytes(raw)
    report = json.loads(p["report"].read_text(encoding="utf-8"))
    report["pcap_sha256"] = hashlib.sha256(raw).hexdigest()
    report["pcap_size_bytes"] = len(raw)
    repin(p, report)
    provenance = p["provenance"].copy()
    provenance[provenance.index("--expected-offline-import-report-sha256") + 1] = p["pin"]
    return provenance


@pytest.mark.parametrize("malformed", ["header_only", "truncated_payload", "invalid_fraction"])
def test_re_pinned_structurally_invalid_pcap_refuses_listing_and_soc_write(prepared, malformed):
    # The original and import report are consistently re-pinned. A SHA match
    # alone must not allow malformed PCAP framing to enter SOC evidence.
    p = prepared
    header = bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    if malformed == "header_only":
        raw = header
    elif malformed == "truncated_payload":
        raw = header + struct.pack("<IIII", 100, 123, 5, 5) + b"abcd"
    else:
        raw = header + struct.pack("<IIII", 100, 1_000_000, 4, 4) + b"test"
    provenance = _repin_pcap(p, raw)
    listing = run(p["base"] + provenance + ["--list-candidates"])
    assert listing.returncode == 1
    refused = run(p["base"] + provenance + write_args(p))
    assert refused.returncode == 1
    assert not p["db"].exists()
    assert str(p["pcap"]) not in refused.stderr


def test_direct_soc_api_rejects_re_pinned_header_only_pcap(prepared):
    p = prepared
    header = bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    _repin_pcap(p, header)
    with pytest.raises(ValueError, match="no packet"):
        create_new_log_candidate_case(
            p["db"], source_data=p["log"].read_bytes(), model=p["model"],
            report_data=p["report_data"], expected_log_sha256=p["log_sha"],
            model_sha256=p["model_sha"], lab_cidrs=["192.168.56.0/24"],
            record_index=p["index"], analyst_confirmed=True,
            operator_confirmed_authorized=True, operator_confirmed_new_capture=True,
            offline_import_report_path=p["report"],
            offline_import_report_sha256=p["pin"],
            offline_import_pcap_path=p["pcap"],
            offline_import_log_path=p["log"],
        )
    assert not p["db"].exists()


def test_legacy_manual_triage_still_available_without_pcap_claim(prepared):
    p = prepared
    legacy = run(p["base"] + write_args(p))
    assert legacy.returncode == 0, legacy.stderr
    assert "offline_pcap_provenance_reverified" not in legacy.stdout
    assert "Original PCAP provenance NOT software-checked" in list_cases(p["db"]).iloc[0]["analyst_note"]
