"""Synthetic-only PCAP provenance regression at manual SOC write boundary.

Zeek import is mocked. Real scorer and triage CLIs run offline; these tests
do not establish VMware isolation, PCAP authenticity or attack detection.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from test_offline_pcap_verify import imported
from test_zeek_offline_baseline import _dataset

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.model_artifact import build_zeek_research_artifact
from blue_team_ai.new_log_triage import create_new_log_candidate_case
from siem_ai.core import list_cases


@pytest.fixture
def prepared(imported):
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


def test_legacy_manual_triage_still_available_without_pcap_claim(prepared):
    p = prepared
    legacy = run(p["base"] + write_args(p))
    assert legacy.returncode == 0, legacy.stderr
    assert "offline_pcap_provenance_reverified" not in legacy.stdout
    assert "Original PCAP provenance NOT software-checked" in list_cases(p["db"]).iloc[0]["analyst_note"]
