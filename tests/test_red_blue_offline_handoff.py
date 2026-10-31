"""Synthetic-only Red/Blue evidence handoff; no Zeek binary, packets or SOC writes."""
from __future__ import annotations

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
from shared.offline_handoff import verify_red_blue_offline_handoff
from test_red_team_offline_fixture_binding import evidence
from test_zeek_offline_baseline import _dataset

CIDRS = ["192.168.56.0/24"]


@pytest.fixture
def joint(evidence):
    raw = evidence["log"].read_bytes()
    source_sha = hashlib.sha256(raw).hexdigest()
    model = build_zeek_research_artifact(_dataset(), input_manifest_sha256="a" * 64)
    model_bytes = json.dumps(model, allow_nan=False).encode("utf-8")
    model_sha = hashlib.sha256(model_bytes).hexdigest()
    report = score_new_zeek_log(
        raw, model, expected_log_sha256=source_sha,
        lab_cidrs=CIDRS, model_sha256=model_sha,
    )
    report_bytes = json.dumps(report, allow_nan=False).encode("utf-8")
    model_path = evidence["log"].parent / "model.json"
    report_path = evidence["log"].parent / "new-predictions.json"
    model_path.write_bytes(model_bytes)
    report_path.write_bytes(report_bytes)
    return {
        **evidence, "raw": raw, "model_obj": model, "model": model_path,
        "model_sha": model_sha, "blue": report_path, "blue_report": report,
        "source_sha": source_sha,
    }


def _verify(item, **changes):
    audit_data = item["audit"].read_bytes()
    report_data = item["blue"].read_bytes()
    options = {
        "audit_data": audit_data,
        "expected_audit_sha256": hashlib.sha256(audit_data).hexdigest(),
        "import_report_path": item["report"],
        "expected_import_report_sha256": hashlib.sha256(item["report"].read_bytes()).hexdigest(),
        "pcap_path": item["pcap"], "conn_log_path": item["log"],
        "source_data": item["raw"], "expected_log_sha256": item["source_sha"],
        "model": item["model_obj"], "model_sha256": item["model_sha"],
        "blue_report_data": report_data,
        "expected_blue_report_sha256": hashlib.sha256(report_data).hexdigest(),
        "lab_cidrs": CIDRS,
        "operator_confirmed_authorized": True,
        "operator_confirmed_offline": True,
        "operator_confirmed_fixture_reviewed": True,
    }
    options.update(changes)
    return verify_red_blue_offline_handoff(**options)


def test_same_pinned_source_joins_without_detection_or_execution_claims(joint):
    result = _verify(joint)
    assert result["same_pinned_zeek_source_verified"] is True
    assert result["red_proposal_id"] == 1
    assert result["red_scenario_id"] == "baseline_web"
    assert result["zeek_flow_count"] == 1
    assert result["blue_research_candidate_count"] == joint["blue_report"]["research_candidate_count"]
    assert result["blue_report_recomputed"] is True
    assert result["pcap_framing_verified"] is True
    for field in (
        "scenario_traffic_match_verified", "ground_truth_verified",
        "held_out_test_exclusion_verified", "blue_team_detection_verified",
        "independent_authorization_verified", "physical_host_only_isolation_verified",
        "capture_authenticity_verified", "operational_alerts_created",
        "soc_cases_created", "red_team_execution_enabled", "network_access",
    ):
        assert result[field] is False
    assert "192.168." not in json.dumps(result)
    assert "C123" not in json.dumps(result)


def test_tampered_blue_report_rejected_even_if_digest_re_pinned(joint):
    tampered = dict(joint["blue_report"])
    tampered["research_candidate_count"] += 1
    payload = json.dumps(tampered).encode()
    with pytest.raises(ValueError, match="differs"):
        _verify(joint, blue_report_data=payload,
                expected_blue_report_sha256=hashlib.sha256(payload).hexdigest())


def test_wrong_independent_blue_pin_rejected(joint):
    with pytest.raises(ValueError, match="Blue research report SHA"):
        _verify(joint, expected_blue_report_sha256="0" * 64)


def test_different_red_blue_source_rejected_even_with_valid_blue_scores(joint):
    changed = joint["raw"].replace(b"C123", b"C999")
    changed_sha = hashlib.sha256(changed).hexdigest()
    changed_report = score_new_zeek_log(
        changed, joint["model_obj"], expected_log_sha256=changed_sha,
        lab_cidrs=CIDRS, model_sha256=joint["model_sha"],
    )
    payload = json.dumps(changed_report).encode()
    with pytest.raises(ValueError, match="Red/Blue original Zeek source"):
        _verify(
            joint, source_data=changed, expected_log_sha256=changed_sha,
            blue_report_data=payload,
            expected_blue_report_sha256=hashlib.sha256(payload).hexdigest(),
        )


def test_tampered_red_audit_and_original_pcap_refused(joint):
    with pytest.raises(ValueError):
        _verify(joint, expected_audit_sha256="0" * 64)
    joint["pcap"].write_bytes(joint["pcap"].read_bytes() + b"x")
    with pytest.raises(ValueError):
        _verify(joint)


@pytest.mark.parametrize("confirmation", [
    "operator_confirmed_authorized", "operator_confirmed_offline",
    "operator_confirmed_fixture_reviewed",
])
def test_all_operator_declarations_required(joint, confirmation):
    with pytest.raises(ValueError, match="confirmations"):
        _verify(joint, **{confirmation: False})


def test_cli_read_only_and_fails_closed_without_declarations(joint):
    original = {key: joint[key].read_bytes() for key in ("audit", "pcap", "log", "report", "model", "blue")}
    command = [
        sys.executable, str(ROOT / "scripts/verify_red_blue_offline_handoff.py"),
        "--audit", str(joint["audit"]),
        "--expected-audit-sha256", hashlib.sha256(original["audit"]).hexdigest(),
        "--offline-import-report", str(joint["report"]),
        "--expected-offline-import-report-sha256", hashlib.sha256(original["report"]).hexdigest(),
        "--pcap", str(joint["pcap"]), "--log", str(joint["log"]),
        "--expected-log-sha256", joint["source_sha"],
        "--model", str(joint["model"]), "--expected-model-sha256", joint["model_sha"],
        "--blue-report", str(joint["blue"]),
        "--expected-blue-report-sha256", hashlib.sha256(original["blue"]).hexdigest(),
        "--cidr", CIDRS[0],
    ]
    refused = subprocess.run(command, capture_output=True, text=True, check=False)
    assert refused.returncode == 1
    assert "refused" in refused.stderr
    success = subprocess.run(
        command + ["--confirm-authorized", "--confirm-offline-only", "--confirm-fixture-reviewed"],
        capture_output=True, text=True, check=False,
    )
    assert success.returncode == 0, success.stderr
    result = json.loads(success.stdout)
    assert result["same_pinned_zeek_source_verified"] is True
    assert result["blue_team_detection_verified"] is False
    assert all(joint[key].read_bytes() == data for key, data in original.items())
    assert not list(joint["log"].parent.glob("*.sqlite*"))
    changed = command.copy()
    changed[changed.index("--expected-model-sha256") + 1] = "0" * 64
    assert subprocess.run(changed, capture_output=True).returncode == 1
