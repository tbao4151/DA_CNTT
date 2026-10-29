"""Red Team exported chronology verification; all observations are synthetic."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from red_team_ai.audit_verify import MAX_AUDIT_BYTES, verify_planning_audit_bytes
from red_team_ai.planning_audit import append_manual_feedback, append_proposal, export_planning_audit
from red_team_ai.scenario_policy import choose_scenario


def _audit_bytes() -> bytes:
    plan = choose_scenario([], strategy="ucb1", seed=42)
    events = append_proposal(
        [], plan, seed=42, recorded_at_utc="2026-10-29T02:00:00+00:00",
    )
    events = append_manual_feedback(
        events, proposal_id=1, blue_flagged=False,
        recorded_at_utc="2026-10-29T02:01:00+00:00",
    )
    return (json.dumps(export_planning_audit(events), ensure_ascii=False) + "\n").encode()


def test_valid_export_replays_without_claiming_attack_or_authenticity():
    raw = _audit_bytes()
    verified = verify_planning_audit_bytes(raw)
    assert verified["proposal_count"] == verified["manual_feedback_count"] == 1
    assert verified["policy_replay_consistent"] is True
    assert verified["independent_pin_verified"] is False
    assert verified["blue_team_outcomes_verified"] is False
    assert verified["execution_performed"] is False
    assert verified["attack_detection_measured"] is False


def test_separate_sha256_pin_detects_modified_export():
    raw = _audit_bytes()
    pin = hashlib.sha256(raw).hexdigest()
    assert verify_planning_audit_bytes(raw, expected_sha256=pin)["independent_pin_verified"]
    with pytest.raises(ValueError, match="SHA-256"):
        verify_planning_audit_bytes(raw + b" ", expected_sha256=pin)
    with pytest.raises(ValueError, match="lowercase"):
        verify_planning_audit_bytes(raw, expected_sha256=pin.upper())


@pytest.mark.parametrize("field,value", [
    ("manual_feedback_count", True),
    ("blue_team_outcomes_verified", True),
    ("execution_enabled", True),
    ("feedback_origin", "verified_by_soc"),
    ("audit_version", 2),
    ("unexpected", "payload"),
])
def test_rejects_forged_top_level_claims(field, value):
    report = json.loads(_audit_bytes())
    report[field] = value
    with pytest.raises(ValueError, match="metadata"):
        verify_planning_audit_bytes(json.dumps(report).encode())


def test_rejects_forged_event_policy_and_feedback():
    report = json.loads(_audit_bytes())
    report["events"][0]["scenario_id"] = "dns_variation"
    with pytest.raises(ValueError, match="policy"):
        verify_planning_audit_bytes(json.dumps(report).encode())
    report = json.loads(_audit_bytes())
    report["events"][1]["verified"] = True
    with pytest.raises(ValueError, match="unverified"):
        verify_planning_audit_bytes(json.dumps(report).encode())


@pytest.mark.parametrize("raw", [
    b'{"events":[],"events":[]}',
    b'{"events":[],"bad":NaN}',
    b'{"events":[],"bad":Infinity}',
    b'\xff',
    b'',
    b' ' * (MAX_AUDIT_BYTES + 1),
])
def test_rejects_malformed_duplicate_nonfinite_and_oversize(raw):
    with pytest.raises(ValueError):
        verify_planning_audit_bytes(raw)


def test_cli_private_read_only_and_fail_closed(tmp_path):
    source = tmp_path / "offline-audit.json"
    original = _audit_bytes()
    source.write_bytes(original)
    pin = hashlib.sha256(original).hexdigest()
    script = ROOT / "scripts" / "verify_red_team_planning_audit.py"
    def run(digest):
        return subprocess.run(
            [sys.executable, str(script), "--audit", str(source),
             "--expected-sha256", digest],
            text=True, capture_output=True, check=False, timeout=30,
        )
    accepted = run(pin)
    assert accepted.returncode == 0, accepted.stderr
    result = json.loads(accepted.stdout)
    assert result["independent_pin_verified"] is True
    assert result["network_access"] is False
    assert "192.168." not in accepted.stdout
    assert run("0" * 64).returncode != 0
    assert source.read_bytes() == original
    assert sorted(p.name for p in tmp_path.iterdir()) == [source.name]
