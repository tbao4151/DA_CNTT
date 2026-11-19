"""Network-free tests for operator-assisted VMware JSONL progress."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import run_vmware_stepwise as mod
from test_vmware_stepwise import args, fake_raw, fake_receipt


def _mock_stimulus(monkeypatch):
    monkeypatch.setattr(
        mod.stimulus, "run",
        lambda **kwargs: fake_receipt() if kwargs["execute"] else {"network_attempts": 0},
    )


def _mock_capture(monkeypatch, evidence: Path):
    def fake_fetch(**_kwargs):
        raw = fake_raw()
        (evidence / "sample.log").write_bytes(raw)
        return {
            "local_log_filename": "sample.log",
            "log_sha256": hashlib.sha256(raw).hexdigest(),
            "flow_count": 2,
        }
    monkeypatch.setattr(mod.collector, "fetch", fake_fetch)


def _check_common(events):
    assert [event["seq"] for event in events] == list(range(1, len(events) + 1))
    assert all(event["kind"] == "da005_vmware_stepwise_progress_v1" for event in events)
    for event in events:
        assert event["mode"] == "operator_assisted_benign_hostonly_experiment"
        assert event["vmware_isolation_verified"] is False
        assert event["attack_executed"] is False
        assert event["ai_attack_planning_executed"] is False
        assert event["operational_ai_detection_verified"] is False
        assert event["soc_alerts_created"] is False
        assert "192.168." not in json.dumps(event)
        assert "sample.log" not in json.dumps(event)


def test_dry_run_reports_only_dry_run_and_no_network(monkeypatch, tmp_path):
    events = []
    monkeypatch.setattr(mod.collector, "fetch", lambda **_k: pytest.fail("No SSH on dry-run"))
    monkeypatch.setattr(mod.stimulus, "send_benign_probe", lambda **_k: pytest.fail("No network"))
    out = mod.run_sequence(**args(tmp_path), progress_sink=events.append)
    assert out["mode"] == "DRY_RUN_EXECUTION_OFF"
    assert [(e["stage"], e["status"]) for e in events] == [("preflight", "dry_run")]
    _check_common(events)


def test_capture_only_progress_tracks_actual_completed_stages(monkeypatch, tmp_path):
    _mock_stimulus(monkeypatch)
    _mock_capture(monkeypatch, tmp_path)
    events = []
    result = mod.run_sequence(**args(tmp_path), execute=True,
                              operator_confirmed_hostonly=True, settle_s=0,
                              progress_sink=events.append)
    assert result["captured_log_flow_count"] == 2
    assert [(e["stage"], e["status"]) for e in events] == [
        ("preflight", "completed"),
        ("red", "running"), ("red", "completed"),
        ("zeek", "running"), ("zeek", "completed"),
        ("blue", "skipped"), ("audit", "running"),
        ("audit", "completed"), ("soc", "skipped"),
    ]
    assert events[2]["counts"]["attempted_probes"] == 2
    assert events[4]["counts"]["snapshot_flow_count"] == 2
    assert events[7]["counts"]["candidate_matches"] == 2
    _check_common(events)


def test_model_branch_progress_only_completed_after_bridge(monkeypatch, tmp_path):
    _mock_stimulus(monkeypatch)
    model = tmp_path / "model.json"
    model.write_text("test-only-mock-model", encoding="utf-8")
    monkeypatch.setattr(mod.blue, "load_pinned_zeek_research_model", lambda *_a, **_kw: {})
    def fake_blue(**_kwargs):
        raw = fake_raw()
        (tmp_path / "sample.log").write_bytes(raw)
        return {
            "log_file": "sample.log",
            "log_sha256": hashlib.sha256(raw).hexdigest(),
            "flow_count": 2, "report_file": "sample.research.json",
            "research_candidate_count": 1,
        }
    monkeypatch.setattr(mod.blue, "run_bridge", fake_blue)
    events = []
    out = mod.run_sequence(**args(tmp_path), execute=True,
                           operator_confirmed_hostonly=True, settle_s=0,
                           model_path=model, expected_model_sha256="a" * 64,
                           progress_sink=events.append)
    assert out["blue_research_scoring_performed"] is True
    assert events[5]["stage"] == "blue"
    assert events[5]["status"] == "completed"
    assert events[5]["counts"]["research_candidate_count"] == 1
    assert ("soc", "skipped") in [(e["stage"], e["status"]) for e in events]
    _check_common(events)


def test_refused_isolation_emits_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(mod.stimulus, "send_benign_probe", lambda **_k: pytest.fail("No packet"))
    events = []
    with pytest.raises(ValueError, match="confirm"):
        mod.run_sequence(**args(tmp_path), execute=True, progress_sink=events.append)
    assert events == []


def test_failed_scp_never_emits_completion(monkeypatch, tmp_path):
    _mock_stimulus(monkeypatch)
    monkeypatch.setattr(mod.collector, "fetch",
                        lambda **_kw: (_ for _ in ()).throw(RuntimeError("mock SSH failure")))
    events = []
    with pytest.raises(RuntimeError, match="mock SSH failure"):
        mod.run_sequence(**args(tmp_path), execute=True,
                         operator_confirmed_hostonly=True, settle_s=0,
                         progress_sink=events.append)
    states = {(e["stage"], e["status"]) for e in events}
    assert ("red", "completed") in states
    assert ("zeek", "running") in states
    assert ("zeek", "completed") not in states
    assert ("blue", "completed") not in states
    assert ("soc", "skipped") not in states
    _check_common(events)


def test_jsonl_dry_run_cli_emits_progress_and_terminal(tmp_path, capsys):
    options = args(tmp_path)
    argv = [
        "--source-ip", options["source_ip"],
        "--target-ip", options["target_ip"],
        "--cidr", options["cidr"],
        "--scenario", options["scenario_id"],
        "--user", options["username"],
        "--known-hosts", str(options["known_hosts"]),
        "--output-dir", str(options["output_dir"]),
        "--progress-jsonl",
    ]
    assert mod.main(argv) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(lines) == 2
    assert lines[0]["kind"] == "da005_vmware_stepwise_progress_v1"
    assert lines[0]["status"] == "dry_run"
    assert lines[1]["kind"] == "da005_vmware_stepwise_terminal_v1"
    assert lines[1]["status"] == "dry_run"
    assert lines[1]["result"]["network_attempts"] == 0
    assert "traffic" not in lines[1]["result"]
    assert "scope" not in lines[1]["result"]
    assert "192.168." not in json.dumps(lines[1])
    assert str(options["output_dir"]) not in json.dumps(lines[1])


def test_progress_sink_must_be_callable(tmp_path):
    with pytest.raises(ValueError, match="callable"):
        mod.run_sequence(**args(tmp_path), progress_sink=123)
