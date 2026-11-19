"""Network-free stepwise scenario → Zeek → Blue research orchestration tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_vmware_stepwise as mod


def args(tmp_path):
    known = tmp_path / "known_hosts"
    known.write_text("test key for test only\n", encoding="utf-8")
    return dict(
        source_ip="192.168.77.1",
        target_ip="192.168.77.20",
        cidr="192.168.77.0/24",
        scenario_id="connection_shift",
        username="ubuntu",
        known_hosts=known,
        output_dir=tmp_path,
    )


def test_dry_run_fails_closed_before_ssh_or_network(monkeypatch, tmp_path):
    monkeypatch.setattr(mod.collector, "fetch", lambda **_kw: pytest.fail("No SSH in dry-run"))
    monkeypatch.setattr(mod.stimulus, "send_benign_probe", lambda **_kw: pytest.fail("No traffic in dry-run"))
    r = mod.run_sequence(**args(tmp_path))
    assert r["mode"] == "DRY_RUN_EXECUTION_OFF"
    assert r["traffic"]["network_attempts"] == 0
    assert r["blue_research_scoring_performed"] is False
    assert r["ssh_fetch_performed"] is False


def test_explicit_hostonly_isolation_gate_before_traffic(monkeypatch, tmp_path):
    monkeypatch.setattr(mod.stimulus, "send_benign_probe", lambda **_kw: pytest.fail("Do not probe"))
    with pytest.raises(ValueError, match="confirm"):
        mod.run_sequence(**args(tmp_path), execute=True)


def test_fail_before_network_if_pinned_model_is_bad(monkeypatch, tmp_path):
    opts = args(tmp_path)
    model = tmp_path / "model.json"
    model.write_text("invalid mock model")
    monkeypatch.setattr(mod.blue, "load_pinned_zeek_research_model",
                        lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("model pin mismatch")))
    monkeypatch.setattr(mod.stimulus, "send_benign_probe", lambda **_kw: pytest.fail("Must not send"))
    with pytest.raises(ValueError, match="model pin mismatch"):
        mod.run_sequence(**opts, execute=True, operator_confirmed_hostonly=True,
                         model_path=model, expected_model_sha256="a" * 64)


def test_manual_capture_only_sequencing(monkeypatch, tmp_path):
    opts = args(tmp_path)
    called = []
    def fake_run(**kw):
        called.append(("stimulus", kw["execute"]))
        return {"network_attempts": 2, "private_receipt_filename": "test-receipt.json"}
    def fake_fetch(**kw):
        called.append(("fetch", kw["host"]))
        return {"local_log_filename": "test-zeek.log", "flow_count": 12}
    monkeypatch.setattr(mod.stimulus, "run", fake_run)
    monkeypatch.setattr(mod.collector, "fetch", fake_fetch)
    monkeypatch.setattr(mod.time, "sleep", lambda seconds: called.append(("settle", seconds)))
    r = mod.run_sequence(**opts, execute=True, operator_confirmed_hostonly=True, settle_s=2)
    assert called == [("stimulus", False), ("stimulus", True), ("settle", 2), ("fetch", "192.168.77.20")]
    assert r["traffic_attempts"] == 2
    assert r["captured_log_flow_count"] == 12
    assert r["blue_research_scoring_performed"] is False
    assert r["full_one_click_dual_ai"] is False
    assert r["source_to_log_correlation_verified"] is False


def test_optional_blue_research_is_checked_before_stimulus(monkeypatch, tmp_path):
    opts = args(tmp_path)
    model = tmp_path / "zeek.json"
    model.write_text("test-only fake model")
    order = []
    monkeypatch.setattr(
        mod.blue, "load_pinned_zeek_research_model",
        lambda *_a, **_kw: order.append("validate_model"),
    )
    def fake_run(**kw):
        order.append("stimulus" if kw["execute"] else "dryrun")
        return {"network_attempts": 1, "private_receipt_filename": "traffic.json"}
    def fake_blue(**kwargs):
        order.append("blue")
        assert kwargs["model_path"] == model
        return {"log_file": "zeek.log", "flow_count": 2,
                "report_file": "zeek.research.json", "research_candidate_count": 1}
    monkeypatch.setattr(mod.stimulus, "run", fake_run)
    monkeypatch.setattr(mod.blue, "run_bridge", fake_blue)
    r = mod.run_sequence(**opts, execute=True, operator_confirmed_hostonly=True,
                         model_path=model, expected_model_sha256="a" * 64, settle_s=0)
    assert order == ["dryrun", "validate_model", "stimulus", "blue"]
    assert r["research_candidate_count"] == 1
    assert r["blue_research_scoring_performed"] is True
    assert r["operational_detection_verified"] is False
    assert r["automated_soc_alerts"] is False


@pytest.mark.parametrize("invalid", [
    {"model_path": Path("missing.json")},
    {"expected_model_sha256": "a" * 64},
    {"settle_s": -1},
    {"settle_s": 100},
    {"attempts": 6},
])
def test_invalid_setup_never_sends_network(monkeypatch, tmp_path, invalid):
    monkeypatch.setattr(mod.stimulus, "send_benign_probe", lambda **_kw: pytest.fail("No packet"))
    with pytest.raises((ValueError, OSError)):
        mod.run_sequence(**{**args(tmp_path), **invalid}, execute=True,
                         operator_confirmed_hostonly=True)
