"""Network-free stepwise scenario → Zeek → Blue research orchestration tests."""
from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_vmware_stepwise as mod

WHEN = datetime(2026, 11, 19, 5, tzinfo=timezone.utc)


def args(tmp_path):
    known = tmp_path / "known_hosts"
    known.write_text("test key for test only\n", encoding="utf-8")
    return dict(
        source_ip="192.168.77.1", target_ip="192.168.77.20",
        cidr="192.168.77.0/24", scenario_id="connection_shift",
        username="ubuntu", known_hosts=known, output_dir=tmp_path,
    )


def fake_receipt():
    return {
        "kind": "da005_benign_vmware_hostonly_network_stimulus",
        "mode": "BENIGN_LAB_EXECUTION",
        "scenario_id": "connection_shift",
        "scope": {"source_ip": "192.168.77.1", "target_ip": "192.168.77.20",
                  "cidr": "192.168.77.0/24"},
        "network_attempts": 2, "planned_attempts": 2,
        "private_receipt_filename": "traffic.json",
        "events": [
            {"scenario_id": "connection_shift", "protocol": "tcp", "port": 22,
             "attempted_at_utc": WHEN.isoformat()},
            {"scenario_id": "connection_shift", "protocol": "tcp", "port": 22,
             "attempted_at_utc": (WHEN + timedelta(seconds=3)).isoformat()},
        ],
    }


def fake_raw():
    header = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
    lines = [
        f"{time.timestamp():.3f}\t{uid}\t192.168.77.1\t54321\t192.168.77.20\t22\ttcp"
        for time, uid in ((WHEN, "Cone"), (WHEN + timedelta(seconds=3), "Ctwo"))
    ]
    return (header + "\n".join(lines) + "\n").encode("utf-8")


def test_dry_run_fails_closed_before_ssh_or_network(monkeypatch, tmp_path):
    monkeypatch.setattr(mod.collector, "fetch", lambda **_kw: pytest.fail("No SSH in dry-run"))
    monkeypatch.setattr(mod.stimulus, "send_benign_probe",
                        lambda **_kw: pytest.fail("No traffic in dry-run"))
    r = mod.run_sequence(**args(tmp_path))
    assert r["mode"] == "DRY_RUN_EXECUTION_OFF"
    assert r["traffic"]["network_attempts"] == 0
    assert r["blue_research_scoring_performed"] is False
    assert r["ssh_fetch_performed"] is False


def test_explicit_hostonly_isolation_gate_before_traffic(monkeypatch, tmp_path):
    monkeypatch.setattr(mod.stimulus, "send_benign_probe",
                        lambda **_kw: pytest.fail("Do not probe"))
    with pytest.raises(ValueError, match="confirm"):
        mod.run_sequence(**args(tmp_path), execute=True)


def test_fail_before_network_if_pinned_model_is_bad(monkeypatch, tmp_path):
    opts = args(tmp_path)
    model = tmp_path / "model.json"
    model.write_text("invalid mock model")
    monkeypatch.setattr(
        mod.blue, "load_pinned_zeek_research_model",
        lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("model pin mismatch")),
    )
    monkeypatch.setattr(mod.stimulus, "send_benign_probe",
                        lambda **_kw: pytest.fail("Must not send"))
    with pytest.raises(ValueError, match="model pin mismatch"):
        mod.run_sequence(
            **opts, execute=True, operator_confirmed_hostonly=True,
            model_path=model, expected_model_sha256="a" * 64,
        )


def test_manual_capture_only_sequencing(monkeypatch, tmp_path):
    opts = args(tmp_path)
    called = []
    def fake_run(**kw):
        called.append(("stimulus", kw["execute"]))
        return fake_receipt() if kw["execute"] else {"network_attempts": 0}
    def fake_fetch(**kw):
        called.append(("fetch", kw["host"]))
        raw = fake_raw()
        (tmp_path / "test-zeek.log").write_bytes(raw)
        return {
            "local_log_filename": "test-zeek.log",
            "log_sha256": hashlib.sha256(raw).hexdigest(), "flow_count": 2,
        }
    monkeypatch.setattr(mod.stimulus, "run", fake_run)
    monkeypatch.setattr(mod.collector, "fetch", fake_fetch)
    monkeypatch.setattr(mod.time, "sleep",
                        lambda seconds: called.append(("settle", seconds)))
    result = mod.run_sequence(
        **opts, execute=True, operator_confirmed_hostonly=True, settle_s=2,
    )
    assert called == [
        ("stimulus", False), ("stimulus", True),
        ("settle", 2), ("fetch", "192.168.77.20"),
    ]
    assert result["traffic_attempts"] == 2
    assert result["captured_log_flow_count"] == 2
    assert result["candidate_matching_attempts"] == 2
    assert result["unmatched_attempts"] == 0
    assert (tmp_path / result["candidate_links_file"]).exists()
    assert result["blue_research_scoring_performed"] is False
    assert result["full_one_click_dual_ai"] is False
    assert result["source_to_log_correlation_verified"] is False


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
        return fake_receipt() if kw["execute"] else {"network_attempts": 0}
    def fake_blue(**kwargs):
        order.append("blue")
        assert kwargs["model_path"] == model
        raw = fake_raw()
        (tmp_path / "zeek.log").write_bytes(raw)
        return {
            "log_file": "zeek.log", "log_sha256": hashlib.sha256(raw).hexdigest(),
            "flow_count": 2, "report_file": "zeek.research.json",
            "research_candidate_count": 1,
        }
    monkeypatch.setattr(mod.stimulus, "run", fake_run)
    monkeypatch.setattr(mod.blue, "run_bridge", fake_blue)
    result = mod.run_sequence(
        **opts, execute=True, operator_confirmed_hostonly=True,
        model_path=model, expected_model_sha256="a" * 64, settle_s=0,
    )
    assert order == ["dryrun", "validate_model", "stimulus", "blue"]
    assert result["research_candidate_count"] == 1
    assert result["candidate_matching_attempts"] == 2
    assert result["blue_research_scoring_performed"] is True
    assert result["operational_detection_verified"] is False
    assert result["automated_soc_alerts"] is False


def test_mismatched_source_sha_fails_before_candidate_publication(monkeypatch, tmp_path):
    opts = args(tmp_path)
    def fake_run(**kw):
        return fake_receipt() if kw["execute"] else {"network_attempts": 0}
    def fake_fetch(**_kw):
        (tmp_path / "zeek.log").write_bytes(fake_raw())
        return {"local_log_filename": "zeek.log",
                "log_sha256": "f"*64, "flow_count": 2}
    monkeypatch.setattr(mod.stimulus, "run", fake_run)
    monkeypatch.setattr(mod.collector, "fetch", fake_fetch)
    with pytest.raises(ValueError, match="pinned SHA-256"):
        mod.run_sequence(
            **opts, execute=True, operator_confirmed_hostonly=True, settle_s=0,
        )
    assert not list(tmp_path.glob("*.candidate-links.json"))


@pytest.mark.parametrize("invalid", [
    {"model_path": Path("missing.json")},
    {"expected_model_sha256": "a" * 64},
    {"settle_s": -1},
    {"settle_s": 100},
    {"attempts": 6},
])
def test_invalid_setup_never_sends_network(monkeypatch, tmp_path, invalid):
    monkeypatch.setattr(mod.stimulus, "send_benign_probe",
                        lambda **_kw: pytest.fail("No packet"))
    with pytest.raises((ValueError, OSError)):
        mod.run_sequence(
            **{**args(tmp_path), **invalid}, execute=True,
            operator_confirmed_hostonly=True,
        )


def test_stepwise_forwards_operator_private_snapshot_key_without_credential_leak(monkeypatch, tmp_path):
    opts = args(tmp_path)
    identity = tmp_path / "id_ed25519_da005"
    identity.write_text("TEST ONLY KEY", encoding="utf-8")
    snapshot = "/home/ubuntu/da005-private-logs/conn-20261119T161546.log"
    passed = []

    def fake_run(**kwargs):
        return fake_receipt() if kwargs["execute"] else {"network_attempts": 0}

    def fake_fetch(**kwargs):
        passed.append(kwargs)
        raw = fake_raw()
        (tmp_path / "zeek.log").write_bytes(raw)
        return {
            "local_log_filename": "zeek.log",
            "log_sha256": hashlib.sha256(raw).hexdigest(),
            "flow_count": 2,
        }

    monkeypatch.setattr(mod.stimulus, "run", fake_run)
    monkeypatch.setattr(mod.collector, "fetch", fake_fetch)
    report = mod.run_sequence(
        **opts, identity_file=identity, remote_path=snapshot,
        execute=True, operator_confirmed_hostonly=True, settle_s=0,
    )
    assert passed[0]["identity_file"] == identity
    assert passed[0]["remote_path"] == snapshot
    assert report["candidate_matching_attempts"] == 2
    assert report["operational_detection_verified"] is False
    assert report["full_one_click_dual_ai"] is False


def test_stepwise_denies_unsafe_snapshot_before_running_probe(monkeypatch, tmp_path):
    monkeypatch.setattr(
        mod.stimulus, "send_benign_probe",
        lambda **_kw: pytest.fail("No packets for unsafe remote path"),
    )
    with pytest.raises(ValueError, match="not allowlisted"):
        mod.run_sequence(
            **args(tmp_path),
            remote_path="/etc/shadow",
            execute=True,
            operator_confirmed_hostonly=True,
        )
