"""Cooperative STOP guard acceptance (all network and SSH calls mocked)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import run_hostonly_benign_traffic as stimulus
import run_vmware_stepwise as stepwise
from test_vmware_stepwise import args, fake_receipt, fake_raw


BASE = dict(
    source_ip="192.168.77.1", target_ip="192.168.77.20",
    cidr="192.168.77.0/24", scenario_id="connection_shift",
)


def test_probe_stop_present_blocks_first_packet_without_receipt(monkeypatch, tmp_path):
    monkeypatch.setattr(stimulus, "send_benign_probe",
                        lambda **kwargs: pytest.fail("Network attempted with STOP already set"))
    with pytest.raises(stimulus.OperatorStopRequested):
        stimulus.run(**BASE, count=4, execute=True, output_dir=tmp_path,
                     operator_confirmed_hostonly=True, stop_requested=lambda: True)
    assert list(tmp_path.iterdir()) == []


def test_probe_stop_between_attempts_blocks_later_sockets(monkeypatch, tmp_path):
    calls = []
    def fake_send(**kwargs):
        calls.append(kwargs)
        return {"socket_operation_success": True, "network_capture_verified": False}
    monkeypatch.setattr(stimulus, "send_benign_probe", fake_send)
    monkeypatch.setattr(stimulus.time, "sleep", lambda _duration: None)
    with pytest.raises(stimulus.OperatorStopRequested):
        stimulus.run(**BASE, count=4, execute=True, output_dir=tmp_path,
                     operator_confirmed_hostonly=True,
                     stop_requested=lambda: len(calls) >= 1)
    assert len(calls) == 1
    assert list(tmp_path.iterdir()) == []


def test_noncallable_stop_checker_is_refused_before_packet(monkeypatch, tmp_path):
    monkeypatch.setattr(stimulus, "send_benign_probe",
                        lambda **kwargs: pytest.fail("No network allowed"))
    with pytest.raises(ValueError, match="callable"):
        stimulus.run(**BASE, execute=True, output_dir=tmp_path,
                     operator_confirmed_hostonly=True, stop_requested=123)


def test_stepwise_preexisting_stop_blocks_red_zeek_and_soc(monkeypatch, tmp_path):
    opts = args(tmp_path)
    monkeypatch.setattr(stepwise.stimulus, "run",
                        lambda **kwargs: {"network_attempts": 0} if not kwargs["execute"]
                        else pytest.fail("No Red run"))
    monkeypatch.setattr(stepwise.collector, "fetch",
                        lambda **kwargs: pytest.fail("No SSH/SCP"))
    stages = []
    with pytest.raises(stimulus.OperatorStopRequested):
        stepwise.run_sequence(**opts, execute=True, operator_confirmed_hostonly=True,
                              progress_sink=stages.append, stop_requested=lambda: True)
    assert stages == []


def test_stop_after_red_disallows_zeek_scp(monkeypatch, tmp_path):
    opts = args(tmp_path)
    gate = {"stop": False}
    def fake_traffic(**kwargs):
        if kwargs["execute"]:
            gate["stop"] = True
            return fake_receipt()
        return {"network_attempts": 0}
    monkeypatch.setattr(stepwise.stimulus, "run", fake_traffic)
    monkeypatch.setattr(stepwise.collector, "fetch", lambda **kw: pytest.fail("No SCP after STOP"))
    events = []
    with pytest.raises(stimulus.OperatorStopRequested):
        stepwise.run_sequence(**opts, execute=True, operator_confirmed_hostonly=True,
                              settle_s=0, progress_sink=events.append,
                              stop_requested=lambda: gate["stop"])
    states = [(e["stage"], e["status"]) for e in events]
    assert states == [("preflight", "completed"), ("red", "running")]
    assert ("red", "completed") not in states
    assert ("soc", "skipped") not in states


def test_stop_after_zeek_snapshot_blocks_audit_and_soc(monkeypatch, tmp_path):
    opts = args(tmp_path)
    gate = {"stop": False}
    def fake_traffic(**kwargs):
        return fake_receipt() if kwargs["execute"] else {"network_attempts": 0}
    def fake_fetch(**kwargs):
        (tmp_path / "sample.log").write_bytes(fake_raw())
        gate["stop"] = True
        return {"local_log_filename": "sample.log", "flow_count": 2,
                "log_sha256": "f" * 64}
    monkeypatch.setattr(stepwise.stimulus, "run", fake_traffic)
    monkeypatch.setattr(stepwise.collector, "fetch", fake_fetch)
    events = []
    with pytest.raises(stimulus.OperatorStopRequested):
        stepwise.run_sequence(**opts, execute=True, operator_confirmed_hostonly=True,
                              settle_s=0, progress_sink=events.append,
                              stop_requested=lambda: gate["stop"])
    assert ("zeek", "completed") in [(e["stage"], e["status"]) for e in events]
    assert ("audit", "running") not in [(e["stage"], e["status"]) for e in events]
    assert not list(tmp_path.glob("*.candidate-links.json"))


def test_marker_must_be_named_and_share_pinned_private_evidence_folder(tmp_path):
    folder = tmp_path / "captures"
    folder.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    expected = folder / "DA005_STOP.flag"
    check = stepwise._make_stop_checker(expected, folder)
    assert check() is False
    expected.write_bytes(b"")
    assert check() is True
    expected.unlink()
    assert check() is False
    for invalid in (folder / "STOP.flag", other / "DA005_STOP.flag", Path("DA005_STOP.flag")):
        with pytest.raises(ValueError):
            stepwise._make_stop_checker(invalid, folder)
    # The checker must never follow marker symlinks.
    try:
        expected.symlink_to(other / "something")
    except (OSError, NotImplementedError):
        return
    assert check() is True
    with pytest.raises(ValueError, match="STOP marker"):
        stepwise._make_stop_checker(expected, folder)


def test_cli_preexisting_stop_emits_terminal_refusal_not_completion(monkeypatch, tmp_path, capsys):
    opts = args(tmp_path)
    marker = tmp_path / "DA005_STOP.flag"
    marker.write_bytes(b"")
    monkeypatch.setattr(stepwise.stimulus, "send_benign_probe",
                        lambda **kwargs: pytest.fail("No network allowed"))
    monkeypatch.setattr(stepwise.collector, "fetch",
                        lambda **kwargs: pytest.fail("No SCP allowed"))
    argv = [
        "--source-ip", opts["source_ip"], "--target-ip", opts["target_ip"],
        "--cidr", opts["cidr"], "--scenario", opts["scenario_id"],
        "--user", opts["username"], "--known-hosts", str(opts["known_hosts"]),
        "--output-dir", str(opts["output_dir"]),
        "--execute", "--operator-confirmed-hostonly", "--progress-jsonl",
        "--stop-file", str(marker),
    ]
    assert stepwise.main(argv) == 1
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(lines) == 1 and lines[0]["status"] == "refused"
    assert lines[0]["attack_executed"] is False
    assert lines[0]["soc_alerts_created"] is False


def test_keyboard_interrupt_emits_refused_terminal_without_traceback(monkeypatch, tmp_path, capsys):
    opts = args(tmp_path)
    def fake_traffic(**kw):
        if kw["execute"]:
            raise KeyboardInterrupt
        return {"network_attempts": 0}
    monkeypatch.setattr(stepwise.stimulus, "run", fake_traffic)
    argv = [
        "--source-ip", opts["source_ip"], "--target-ip", opts["target_ip"],
        "--cidr", opts["cidr"], "--scenario", opts["scenario_id"],
        "--user", opts["username"], "--known-hosts", str(opts["known_hosts"]),
        "--output-dir", str(opts["output_dir"]),
        "--execute", "--operator-confirmed-hostonly", "--progress-jsonl",
    ]
    assert stepwise.main(argv) != 0
    output = capsys.readouterr()
    rows = [json.loads(line) for line in output.out.splitlines()]
    assert rows[-1]["status"] == "refused"
    assert all(r.get("status") != "completed" or r.get("kind") != stepwise.__name__ for r in rows)
    assert "Traceback" not in output.err
