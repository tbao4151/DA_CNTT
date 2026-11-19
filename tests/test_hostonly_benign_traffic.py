"""Network-free safety and event-provenance tests for bounded VMware traffic runner."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_hostonly_benign_traffic as mod


BASE = {
    "source_ip": "192.168.77.1",
    "target_ip": "192.168.77.20",
    "cidr": "192.168.77.0/24",
    "scenario_id": "baseline_web",
}


@pytest.mark.parametrize("source,target,cidr", [
    ("192.168.77.1", "8.8.8.8", "192.168.77.0/24"),
    ("192.168.77.1", "192.168.78.20", "192.168.77.0/24"),
    ("192.168.77.20", "192.168.77.20", "192.168.77.0/24"),
    ("192.168.77.0", "192.168.77.20", "192.168.77.0/24"),
    ("192.168.77.1", "192.168.77.255", "192.168.77.0/24"),
    ("192.168.77.1", "192.168.77.20", "192.168.77.1/24"),
    ("192.168.77.1", "192.168.77.20", "192.168.0.0/16"),
    ("127.0.0.1", "127.0.0.2", "127.0.0.0/24"),
    ("192.168.77.1", "2001:db8::10", "192.168.77.0/24"),
])
def test_fail_closed_scope(source, target, cidr):
    with pytest.raises(ValueError):
        mod.validate_scope(source_ip=source, target_ip=target, cidr=cidr)


def test_dry_run_never_sends_packet_or_creates_receipt(monkeypatch, tmp_path):
    monkeypatch.setattr(mod, "send_benign_probe", lambda **_kwargs: pytest.fail("No network in dry-run"))
    result = mod.run(**BASE, output_dir=tmp_path)
    assert result["mode"] == "DRY_RUN_EXECUTION_OFF"
    assert result["events"] == []
    assert result["network_attempts"] == 0
    assert result["ai_detection_performed"] is False
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("kwargs", [
    {"count": 0},
    {"count": 5},
    {"count": True},
    {"delay_ms": 0},
    {"delay_ms": 400},
    {"delay_ms": 4000},
    {"timeout_s": 4},
    {"scenario_id": "port_scan"},
])
def test_refuse_unsafe_parameters(kwargs):
    with pytest.raises(ValueError):
        mod.run(**{**BASE, **kwargs})


def test_execution_requires_explicit_operator_confirmation_and_receipt_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "send_benign_probe", lambda **_kw: pytest.fail("No packet without full gate"))
    with pytest.raises(ValueError, match="confirmation"):
        mod.run(**BASE, execute=True, output_dir=tmp_path)
    with pytest.raises(ValueError, match="receipt"):
        mod.run(**BASE, execute=True, operator_confirmed_hostonly=True)


def test_exec_records_bounded_attempts_and_never_claims_detection(tmp_path, monkeypatch):
    events = []
    def fake_probe(**kwargs):
        events.append(kwargs)
        return {
            "scenario_id": kwargs["scenario_id"],
            "socket_operation_success": True,
            "network_capture_verified": False,
            "ai_detection_performed": False,
        }
    monkeypatch.setattr(mod, "send_benign_probe", fake_probe)
    monkeypatch.setattr(mod.time, "sleep", lambda _duration: None)
    r = mod.run(
        **BASE, count=3, execute=True, operator_confirmed_hostonly=True, output_dir=tmp_path,
    )
    assert len(events) == 3
    assert all(x["source_ip"] == "192.168.77.1" for x in events)
    assert r["network_attempts"] == 3
    assert r["hostonly_isolation_verified_by_software"] is False
    assert r["attack_executed"] is False
    assert r["ai_detection_performed"] is False
    receipt = tmp_path / r["private_receipt_filename"]
    persisted = json.loads(receipt.read_text(encoding="utf-8"))
    assert persisted["network_attempts"] == 3
    assert persisted["model_metrics_computed"] is False


def test_validated_fixed_dns_query_is_nonrecursive_and_reserved():
    payload = mod._dns_message()
    assert payload[:2] == b"\xda\x05"
    assert payload[2:4] == b"\x00\x00"
    assert payload.count(b"\x07invalid") == 1
    assert b"example.com" not in payload


def test_tcp_handshake_binds_to_pinned_hostonly_source(monkeypatch):
    recorded = []
    class FakeSocket:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass
        def settimeout(self, timeout):
            recorded.append(("timeout", timeout))
        def sendall(self, payload):
            recorded.append(("payload", payload))
        def recv(self, amount):
            return b"HTTP/1.0 200 OK"
    def fake_connect(addr, **kw):
        recorded.append(("connect", addr, kw))
        return FakeSocket()
    monkeypatch.setattr(mod.socket, "create_connection", fake_connect)
    probe = mod.send_benign_probe(
        scenario_id="baseline_web",
        source_ip="192.168.77.1", target_ip="192.168.77.20",
    )
    assert ("connect", ("192.168.77.20", 8080),
            {"timeout": 1.0, "source_address": ("192.168.77.1", 0)}) in recorded
    assert any(step[0] == "payload" and b"HEAD / HTTP/1.0" in step[1] for step in recorded)
    assert probe["socket_operation_success"] is True
    assert probe["network_capture_verified"] is False


def test_dns_mode_binds_and_uses_fixed_guest_port_without_lookup(monkeypatch):
    recorded = []
    class FakeUDP:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass
        def bind(self, address):
            recorded.append(("bind", address))
        def settimeout(self, value):
            recorded.append(("timeout", value))
        def connect(self, address):
            recorded.append(("connect", address))
        def send(self, payload):
            recorded.append(("send", payload))
        def recv(self, _size):
            return b"response"
    monkeypatch.setattr(mod.socket, "socket", lambda *_args: FakeUDP())
    event = mod.send_benign_probe(
        scenario_id="dns_variation", source_ip="192.168.77.1", target_ip="192.168.77.20",
    )
    assert ("bind", ("192.168.77.1", 0)) in recorded
    assert ("connect", ("192.168.77.20", 53)) in recorded
    assert event["socket_operation_success"] is True
    assert event["ai_detection_performed"] is False


def test_no_actual_attacks_implied_by_tcp_or_udp_outcome(monkeypatch):
    def reject(*_args, **_kwargs):
        raise ConnectionRefusedError("private detail")
    monkeypatch.setattr(mod.socket, "create_connection", reject)
    event = mod.send_benign_probe(
        scenario_id="connection_shift", source_ip="192.168.77.1", target_ip="192.168.77.20",
    )
    assert event["socket_error_type"] == "ConnectionRefusedError"
    assert event["socket_operation_success"] is False
    assert event["network_capture_verified"] is False
    assert "private detail" not in json.dumps(event)
