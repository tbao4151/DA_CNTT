"""Regression tests for synthetic replay orchestration.

These tests intentionally assert that no live network execution or AI detection
is claimed by the replay-only session mode.
"""
from __future__ import annotations

import time
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fastapi.testclient import TestClient

from api.main import create_app


def test_start_stream_stop_report_and_fail_closed_contract():
    with TestClient(create_app()) as client:
        assert client.post(
            "/api/v1/live-sessions",
            json={"mode": "vmware_live", "rounds": 1},
        ).status_code == 422
        assert client.post(
            "/api/v1/live-sessions",
            json={"mode": "synthetic_replay", "rounds": 99},
        ).status_code == 422

        started = client.post(
            "/api/v1/live-sessions",
            json={"mode": "synthetic_replay", "rounds": 2, "strategy": "ucb1"},
        )
        assert started.status_code == 201
        body = started.json()
        sid = body["session_id"]
        assert body["status"] == "running"
        assert body["provenance"]["network_execution"] is False
        assert body["provenance"]["ai_detection_executed"] is False

        # Only one active run; avoid concurrent telemetry/test interference.
        concurrent = client.post("/api/v1/live-sessions", json={})
        assert concurrent.status_code == 409

        stopped = client.post(f"/api/v1/live-sessions/{sid}/stop")
        assert stopped.status_code == 200
        assert stopped.json()["status"] == "stopped"

        stream = client.get(f"/api/v1/live-sessions/{sid}/events")
        assert stream.status_code == 200
        assert stream.headers["content-type"].startswith("text/event-stream")
        assert "event: progress" in stream.text
        assert "event: complete" in stream.text

        report = client.get(f"/api/v1/live-sessions/{sid}/report").json()
        assert report["status"] == "stopped"
        assert report["report_kind"] == "synthetic_replay_telemetry_only"
        assert report["verified_detection_metrics"] is None
        assert report["real_network_flows"] == 0
        assert report["verified_ai_alerts"] == 0
        assert client.get("/api/v1/live-sessions/no-such-session").status_code == 404


def test_completed_replay_has_true_provenance_and_all_stages():
    with TestClient(create_app()) as client:
        created = client.post(
            "/api/v1/live-sessions",
            json={"rounds": 1, "strategy": "random"},
        )
        assert created.status_code == 201
        sid = created.json()["session_id"]
        deadline = time.monotonic() + 8
        state = created.json()
        while state["status"] == "running" and time.monotonic() < deadline:
            time.sleep(0.15)
            state = client.get(f"/api/v1/live-sessions/{sid}").json()

        assert state["status"] == "completed"
        assert state["current_round"] == 1
        stages = {ev["stage"] for ev in state["events"]}
        assert {"red", "zeek", "blue", "soc", "system"} <= stages
        assert state["provenance"]["fixture_flows_per_round"] > 0
        assert state["provenance"]["vmware_connected"] is False
        assert state["provenance"]["verified_attack_events"] == 0
        assert state["provenance"]["verified_ai_alerts"] == 0
        assert all(ev["source"] == "synthetic_replay" for ev in state["events"])
        assert client.get(f"/api/v1/live-sessions/{sid}/report").json()[
            "verified_detection_metrics"
        ] is None



def test_stop_during_first_replay_delay_never_emits_later_stages():
    """Stopping after Red selection must not leak Zeek/Blue/SOC events."""
    with TestClient(create_app()) as client:
        created = client.post("/api/v1/live-sessions", json={"rounds": 2})
        assert created.status_code == 201
        sid = created.json()["session_id"]
        deadline = time.monotonic() + 3
        state = created.json()
        while time.monotonic() < deadline:
            state = client.get(f"/api/v1/live-sessions/{sid}").json()
            if any(event["stage"] == "red" for event in state["events"]):
                break
            time.sleep(0.01)
        assert any(event["stage"] == "red" for event in state["events"])
        assert not any(event["stage"] == "zeek" for event in state["events"])
        stopped = client.post(f"/api/v1/live-sessions/{sid}/stop")
        assert stopped.status_code == 200
        assert stopped.json()["status"] == "stopped"
        event_count = stopped.json()["event_count"]
        time.sleep(0.85)
        final = client.get(f"/api/v1/live-sessions/{sid}").json()
        assert final["status"] == "stopped"
        assert final["event_count"] == event_count
        assert not any(
            event["stage"] in {"zeek", "blue", "soc"}
            for event in final["events"]
        )
        assert client.post(f"/api/v1/live-sessions/{sid}/stop").json()["event_count"] == event_count
