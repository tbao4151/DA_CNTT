"""Bounded, non-executing lab-session event stream.

This is a truthful SYNTHETIC REPLAY foundation for the one-click dashboard.
It never launches attacks, contacts VMware, infers Zeek labels, or claims that
a Blue Team model detected anything. A later verified adapter may supply real
events without changing the session/event contract.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from uuid import uuid4
from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from red_team_ai.scenario_policy import choose_scenario

MAX_SESSIONS = 8


class StartSessionRequest(BaseModel):
    mode: Literal["synthetic_replay"] = "synthetic_replay"
    strategy: Literal["ucb1", "random"] = "ucb1"
    rounds: int = Field(default=2, ge=1, le=4)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_live_router(synthetic_zeek_fixture: bytes) -> APIRouter:
    """Per-app in-memory sessions prevent test clients from sharing state."""
    router = APIRouter(prefix="/api/v1/live-sessions", tags=["Live Lab Sessions"])
    sessions: dict[str, dict] = {}
    tasks: dict[str, asyncio.Task] = {}
    lock = asyncio.Lock()
    fixture_flow_count = sum(
        1 for row in synthetic_zeek_fixture.splitlines()
        if row.strip() and not row.startswith(b"#")
    )

    def get_session(session_id: str) -> dict:
        session = sessions.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="Phiên kiểm thử không tồn tại.")
        return session

    def snapshot(session: dict) -> dict:
        return {
            "session_id": session["session_id"],
            "status": session["status"],
            "mode": session["mode"],
            "strategy": session["strategy"],
            "rounds": session["rounds"],
            "current_round": session["current_round"],
            "started_at": session["started_at"],
            "finished_at": session["finished_at"],
            "event_count": len(session["events"]),
            "events": list(session["events"]),
            "provenance": {
                "source": "hardcoded_synthetic_zeek_fixture",
                "network_execution": False,
                "vmware_connected": False,
                "ai_detection_executed": False,
                "verified_attack_events": 0,
                "verified_ai_alerts": 0,
                "fixture_flows_per_round": fixture_flow_count,
            },
        }

    def emit(session: dict, stage: str, message: str, *, details: dict | None = None) -> None:
        session["events"].append({
            "seq": len(session["events"]) + 1,
            "time": _now(),
            "stage": stage,
            "message": message,
            "details": details or {},
            "source": "synthetic_replay",
        })

    async def run_replay(session: dict) -> None:
        try:
            for round_number in range(1, session["rounds"] + 1):
                if session["status"] != "running":
                    return
                session["current_round"] = round_number
                selection = choose_scenario([], strategy=session["strategy"], seed=42 + round_number)
                emit(
                    session, "red",
                    "Red Team đã chọn NHÃN kịch bản offline; KHÔNG có thực thi mạng.",
                    details={
                        "scenario_id": selection["scenario_id"],
                        "scenario_title": selection["title"],
                        "rationale": selection["rationale"],
                        "feedback_count": 0,
                        "round": round_number,
                        "execution_enabled": False,
                    },
                )
                await asyncio.sleep(0.65)
                if session["status"] != "running":
                    return
                emit(
                    session, "zeek",
                    "Đang phát lại dữ liệu Zeek tổng hợp; KHÔNG phải log VMware trực tiếp.",
                    details={"sample_flow_count": fixture_flow_count, "round": round_number},
                )
                await asyncio.sleep(0.65)
                if session["status"] != "running":
                    return
                emit(
                    session, "blue",
                    "Blue Team chưa chạy suy luận trên Zeek; không phát sinh dự đoán hay cảnh báo.",
                    details={"model_inference": False, "alerts": 0, "round": round_number},
                )
                await asyncio.sleep(0.65)
                if session["status"] != "running":
                    return
                emit(
                    session, "soc",
                    "Lưu trạng thái replay; không tạo SOC case hoặc kết luận tấn công.",
                    details={"verified_cases": 0, "round": round_number},
                )
                await asyncio.sleep(0.4)
                if session["status"] != "running":
                    return
            if session["status"] == "running":
                session["status"] = "completed"
                session["finished_at"] = _now()
                emit(session, "system", "Phiên replay tổng hợp hoàn thành.")
        except asyncio.CancelledError:
            # Stop requests set the terminal status before cancelling the task.
            if session["status"] == "running":
                session["status"] = "stopped"
                session["finished_at"] = _now()
                emit(session, "system", "Phiên replay bị hủy.")
            raise
        except Exception:
            session["status"] = "failed"
            session["finished_at"] = _now()
            emit(session, "system", "Phiên replay gặp lỗi; không có kết quả kiểm thử xác nhận.")

    @router.post("", status_code=201)
    async def start_session(payload: StartSessionRequest):
        async with lock:
            if any(s["status"] == "running" for s in sessions.values()):
                raise HTTPException(status_code=409, detail="Đang có một phiên hoạt động.")
            if len(sessions) >= MAX_SESSIONS:
                # Remove only terminal sessions; never evict a running session.
                oldest_terminal = next(
                    (key for key, val in sessions.items() if val["status"] != "running"), None
                )
                if oldest_terminal is None:
                    raise HTTPException(status_code=429, detail="Đã đạt giới hạn phiên.")
                del sessions[oldest_terminal]
                tasks.pop(oldest_terminal, None)
            session_id = uuid4().hex
            session = {
                "session_id": session_id,
                "mode": payload.mode,
                "strategy": payload.strategy,
                "rounds": payload.rounds,
                "current_round": 0,
                "status": "running",
                "started_at": _now(),
                "finished_at": None,
                "events": [],
            }
            sessions[session_id] = session
            emit(session, "system", "Bắt đầu SYNTHETIC REPLAY · EXECUTION OFF.")
            tasks[session_id] = asyncio.create_task(run_replay(session))
            return snapshot(session)

    @router.get("/{session_id}")
    async def session_status(session_id: str):
        return snapshot(get_session(session_id))

    @router.get("/{session_id}/events")
    async def stream_events(session_id: str):
        session = get_session(session_id)

        async def generate():
            cursor = 0
            while True:
                items = session["events"][cursor:]
                for event in items:
                    cursor += 1
                    yield (
                        f"id: {event['seq']}\n"
                        "event: progress\n"
                        f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                    )
                if session["status"] != "running" and cursor >= len(session["events"]):
                    yield "event: complete\ndata: {}\n\n"
                    return
                await asyncio.sleep(0.2)

        return StreamingResponse(
            generate(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @router.post("/{session_id}/stop")
    async def stop_session(session_id: str):
        session = get_session(session_id)
        if session["status"] == "running":
            session["status"] = "stopped"
            session["finished_at"] = _now()
            emit(session, "system", "Người vận hành đã dừng phiên replay.")
            task = tasks.get(session_id)
            if task:
                task.cancel()
        return snapshot(session)

    @router.get("/{session_id}/report")
    async def get_report(session_id: str):
        session = get_session(session_id)
        return {
            **snapshot(session),
            "report_kind": "synthetic_replay_telemetry_only",
            "verified_detection_metrics": None,
            "real_network_flows": 0,
            "verified_ai_alerts": 0,
            "limitations": [
                "Đây là timeline synthetic replay, không phải tấn công hoặc thu log VMware thật.",
                "Chưa có pipeline inference đã được kiểm chứng cho Zeek conn.log.",
                "UCB1 chưa nhận feedback AI có ground truth: không tuyên bố đã học thích nghi.",
            ],
        }

    return router
