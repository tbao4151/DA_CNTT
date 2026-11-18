# DA005 — Dual-AI Live Session Foundation (Iteration 1)

This branch adds a bounded synthetic event-stream foundation, NOT deployed attack simulation and NOT Zeek/VMware live detection.

## Implemented

- FastAPI endpoints: POST /api/v1/live-sessions, GET /api/v1/live-sessions/{id}, GET /api/v1/live-sessions/{id}/events (SSE), POST /api/v1/live-sessions/{id}/stop and GET /api/v1/live-sessions/{id}/report.
- Session status/history, max one active session, rounds 1–4, eight retained sessions, cancellation.
- UCB1/random selects OFFLINE CATALOG LABEL ONLY, with no verified Blue Team feedback; no network command is run.
- Zeek sample flow counts from hardcoded SYNTHETIC fixture; no genuine AI predictions or alerts are claimed.
- Next.js route /automated-lab: Red/Blue panels, stream timeline, error states, start/stop, JSON report download, polling fallback.
- Regression tests at tests/test_live_sessions.py.

## How to run on Windows

1. Switch to feature/da005-live-session-foundation and install dependencies if necessary.
2. Open two terminals in repository root, execute .\start_backend.ps1 and .\start_frontend.ps1.
3. Navigate to http://127.0.0.1:3000/automated-lab.
4. Start replay and observe SSE telemetry; optionally stop or export JSON report.

## Verification commands — NOT YET EXECUTED for this branch

- .\.venv\Scripts\python.exe -m pytest -q tests/test_live_sessions.py
- cd frontend ; npm.cmd run typecheck ; npm.cmd run lint ; npm.cmd run build
- Browser QA: responsive desktop/mobile, SSE status, Stop, Export, backend disconnect/reconnect.

## Missing before genuine automatic two-AI demo

1. Verify VMware Host-only isolation, log transport, source integrity and time correlation.
2. Train/validate a Zeek-compatible detector (do not feed Zeek fields directly into UNSW-NB15 RF).
3. Add approved non-destructive test runner with allowlist, rate/time limits and emergency stop.
4. Wire real detection evidence, alert/case creation, verified ground truth and session persistence.
5. Produce Step-by-Step and One-Click workflows from actual observations; PDF reports follow verified measurements.

No real attack, live Zeek test, successful CI run, browser screenshot, or model metric is claimed here.
