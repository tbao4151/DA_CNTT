# Live session frontend provenance guard (2026-11-18)

Scope: frontend-only validation for the existing synthetic SSE foundation. The dashboard rejects session snapshots unless `mode=synthetic_replay`, `provenance.source=hardcoded_synthetic_zeek_fixture`, all execution/VMware/inference flags are false, verified attack/AI alert counts are zero, and every snapshot event is marked `synthetic_replay`. Incoming SSE progress events are likewise rejected when their source differs. A mismatch produces a visible error rather than being presented as genuine lab telemetry.

This is defensive UI contract validation, not cryptographic provenance verification. A malicious server could forge all fields; no original VMware capture, AI inference, independently labeled evaluation, or browser QA is claimed. No backend model or network execution was changed.

Verification required before merge: Next.js TypeScript typecheck/build and manual browser check for start, progress, stop, terminal refresh and JSON export; negative contract test with a deliberately mismatched source in a local development backend. PR #393 must remain separately reviewed and its exact-head CI checked. Streamlit fallback remains untouched.
