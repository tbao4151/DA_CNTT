# DA005 — CI-to-lab evidence boundary (04/11/2026)

This is a **verified GitHub snapshot**, not a laptop or VMware experiment. The DA005 faculty title remains unchanged.

## Verified source and checks

- Main merge commit at review: `f6804e8189e6f27d03f4e8003eb745ccfd46404b` (PR #389, strict unknown Zeek control-marker rejection).
- Exact final PR feature commit: `8c84cd3be0374b5e2293f9ae23de281336396e81`.
- GitHub commit-associated pull-request workflow queries returned completed SUCCESS for **Mini-SIEM quality gates**, **Windows offline Zeek contract**, and **Real Zeek offline synthetic smoke** on that feature commit.
- Open PR search at review returned no PRs. The connector's commit-workflow lookup filters to PR-triggered runs, so **post-merge main CI is not certified by this check**.

## What this proves and does not prove

Passing the above tests supports the software regression contract on the feature head: strict Zeek control markers and existing synthetic fixtures. It does **not** prove that a student machine executed Python 3.12.9, that VMware networking is isolated, that a PCAP was captured, or that any flow has independently verified Attack/Normal truth. Do not count these CI runs as G1–G8 PASS or as live detection. Dataset Mode UNSW-NB15 metrics remain historical and separate.

## Required operator handoff (no public uploads)

1. On Windows 11, record `py -3.12 --version`, `git rev-parse HEAD`, and run `py -3.12 -m pytest -q tests/test_zeek_telemetry.py tests/test_zeek_flow_identity_guard.py tests/test_zeek_new_log_runtime.py`. Save the exit code and terminal output privately.
2. Follow `docs/G1_G3_PRIVATE_EVIDENCE_HANDOFF.md`: verify **all** VMware guest NICs, IPv4/IPv6 routes and forwarding plus written authorization before any capture. If ambiguous, stop.
3. In an approved Host-only session, preserve an original bounded benign PCAP and offline Zeek `conn.log`, record tool versions and SHA-256 of both. Never commit raw evidence or private addresses.
4. Independently review G1–G3 evidence. Only then prepare disjoint session/host labeling and holdout for G4–G5, explicit analyst-confirmed case for G6, measured clocks for G7, and non-executing Red policy comparison for G8.

## Next development gate

Build and test a single **offline** Zeek NEW-log → research candidate → explicit analyst confirmation → Unclassified SOC case regression using a synthetic fixture, while preserving distinct evidence provenance and avoiding operational alert claims. Verify the existing entrypoints first to avoid duplicating current tests. Do not merge a new implementation without exact-head required CI and conflict checks.
