# Cyber Lab Mode — telemetry boundary (offline-first)

## Architecture and current implementation

Dataset Mode is the existing `app.py` + `src/siem_ai/` UNSW-NB15 prototype. It has an offline trained Random Forest, held-out benchmark reports, alert views and SQLite SOC cases. The official UNSW train/test CSVs do not contain original IPs or event timestamps.

Cyber Lab Mode is **not yet a working end-to-end application**. This increment adds only `src/blue_team_ai/zeek.py`, a bounded **offline** reader for Zeek ASCII `conn.log`, plus synthetic regression tests. It does not capture packets, replay traffic, execute Red Team scenarios, classify Zeek flows, create alerts or cases, or expose a Cyber Lab UI. No existing Dataset Mode entry point or model is modified.

Planned boundary: `Host-only VMware lab (student-owned, isolated) -> Zeek conn.log / offline PCAP -> validated telemetry -> separately trained lab-compatible AI -> alert -> SOC evidence/case -> Blue Team UI`. A separate Red Team UI may later select only pre-approved, non-destructive offline replays under explicit operator control, with an allowlist, rate limits and kill switch. None of those active controls is implemented in this increment; lab operation must remain off.

## Offline Zeek contract

The `load_zeek_conn_log(path)` and `parse_zeek_conn_log(data)` functions accept Zeek's ASCII tab-separated `conn.log` with `#separator \\x09`, a `#fields` header, and the required source/destination address, port, UID, timestamp and protocol columns. They reject invalid IPs/ports, malformed numeric fields, bad UTF-8, duplicate/missing headers, mismatched field counts and empty logs. The local file reader is bounded to 15 MiB and 10,000 records. It never opens a socket.

Each event includes `origin=offline_zeek_log`, `source_sha256` of the exact bytes, `event_time_utc` derived from the supplied Zeek `ts`, `uid`, source/destination IP and port, protocol, and optional duration/bytes/packets. Missing optional numeric values are `None`, not zero. These are **claims about the log file contents**, not a claim that a live network was observed or that a label is correct.

**Critical scientific boundary:** Zeek `conn.log` is not feature-equivalent to the 42 UNSW-NB15 model inputs. Never call the existing Random Forest with this event dictionary, and never infer missing UNSW features as zero. A separate validated feature schema, labeled lab dataset, split protocol and trained model are required before Cyber Lab AI alerts can be claimed.

## Repeatable developer checks

From the repository root on Windows with Python 3.12 installed:

```powershell
py -3.12 -m pytest -q tests/test_zeek_telemetry.py
py -3.12 -c "import sys; sys.path.insert(0, 'src'); from blue_team_ai.zeek import load_zeek_conn_log; print(load_zeek_conn_log('PATH_TO_YOUR_OFFLINE_CONN.LOG')[:2])"
```

Use only a `conn.log` collected within a network the group owns or has permission to test. Record the Zeek version, capture time, network isolation settings, source file checksum and original evidence separately. The synthetic test fixture is not a student-operated capture. Do not upload real private IP logs or sensitive payloads to a public repository.

## Next verified milestones

1. Integrate the offline reader into a separately labeled Cyber Lab preview without changing the Dataset Mode benchmark.
2. Build a typed event/evidence store and parser fixtures for real student-owned Zeek logs; confirm schema and timestamps.
3. Train and evaluate a lab-schema model on independently labeled data; report precision/recall/FPR and detection latency with provenance.
4. Only after operator validation of Host-only isolation, add controlled replay orchestration, safety policy and distinct Red/Blue UIs.
