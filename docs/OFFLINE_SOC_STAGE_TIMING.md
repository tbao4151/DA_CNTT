# DA005 — Operator-recorded offline SOC stage timing (research only)

This optional read-only checker validates a privately recorded **offline**
stage timeline. It does not read PCAP packets, execute Zeek, score a model,
create an alert, write a SOC case, or measure live packet-to-alert latency.
The timestamp record is supplied by the student; software cannot authenticate
the clocks, event origins, evidence pins or manual case action.

## Capture an actual session on Windows 11

After completing the authorized VMware Host-only evidence runbook and manually
creating a research SOC case, record **UTC timestamps from one documented
operator host clock**, with actual timestamps (not invented examples). Keep
the JSON and the original PCAP, Zeek log, model, research report and exported
SOC case in a private folder outside Git. The five SHA-256 fields below must
refer to original separately retained artifacts; this checker only validates
the *format* of those declared pins, not their underlying bytes.

Use this JSON contract, replacing every placeholder and example timestamp
with the real recorded values:

```json
{
  "record_version": 1,
  "clock_basis": "single_operator_host_utc",
  "timestamps_utc": {
    "capture_completed": "2026-11-02T12:00:00Z",
    "zeek_log_ready": "2026-11-02T12:00:01Z",
    "inference_started": "2026-11-02T12:00:03Z",
    "inference_finished": "2026-11-02T12:00:03.500Z",
    "research_queue_ready": "2026-11-02T12:00:04Z",
    "soc_case_created": "2026-11-02T12:00:09Z"
  },
  "declared_evidence_sha256": {
    "pcap": "<REAL_LOWERCASE_SHA256>",
    "zeek_conn": "<REAL_LOWERCASE_SHA256>",
    "model": "<REAL_LOWERCASE_SHA256>",
    "research_report": "<REAL_LOWERCASE_SHA256>",
    "soc_case_export": "<REAL_LOWERCASE_SHA256>"
  }
}
```

**Example times are illustrative, not a completed experiment.** The clock
basis means every entered timestamp was observed on one host's UTC clock;
if this cannot be established, do not use this record. It does not imply
that VMware guests have synchronized clocks. Record the host clock source,
manual start/stop actions, commands, Zeek version and any uncertainty in a
separate dated notebook. The event timestamp inside a PCAP or Zeek flow is
not interchangeable with the timestamp when capture processing completed.

Record the JSON's own SHA-256 independently and run:

```powershell
Get-FileHash "C:/DA005-private/session-001/offline-timing.json" -Algorithm SHA256
py -3.12 scripts/review_offline_soc_stage_timing.py `
  --record "C:/DA005-private/session-001/offline-timing.json" `
  --expected-record-sha256 "<REAL_TIMING_RECORD_SHA256>"
```

The CLI prints only aggregate stage durations and explicit unverified flags,
not timestamps, private paths, IPs or UIDs. It rejects invalid pins, duplicate
JSON keys, missing/extra stages, non-UTC values, reversed order, and records
spanning more than seven days. Zero-duration stages are allowed (clock
resolution may be insufficient); do not interpret zero as instantaneous AI.

The reported total is **capture completion to manual SOC case creation**,
including analyst waiting. It is not event-to-detection latency, online
throughput, or an automated alert SLA. The tool does not independently verify
any of the five evidence files, capture authenticity, model inference, manual
case creation, or Host-only isolation. Preserve source evidence and separately
validate the complete G1–G8 chain.

Synthetic-only regression on Windows Python 3.12.9:

```powershell
py -3.12 -m pytest -q tests/test_offline_soc_stage_timing.py
```

GitHub Actions passing is not a Windows laptop/VMware experiment. Dataset
Mode UNSW-NB15, model thresholds, SQLite and Red Team execution are unchanged.

## Measured offline software subphases (GitHub feature; not a VMware run)

The existing opt-in flags on the two offline CLIs now emit three additional
**monotonic, same-process** durations after successful publication only:

- `scripts/score_zeek_new_log.py --measure-inference-publication-runtime`:
  `offline_new_log_score_duration_ms` (scope/parser/features/model scoring),
  `offline_new_log_json_serialization_duration_ms`, and
  `offline_new_log_json_publish_duration_ms` (private atomic hard-link).
- `scripts/export_zeek_research_alerts.py --measure-research-export-runtime`:
  `offline_research_queue_recompute_duration_ms` (verified queue construction),
  `offline_research_queue_json_serialization_duration_ms`, and
  `offline_research_queue_json_publish_duration_ms`.

The original total `*_duration_ms` fields remain for compatibility.
All values use `time.perf_counter_ns()`; subphases add to the total within
six-decimal rounding. These are **software processing times** inside each
CLI, not UTC timestamps. Input loading, manifest preflight, packet capture,
Zeek processing, inter-command waiting, analyst decision time and SOC case
creation are excluded. Do **not** add independent process measurements to
claim packet-event-to-alert or end-to-end SOC latency. Capture the command
output and exact input/output hashes privately; no timing is embedded in
pinned prediction/queue JSON, and failed publication emits no timing.

These synthetic-only regressions are already part of the Windows offline CI:
`tests/test_zeek_new_log_scoring_partition_gate.py` and
`tests/test_zeek_research_alert_bundle.py`. Student Windows/VMware results
remain unverified until run with authorized original evidence.
