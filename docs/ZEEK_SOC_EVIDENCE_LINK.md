# DA005 — Read-only NEW-log SOC evidence link verification

The offline NEW-log path can produce research predictions and, after explicit
analyst approval, an **Unclassified** SQLite SOC case. The helper
`blue_team_ai.soc_evidence_link.verify_new_log_soc_case_link` checks an
existing case against original, SHA-256-pinned Zeek bytes and a separately
pinned research model/report. It does **not** open cases or send traffic.

The helper recomputes the complete prediction report, compares the selected
original Zeek flow with the stored case's feature snapshot and flow digest,
and checks the **first** audit event's source/model/report/scope hashes, UID,
probability and validation threshold. Later analyst state changes are allowed.
It opens the existing SQLite file in read-only mode; missing files are refused
without creating a database. Returned metadata contains hashes and booleans,
not source/destination IPs or raw flow evidence.

This is a **library verification contract**, not a new CLI or UI feature.
A future step may expose it in the SOC interface after integrating the pinned
private manifest and PCAP import checks. The helper does not independently
verify the declared TRAIN/VALIDATION/TEST partition, ground-truth labels,
VMware Host-only isolation, model authorship, attack detection or end-to-end
latency. The initial audit note is stored in a locally mutable SQLite database,
so this check is not a forensic signature or tamper-proof chain of custody.

Run software-only regression tests (synthetic fixtures, not student lab):

```powershell
py -3.12 -m pytest -q tests/test_zeek_soc_evidence_link.py
```

On the student's Windows machine, preserve the original PCAP, Zeek
`conn.log`, model, prediction report, private manifest, annotations, and
independently recorded SHA-256 values outside Git. Record actual network
isolation and timestamps separately. Do not use this check to claim
operational alerts or measured event-to-SOC delay.
