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

The library contract also has an **offline, read-only CLI** that requires a
separately SHA-256-pinned TRAIN/VALIDATION/TEST manifest, every annotation
digest, a pinned model, original Zeek log and research report, and an existing
private SQLite case. It screens declared partition non-reuse and recomputes
the original inference before comparing the stored snapshot and creation audit.
Optional original PCAP import provenance requires all three import options.
The CLI never creates a case, changes SQLite, or emits individual IPs/UIDs.
The underlying library helper does not independently
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


## Strict private CLI (Windows PowerShell)

The case must already exist from the **manual, authorized** NEW-log triage
workflow. Replace every placeholder with independently recorded values.
The private manifest must include `labels_sha256` for every capture.

```powershell
py -3.12 scripts/verify_zeek_soc_case_link.py `
  --model "C:/DA005-private/model.json" `
  --expected-model-sha256 "<PINNED_MODEL_SHA256>" `
  --log "C:/DA005-private/new/conn.log" `
  --expected-log-sha256 "<PINNED_LOG_SHA256>" `
  --report "C:/DA005-private/new/predictions.json" `
  --manifest "C:/DA005-private/experiment/manifest.json" `
  --expected-manifest-sha256 "<PINNED_MANIFEST_SHA256>" `
  --cidr "<HOST_ONLY_CIDR>" `
  --db "C:/DA005-private/soc/cases.sqlite3" `
  --case-id 1 --record-index 0
```

For a separately pinned offline PCAP import, additionally provide
`--offline-import-report`, `--expected-offline-import-report-sha256`
and `--offline-import-pcap` together. A successful check only establishes
consistency with **operator-declared** sources and an editable local SQLite
audit. It does not establish complete capture history, trusted labels,
physical isolation, verified attacks or real event-to-case latency.
No JSON report is written; failures produce a generic message without
private evidence details.

```powershell
py -3.12 -m pytest -q tests/test_zeek_soc_case_link_cli.py
```

## Canonical creation-audit verification (29/10/2026)

The read-only verifier now requires the complete canonical original creation note rather than disconnected substrings. It refuses inserted claims such as verified attack, reordered provenance clauses and trailing text. The strict CLI also compares the stored manifest digest against the independently pinned manifest and (when supplied) import-report/PCAP digests against verified original bytes. Legitimate later analyst updates remain valid.

This is a fail-closed software-consistency check. Older or manually edited noncanonical creation notes may be refused; preserve original evidence rather than rewriting it. SQLite remains mutable, unsigned and unauthenticated. No independent label, isolation, attack detection or latency claim follows. Regression command: py -3.12 -m pytest -q tests/test_zeek_soc_evidence_link.py tests/test_zeek_soc_case_link_cli.py.
