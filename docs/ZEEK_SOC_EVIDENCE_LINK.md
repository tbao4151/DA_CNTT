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

## Optional read-only processing-stage timing (feature PR pending, 29/10/2026)

Append `--timing-json` to the **same pinned, existing-case verification command**
above. On success, stdout contains one aggregate JSON object instead of the
default human-readable summary. It reports monotonic `perf_counter_ns`
processing durations in milliseconds for:

1. Private input path validation and optional offline PCAP import verification.
2. Pinned manifest, annotation, model and NEW-log loading/verification.
3. Declared TRAIN/VALIDATION/TEST partition and flow-identity non-reuse screen.
4. Recomputed offline inference plus **read-only** SQLite SOC evidence-link check.

The `total_processing_ms` interval begins after argument parsing and ends
after the existing case is verified. It includes the file reads and checks
listed above but excludes process startup, argument parsing and stdout JSON
serialization. The last stage may recompute the model/report more than once:
this is **verification overhead**, not a production detector's inference
latency. The tool does **not** time SOC case creation, human investigation,
network capture, Zeek log delivery or an operational alert. It never
calculates delay from Zeek event timestamps, and it creates no case.

Failures emit only the original generic refusal to stderr, with **no partial
timing JSON**. Output excludes private file paths, IP addresses, UIDs and
per-flow predictions; preserve aggregate JSON privately if required for a
student experiment. Results are environment-, workload- and disk-dependent;
repeat on actual authorized Windows/VMware data with CPU, RAM, Zeek version,
capture size and original SHA-256 pins recorded. A synthetic CI pass is
software validation, not a measured student lab run.

Regression:

```powershell
py -3.12 -m pytest -q tests/test_zeek_soc_case_link_cli.py
```

The default CLI output and the existing read-only evidence verifier are
unchanged when `--timing-json` is omitted.


## Pinned research queue at SOC case creation (01/11/2026)

When manual triage uses all three optional research queue inputs
(`--research-alert-bundle`, `--expected-research-alert-bundle-sha256`,
`--research-alert-ref`), the write boundary first reconstructs and verifies
the saved queue from the pinned Zeek/model/manifest evidence. For a **new**
case, the initial SQLite creation audit now records the exact queue SHA-256 and
selected research reference. The strict read-only case-link verifier checks
these two original-audit values against the separately supplied queue pins,
in addition to recomputing the entire queue. It refuses altered, missing or
mismatched bindings without modifying SQLite.

Existing source+UID cases are idempotently reused and their initial audit is
**never rewritten**. If a case was originally created without a queue binding,
the strict queue-aware verifier will refuse it; do not edit its historical
audit to make it pass. Use the legacy verifier without queue flags for that
case, clearly marking that the queue was not bound at creation. The default
creation path without queue inputs and the existing read-only verification
path remain compatible.

A successful strict check supports only *software consistency of the recorded
creation audit*, not cryptographic authenticity of SQLite, historical causation,
operator authorization, independent labels, physical Host-only isolation or
operational AI detection. The new regression cases use synthetic fixtures only.

```powershell
py -3.12 -m pytest -q tests/test_zeek_research_queue_soc_e2e.py tests/test_zeek_soc_evidence_link.py
```
