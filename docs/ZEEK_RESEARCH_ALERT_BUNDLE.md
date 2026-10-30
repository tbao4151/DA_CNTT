# DA005 — Verified offline Zeek research alert-candidate bundle

This is a **research candidate queue**, not operational SIEM alerting or
confirmed attack detection. It bridges the existing pinned Zeek new-log
inference/report review to the **existing explicit manual** SOC triage path.
The CLI writes one private JSON, never a SQLite case or network packet.

From the repository root on Windows 11 with Python 3.12.9, first generate
`new-predictions.json` using `scripts/score_zeek_new_log.py` and its
pinned TRAIN/VALIDATION/TEST manifest gate. Record SHA-256 of all four inputs
**independently** in the private experiment notebook. Then run:

```powershell
py -3.12 scripts/export_zeek_research_alerts.py `
  --model "C:/DA005-private/zeek-experiment/model.json" `
  --expected-model-sha256 "<64 lowercase hex>" `
  --log "C:/DA005-private/new-capture/conn.log" `
  --expected-log-sha256 "<64 lowercase hex>" `
  --report "C:/DA005-private/new-capture/new-predictions.json" `
  --expected-report-sha256 "<64 lowercase hex>" `
  --manifest "C:/DA005-private/zeek-experiment/manifest.json" `
  --expected-manifest-sha256 "<64 lowercase hex>" `
  --cidr "192.168.56.0/24" `
  --output "C:/DA005-private/new-capture/research-alerts.json"
```

Replace the CIDR with the approved RFC1918 VMware Host-only subnet. The
manifest must include `labels_sha256` for every declared TRAIN, VALIDATION
and TEST capture. The exporter re-reads those original captures and labels,
checks model/manifest provenance and screens source and normalized flow
identity non-reuse. It independently verifies the saved prediction JSON by
recomputing **every** score from the pinned model and original log bytes.

The queue preserves the **original zero-based Zeek record index**, UID,
original timestamp/endpoints, research probability and selected validation
threshold, plus source/model/report/manifest hashes. It sorts visible
candidates by probability, with the original index as a deterministic
tie-breaker. `research_alert_ref` uses the existing source+UID research
deduplication namespace, but is **not a SOC case ID**.

Only candidate flows among the **first 500 original rows** are exported:
the current `triage_zeek_new_log.py` manual SOC API intentionally permits
only original indices 0–499. The bundle reports both total candidates and
how many fall outside this window; it never silently renumbers rows. An
analyst may inspect the bundle, then separately run the existing pinned
manual triage command with a chosen original `record_index`, private
SQLite destination and explicit authorization/review/new-capture confirmations.
That operation creates/reuses an **Unclassified** research case, not a
confirmed attack. The exporter itself creates no cases or operational alerts.

Publication uses the existing atomic, no-overwrite same-directory hard-link
writer. The output must be a new JSON file beside the original private log,
outside the public repository. The bundle contains private IPs/UIDs and
must not be uploaded to GitHub. It is not signed evidence. Original PCAP
provenance should be checked separately using the existing offline evidence
chain; this exporter does not claim PCAP provenance.

**Scientific limitations:** operator-declared partition screening cannot
prove the completeness of capture history or authenticity of ground-truth
labels. No physical VMware isolation, genuine attack detection, model
generalization, Precision/Recall/FPR, or event-to-alert-to-SOC latency is
established by synthetic CI. No active Red Team traffic is generated.

Synthetic-only regression:

```powershell
py -3.12 -m pytest -q tests/test_zeek_research_alert_bundle.py
```

On the student Windows laptop, preserve genuine authorized PCAP/Zeek,
model, report, manifest, independent SHA-256 pins, approval and Host-only
configuration privately. Confirm that a selected queue record opens exactly
one Unclassified case through the existing manual SOC workflow and that
a modified input or existing output is refused. Record local results
separately from GitHub CI.


## Optional strict pinned bundle → manual Unclassified SOC handoff (30/10/2026)

The exporter above does not create SOC cases. For one **explicitly selected**
candidate, the existing `scripts/triage_zeek_new_log.py` now accepts a
**three-flag opt-in** pinned bundle gate. This requires the original pinned
TRAIN/VALIDATION/TEST manifest and all original declared captures/labels; the
saved bundle is not trusted merely because its own SHA-256 matches.

First record the bundle SHA-256 independently in the private experiment
notebook (PowerShell `(Get-FileHash ... -Algorithm SHA256).Hash.ToLowerInvariant()`).
Inspect the private bundle and choose its **original** `record_index` and
`research_alert_ref`. Then run, from the repository root:

```powershell
py -3.12 scripts/triage_zeek_new_log.py `
  --model "C:/DA005-private/zeek-experiment/model.json" `
  --expected-model-sha256 "<INDEPENDENT_MODEL_SHA256>" `
  --log "C:/DA005-private/new-capture/conn.log" `
  --expected-log-sha256 "<INDEPENDENT_LOG_SHA256>" `
  --report "C:/DA005-private/new-capture/new-predictions.json" `
  --manifest "C:/DA005-private/zeek-experiment/manifest.json" `
  --expected-manifest-sha256 "<INDEPENDENT_MANIFEST_SHA256>" `
  --cidr "192.168.56.0/24" `
  --record-index <ORIGINAL_ZERO_BASED_INDEX> `
  --db "C:/DA005-private/soc/cyber_lab_cases.sqlite3" `
  --confirm-reviewed --confirm-authorized --confirm-new-capture `
  --research-alert-bundle "C:/DA005-private/new-capture/research-alerts.json" `
  --expected-research-alert-bundle-sha256 "<INDEPENDENT_BUNDLE_SHA256>" `
  --research-alert-ref "<SELECTED_64_CHARACTER_REF>"
```

The database parent directory must already exist and be private. All three
bundle options are required together; listing mode and unpinned-manifest mode
cannot use them. The CLI refuses changed bytes, duplicate JSON keys,
non-finite values, a stale/tampered bundle even when it is re-pinned, and
mismatched selected original row/reference. At the **SOC write boundary** it
rebuilds the entire expected queue from pinned original model, log, prediction
report, declared manifest and original labeled captures. Only then may the
existing manual, idempotent `Unclassified` case be created/reused. The existing canonical SOC creation audit records source/model/report and selected
Zeek UID, not the bundle SHA-256; preserve the independently recorded bundle
pin and chosen reference in the **private experiment notebook**. This keeps
existing strict SOC audit verifiers compatible. Repeated selections reuse the
same source+UID research case.

The legacy manual triage command remains compatible, but does **not** claim
pinned-bundle verification. Existing cases retain their original audit note
when reused; the new bundle pin is not retroactively written. The queue and
SQLite contain private data and must remain outside Git. Synthetic CI cannot
prove VMware isolation, authorization, label correctness, packet-to-Zeek
correspondence, or actual event-to-SOC latency. No operational alert is emitted.

```powershell
py -3.12 -m pytest -q tests/test_zeek_research_alert_bundle.py
```


## Optional local software timing of the manual SOC write boundary

After choosing and independently pinning one candidate as above, append
`--measure-manual-soc-runtime` to the **case-writing** command. This opt-in
prints `offline_manual_soc_handoff_duration_ms` with six decimal places and
an explicit boundary marker. The measurement uses Python's monotonic
`perf_counter_ns` around **one** final call to
`create_new_log_candidate_case`: repeated source/model/report/partition
verification, research queue recomputation when supplied, and SQLite
case creation **or idempotent reuse**. It excludes earlier CLI file reads,
model loading, manifest preflight, the first report review, JSON export,
human analyst decision/wait, packet collection and Zeek processing.
Listing candidates with the timing flag is refused. Failure produces no
duration line, and the flag adds no database fields or extra writes.

A repeated source+UID case can be **reused**, so its timing must not be
compared with first-time case creation without recording that distinction.
The printed value is a local software processing duration, **not** event-to-
detection, capture-to-alert or analyst response latency. Run on the
student's Windows 11 laptop with authorized, independently pinned private
evidence, record CPU/OS/Python/VMware and whether the case already existed,
and preserve stdout privately. Synthetic GitHub CI timing is not a
Windows/VMware measurement. No operational alert or attack ground truth
is established.


## Optional local software timing of verified research queue export

Append `--measure-research-export-runtime` to the **export** command above.
Only after successful publication, the CLI prints
`offline_research_queue_export_duration_ms` with six decimal places and
`offline_research_queue_export_boundary=verified_recompute_json_publish`.
The monotonic `perf_counter_ns` interval begins immediately before the final
`build_verified_research_alert_bundle` call and ends after JSON serialization
and atomic no-overwrite publication. It includes recomputation/verification of
the pinned research queue, JSON serialization and publication. It **excludes**
initial private file reads, model loading, manifest loading and labeled-dataset
construction, capture, Zeek processing, analyst review and SOC case creation.

The duration is printed to stdout only; it is **not** added to the evidence
bundle, so timed and untimed exports of identical inputs remain byte-identical.
Failures (including wrong pins or an existing output) print no duration.
This is an offline software processing measurement, **not** attack detection
latency, end-to-end event-to-alert latency, or a live capture benchmark.
Keep exact local output and machine details privately, and report queue-export
and manual SOC handoff timings as separate stages without adding them as if
they covered all missing pipeline time. Synthetic GitHub CI is not a student
Windows 11/VMware measurement.
