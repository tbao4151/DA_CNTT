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


## Capture genuine offline Blue CLI exit receipts on Windows (optional)

The new `scripts/capture_offline_blue_cli.py` runs **only** the repository's
`score_zeek_new_log.py` or `export_zeek_research_alerts.py` as a Python
subprocess without a shell. It automatically enables the appropriate
`--measure-*` timing flag and records the **actual subprocess exit code**,
original stdout/stderr bytes and SHA-256, command arguments, UTC start/end,
Python version and the published JSON SHA-256 in a private no-overwrite receipt.
A zero exit code alone is insufficient: the documented stage-specific timing
stdout must parse, stderr must be empty and the private output JSON must exist.
Failed/timeout runs retain a receipt with
`successful_offline_timing_trial=false`; they must not enter a benchmark.

Prepare an existing private evidence directory **outside the Git checkout**.
Use the complete pinned CLI options from
[NEW-log scoring](ZEEK_NEW_LOG_OFFLINE_INFERENCE.md) and
[research queue export](ZEEK_RESEARCH_ALERT_BUNDLE.md).
For example, the command form is:

```powershell
py -3.12 scripts/capture_offline_blue_cli.py --stage score `
  --evidence-dir "C:/DA005-private/session-001" --trial-id 001 -- `
  --model "<PRIVATE_MODEL.json>" --expected-model-sha256 "<REAL_PIN>" `
  --log "<PRIVATE_NEW_CONN.log>" --expected-log-sha256 "<REAL_PIN>" `
  --cidr "<AUTHORIZED_HOSTONLY_CIDR>" `
  --output "C:/DA005-private/session-001/score-001.json"
```

For `--stage queue`, pass the **queue CLI's** complete pinned arguments,
including the independently SHA-256-pinned prediction report and declared
TRAIN/VALIDATION/TEST manifest. Use a new `--output` name for every run. The recorder refuses any pre-existing output JSON (including an empty file), so stale results cannot be mistaken for a successful subprocess publication. This is a preflight guard, not an atomic cross-process lock.
The recorder never overwrites existing stdout/stderr/receipt names and never
executes a user-supplied script or shell command. Retain the receipt privately:
`trial-001-score.receipt.json`, alongside `.stdout.txt` and `.stderr.txt`.
The receipt includes private command-line paths and hashes: **do not commit it**.
A timeout is a failed trial, not a timing sample. This wrapper does not
collect packets, execute Red Team scenarios or create SOC cases.

After recording 3–50 genuine paired score/queue runs, independently review
the receipts and use their stdout filenames and SHA-256 in the existing
`runtime-trials.json` manifest below. **The current summary CLI does not
automatically verify receipts or original process exit codes**; the receipt
is an operator-local record, not cryptographic attestation. The external
subprocess wall duration excludes packet-to-alert latency and is not a
substitute for the CLI's internal monotonic phase measurements. CI tests
mock subprocesses; they are not evidence of Windows/VMware execution.

## Repeated paired offline Blue CLI runtime trials (research summary only)

Use the **new read-only** `scripts/summarize_offline_blue_runtime.py` after
the score and research-queue CLIs have completed **successfully** on an
authorized private capture. Collect **3–50 paired trials** (one score and
one queue stdout file per trial), using both opt-in monotonic timing flags
documented above. Each run must have its own **new output JSON name** because
publication intentionally refuses overwrite. Record exact command, exit code,
machine load, Python version, warm/cold state, model/log/manifest/output
SHA-256 and any changed inputs in a separate private notebook. The summary
tool does **not** verify comparability of different trials.

The runtime-summary parser accepts only the two documented CLI success messages,
their fixed explanatory notices, **both mandatory stage-specific bounded nonnegative decimal counters**, and the
expected monotonic timing fields. Score research-candidate count must not exceed
its flow count. Missing counters or impossible candidate/flow counts are refused
rather than accepted as successful trials. It **refuses unexpected stdout text** (including
appended errors, output from the wrong CLI, duplicate counters, and unrecognized
diagnostics) instead of silently treating the file as a successful run. Preserve
the original UTF-8 stdout bytes: do not edit warnings out of a failed command.
The SHA-256 pin authenticates equality to the operator-retained file, **not**
the command exit status or the origin of that file; independently record and
check each actual process exit code before including a trial.

Save each successful CLI stdout in a UTF-8 text file beside the manifest,
outside the Git checkout. For example, capture a command's stdout using
PowerShell redirection to `trial-001-score.txt`; check `$LASTEXITCODE -eq 0`
before including it. Do the same for the research queue CLI and each
additional trial. **Do not fabricate or copy synthetic timing output into a
scientific report.** Compute the SHA-256 of every retained stdout file:

```powershell
Get-FileHash "C:/DA005-private/session-001/trial-001-score.txt" -Algorithm SHA256
Get-FileHash "C:/DA005-private/session-001/trial-001-queue.txt" -Algorithm SHA256
```

Create `runtime-trials.json` in that same private directory. The following
is a **contract example only**, with placeholder hashes and filenames;
repeat the paired object for at least three genuine successful trials:

```json
{
  "version": 1,
  "trials": [
    {
      "score_stdout": "trial-001-score.txt",
      "score_sha256": "<LOWERCASE_SHA256_OF_ORIGINAL_SCORE_STDOUT>",
      "queue_stdout": "trial-001-queue.txt",
      "queue_sha256": "<LOWERCASE_SHA256_OF_ORIGINAL_QUEUE_STDOUT>"
    }
  ]
}
```

The example intentionally has **only one trial** and will be rejected until
at least three distinct pairs are recorded. All names must be simple
Windows-safe basenames: case-insensitive aliases (even if Linux would treat them
as distinct), Windows device names such as CON.txt/NUL/LPT1 and trailing dots
are rejected to prevent one evidence file being counted twice or resolving to
a device on Windows. This does not prove independent command executions.
Absolute paths, traversal, symlinks, duplicate files, oversized
inputs, changed pins, duplicate JSON keys, missing/extra timing fields,
non-monotonic clock declarations and inconsistent phase totals are refused.
The manifest itself must be independently SHA-256 pinned:

```powershell
Get-FileHash "C:/DA005-private/session-001/runtime-trials.json" -Algorithm SHA256
py -3.12 scripts/summarize_offline_blue_runtime.py `
  --manifest "C:/DA005-private/session-001/runtime-trials.json" `
  --expected-manifest-sha256 "<REAL_MANIFEST_SHA256>"
```

On success the CLI prints **aggregate JSON only**: per-stage and per-phase
min/median/mean/nearest-rank p95/max in milliseconds, plus sample count and
explicit unverified scientific flags. It never emits private file names,
source logs, IPs, UIDs or timestamps. Nearest-rank p95 with a small sample
is highly unstable (with three trials it is the maximum); report the sample
count and uncertainty, not just p95. The tool checks the integrity of
operator-supplied stdout bytes, **not** the provenance of PCAP/Zeek, the
original CLI exit status, cross-trial equivalence, ground truth, VMware
isolation, real-time latency or SOC case creation. It cannot establish
packet-to-alert or end-to-end detection performance. No model, Dataset Mode
benchmark, Red Team execution or SQLite data are changed.

Synthetic-only regression (not a student VMware run):

```powershell
py -3.12 -m pytest -q tests/test_offline_blue_runtime_summary.py
```


### Offline CLI notice integrity (synthetic parser contract)

The read-only runtime summary requires exactly one stage-specific safety notice
from each successful score/queue stdout. Optional score provenance notices must
appear in complete two-line pairs (declared partition screening and its caveat;
PCAP/Zeek timestamp presence and its caveat). Duplicate notices, missing mandatory
notices, and unpaired provenance/caveat lines are refused. This prevents a
truncated or selectively edited stdout transcript from being treated as a valid
measurement; it does **not** authenticate the process exit code, command-line
arguments, original capture, or operator-maintained SHA-256 pins.


## Independently pinned paired subprocess receipts (read-only verifier)

After collecting at least three paired score/queue trials with
`scripts/capture_offline_blue_cli.py`, retain all twelve original stdout/stderr
files, six receipt JSON files and six published output JSON files in an
existing private directory **outside the repository**. Do not rename or edit
these files. Prepare a separate UTF-8 receipt manifest in the same directory:

```json
{
  "version": 1,
  "trials": [
    {
      "trial_id": "001",
      "score_receipt": "trial-001-score.receipt.json",
      "score_sha256": "<actual lowercase SHA-256 of score receipt>",
      "queue_receipt": "trial-001-queue.receipt.json",
      "queue_sha256": "<actual lowercase SHA-256 of queue receipt>"
    }
  ]
}
```

The example contains only one pair for readability; **3–50 distinct pairs**
are mandatory. Compute the SHA-256 of the final manifest independently
using `Get-FileHash -Algorithm SHA256`. Run on the **same Windows
checkout** where the recorded CLI script paths and retained output files exist:

```powershell
py -3.12 scripts/verify_offline_blue_receipts.py --manifest "E:\PRIVATE\receipt-manifest.json" --expected-manifest-sha256 "<64 lowercase hex characters>"
py -3.12 -m pytest -q tests/test_offline_blue_receipt_verify.py
```

The verifier checks the independently pinned manifest and receipt bytes,
the actual recorded zero exit codes, stage/trial IDs, fixed allowlisted
script paths, expected timing flag, original stdout/stderr hashes and
lengths, complete stage-specific timing stdout, and the retained published
JSON SHA-256. It never launches a process, writes a case or sends traffic.
It returns **only aggregate verification flags**; private paths, command
arguments, IPs and timestamps remain local. A missing or changed file
fails closed. The separate existing runtime summary still uses its own
pinned stdout manifest; this verifier does not silently convert that
summary into an authenticated benchmark.

**Scientific boundary:** An operator who can rewrite both private
files and their independently supplied hashes can forge a consistent
receipt set. A successful verification is a local consistency check,
not proof of original subprocess identity, independent trial inputs,
VMware Host-only isolation, PCAP authenticity, Attack/Normal labels,
packet-to-alert latency, operational alerts or SOC case creation.
