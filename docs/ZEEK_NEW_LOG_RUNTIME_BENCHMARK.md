# DA005 — Pinned NEW-log offline batch scoring runtime

This optional **read-only software performance** benchmark measures how long
one complete in-memory Zeek NEW-log scoring call takes. It includes scope
validation, Zeek parsing, feature extraction and JSON-model scoring. It
**excludes** reading files, loading the model, declared-partition preflight,
writing JSON, traffic collection, SOC case creation and analyst response.

It is **not detection latency**. Zeek event timestamps do not measure the
time a detector received a flow or when an alert was delivered. Never use the
results to claim end-to-end attack detection, live throughput or SOC response.

## Windows 3.12.9: private reproducible measurement

Preserve the model, original TRAIN/VALIDATION/TEST manifest and every original
capture/annotation, and a genuinely NEW authorized Host-only Zeek conn.log,
all outside Git. Independently record the model/manifest/NEW-log SHA-256
before running; verify VMware network isolation and capture provenance by
separate evidence. Replace all placeholders and the illustrative CIDR:

~~~powershell
py -3.12 scripts/benchmark_zeek_new_log_runtime.py --model "C:/DA005-private/zeek-experiment/model.json" --expected-model-sha256 "<MODEL_SHA256>" --manifest "C:/DA005-private/zeek-experiment/manifest.json" --expected-manifest-sha256 "<MANIFEST_SHA256>" --log "C:/DA005-private/new-capture/conn.log" --expected-log-sha256 "<NEW_LOG_SHA256>" --cidr "192.168.56.0/24" --repetitions 5 --warmup 1
~~~

The CLI prints aggregate JSON to stdout only and refuses to write files.
It checks all declared split captures and normalized flow identities against
the new source before timing. The pinned model, log and manifest must pass
SHA-256 validation. **Every declared TRAIN/VALIDATION/TEST annotation must
also include `labels_sha256` in the manifest**, and the CLI re-reads and
checks those original annotation bytes before measuring. A missing pin or
changed annotation fails closed without producing timing JSON. This aligns
the runtime benchmark input gate with strict NEW-log scoring and SOC triage;
older manifests without per-annotation pins must be updated and the model
recreated or explicitly rebound to the newly pinned manifest through the
documented trusted research workflow. These checks do not authenticate model authorship,
complete partition history, independent labels or physical isolation.

Report the exact Windows version, Python version, CPU, RAM, VM configuration,
Zeek version, original flow count and capture duration, with repeated runs
under a stable load. The report contains per-batch durations (ms), median,
nearest-rank p95 and median batch throughput (flows/s). Default 5 measured
repetitions and 1 untimed warmup; bounds: 1–20 and 0–3 respectively. For
five repetitions, nearest-rank p95 is the maximum, **not** a statistically
stable tail-latency estimate. No per-flow latency or event-to-alert timing is
measured. Do not compare runs with different input sizes or hardware without
normalizing and describing those differences.

Keep the JSON output privately if it is used as a student experiment record.
Synthetic CI timings are runner-dependent and **not** a Windows/VMware result.
Do not tune the model or threshold on this NEW capture.

Software-only regression:

~~~powershell
py -3.12 -m pytest -q tests/test_zeek_new_log_runtime.py
~~~

This does not modify the official UNSW-NB15 benchmark or Red Team safe-off mode.
