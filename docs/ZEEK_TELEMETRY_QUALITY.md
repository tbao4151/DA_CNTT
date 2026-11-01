# DA005 — Offline Zeek telemetry quality screening

This **read-only, offline** screen helps students inspect whether a privately
captured Zeek ASCII `conn.log` is structurally usable **before independent
annotation**. It does not train AI, generate alerts, create SOC cases, or
authenticate attack labels. It cannot establish that a VM was physically
isolated, that the traffic was genuine, or that a model detects attacks.

## Windows Python 3.12.9

First preserve the original `conn.log` and separately record its SHA-256
using `(Get-FileHash -Algorithm SHA256 "C:\DA005-private\capture-001\conn.log").Hash.ToLowerInvariant()`.
Replace the example RFC1918 CIDR with the actual approved Host-only scope.

```powershell
py -3.12 scripts/inspect_zeek_telemetry_quality.py `
  --log "C:/DA005-private/capture-001/conn.log" `
  --expected-log-sha256 "<INDEPENDENT_LOG_SHA256>" `
  --cidr "192.168.56.0/24" `
  --output "C:/DA005-private/capture-001/quality.json"
```

The report is created **only if the destination does not exist**, outside Git.
It contains source/scope digests, observed event time bounds, aggregate endpoint
counts, four fixed protocol buckets, six optional-feature missing-value counts,
and out-of-order timestamp-pair count. Raw IPs, UIDs, ports, source paths and
free-text service/protocol strings are not exported. Unknown protocols are
counted as `other`; missing Zeek counters remain missing, not zero.

The screen fails closed on changed bytes, invalid Zeek schema, repeated UIDs,
out-of-scope endpoints, malformed feature values, or oversized input (15 MiB).
A short capture, missing measurements, one event timestamp, or nonchronological
log order generates a descriptive warning rather than a fabricated attack
classification. These are **not** model performance or detection-latency metrics.

Preserve the original PCAP, Zeek version, Host-only adapter/routes evidence,
authorization, independently produced labels and split assignments privately.
A passing quality screen is **not** a replacement for the separately pinned
PCAP/import verifier, independent ground-truth review, or host-disjoint holdout.

Synthetic-only regression check:

```powershell
py -3.12 -m pytest -q tests/test_zeek_telemetry_quality.py
```

UNSW-NB15 Dataset Mode and Red Team execution remain unchanged.

## Real-Zeek synthetic CI acceptance (not student capture)

The `real-zeek-offline-smoke.yml` workflow now calls the **production CLI**
against the `conn.log` created by the production offline PCAP importer and
**actual Zeek 9.0.1** running in a network-disabled container. It verifies a
single synthetic UDP flow, nine-feature schema, warning for fewer than 30
flows, absence of detection/isolation claims, and refusal of wrong SHA-256,
wrong CIDR and overwriting an existing report. The original log must remain
byte-identical. On successful runs, the short-lived GitHub Actions artifact
contains `ci_real_zeek_telemetry_quality.json` from this synthetic fixture.

The expected SHA-256 is computed within the **same CI run**, not independently
recorded before capture. CI cannot establish provenance of a student-owned
capture, real VMware Host-only isolation, independent labels, attack detection,
or performance. For real research, follow the private Windows procedure above
with a separately recorded digest and preserve the evidence outside Git.


## Optional Zeek ASCII declared-type verification (29/10/2026)

Real Zeek ASCII `conn.log` normally declares both `#fields` and `#types`.
Use `--require-zeek-types` on the private quality CLI to reject missing,
duplicated, late, mismatched or incompatible declarations **before** accepting
a source for research. It checks the seven required fields and six optional
model-relevant fields, permits unrelated Zeek extension columns, and exports
only aggregate schema counts. It does not infer values, labels, authenticity
or Host-only isolation.

~~~powershell
py -3.12 scripts/inspect_zeek_telemetry_quality.py --log "C:/DA005-private/capture-001/conn.log" --expected-log-sha256 "<PIN>" --cidr "192.168.56.0/24" --require-zeek-types --output "C:/DA005-private/capture-001/typed-quality.json"
~~~

For an experiment manifest, add `--require-zeek-types` and the actual
`--cidr` to both `scripts/evaluate_zeek_lab.py --preflight` and the final
evaluation command. All declared split captures are checked. The existing
parser and `--strict-input-gates` bundle keep their previous behavior unless
this **separate** flag is specified. A forged header can pass this software
check; Zeek execution, independent labels and physical isolation must still
be verified separately.


## Optional operator-declared UTC event-start window (29/10/2026)

For a **single** independently pinned private `conn.log`, the quality CLI can
also check that **every parsed Zeek `ts` (connection start)** falls inside an
operator-declared inclusive UTC window. Supply **both** `--event-start-utc`
and `--event-end-utc` in canonical `YYYY-MM-DDTHH:MM:SSZ` format. The
gate refuses incomplete, ambiguous, invalid, reversed or out-of-window
boundaries **before writing** the quality report. No flags means unchanged
legacy behavior. Use a window recorded separately in the private lab notebook
before examining results; do not widen the window to make a failed capture pass.

~~~powershell
py -3.12 scripts/inspect_zeek_telemetry_quality.py `
  --log "C:/DA005-private/capture-001/conn.log" `
  --expected-log-sha256 "<INDEPENDENT_LOG_SHA256>" `
  --cidr "192.168.56.0/24" `
  --require-zeek-types `
  --event-start-utc "2026-10-29T01:00:00Z" `
  --event-end-utc "2026-10-29T01:15:00Z" `
  --output "C:/DA005-private/capture-001/window-quality.json"
~~~

The timestamps above are **illustrative**, not observations. The JSON records
`operator_event_window_checked` but does **not** publish the operator's
bounds or raw UIDs/IPs. A successful check only constrains timestamps
**declared inside the log**; a forged/replayed log can still pass. It does not
authenticate actual capture start/end, the Windows or VM clock, Host-only
isolation, independent labels, or event-to-alert/SOC latency. Zeek `ts` is
the **connection start time**, not the alert creation time or necessarily the
packet-capture start. Long-lived connections can legitimately start before
a capture window; investigate and document rather than silently modifying
evidence. This gate is currently for the single-log quality CLI, **not** an
experiment-wide manifest constraint.

Synthetic-only regression:

~~~powershell
py -3.12 -m pytest -q tests/test_zeek_event_window.py
~~~


## Shared parser UID uniqueness gate (29/10/2026)

A single offline Zeek `conn.log` is now rejected at the **shared parser** if two
records declare the same `uid`, even when their IP endpoints, ports or timestamps
differ. This prevents ambiguous connection identity from reaching manual SOC
case creation and any downstream quality, research or preview workflow. Reuse
of a five-tuple with a **different** Zeek UID remains valid. Existing CLI flags
and the nine-feature Zeek schema are unchanged. For genuine multi-sensor or
concatenated logs with repeated UIDs, retain the originals and handle source
separation explicitly rather than silently deduplicating or changing UIDs.

Run `py -3.12 -m pytest -q tests/test_zeek_telemetry.py tests/test_zeek_manual_triage.py`
on Windows 11. GitHub synthetic CI verifies the software contract only; it
does not authenticate Zeek capture, Host-only isolation, labels, detection
accuracy or event-to-SOC timing.


## Shared parser Zeek #types ordering consistency (29/10/2026)

The common offline `parse_zeek_conn_log` now rejects a second `#types`
declaration or a `#types` declaration that appears after the first flow row.
Previously a duplicated or late header could be silently accepted by callers
that did not opt in to the declared-type quality screen. Exactly one
well-positioned `#types` header is accepted; omission remains compatible
with existing minimal synthetic fixtures and legacy parser clients. Semantic
field/type matching still requires the **separate** `--require-zeek-types`
quality option, which is recommended for real Zeek evidence. The change does
not assert capture authenticity, isolation, independent labels or attack
detection, and does not create traffic or SOC cases.

On Windows run `py -3.12 -m pytest -q tests/test_zeek_telemetry.py`.

## Shared parser terminal Zeek #close boundary (29/10/2026)

The offline Zeek parser now treats an optional `#close<TAB>...` marker as
terminal. It rejects additional flow rows, headers or comments after the
marker, duplicate close markers, premature/empty close markers, and a second
`#separator` directive. Legacy minimal fixtures without `#close` remain
accepted. This prevents a concatenated or appended log segment from being
silently interpreted as one coherent Zeek source/UID namespace. It does not
authenticate the close timestamp, prove completeness, or establish capture
authenticity, VMware isolation, labels or detection accuracy.

On Windows Python 3.12.9 run
`py -3.12 -m pytest -q tests/test_zeek_telemetry.py tests/test_zeek_manual_triage.py`.
Preserve the original authorized Zeek file and its independently pinned
SHA-256; test malformed copies, not the original evidence.


## Shared parser Zeek close-time consistency (01/11/2026)

The offline shared parser now requires an optional `#close` marker to carry a
calendar-valid `YYYY-MM-DD-HH-MM-SS` timestamp. When `#open` is also declared,
`#close` cannot precede `#open`. A matching or later close is allowed; legacy
minimal logs with no `#open` or `#close` remain supported. This prevents an
invalid or reversed log-boundary timestamp from being silently accepted by
research, quality or manual SOC consumers. The parser does **not** infer
packet-to-alert latency or authenticate the timestamps, Zeek process, PCAP,
clock synchronization, physical Host-only isolation or independent labels.
Do not alter original private evidence to pass the check; investigate a refusal.

On Windows Python 3.12.9 run
`py -3.12 -m pytest -q tests/test_zeek_telemetry.py`.

## Optional Zeek ASCII sentinel and conn-path metadata (29/10/2026)

The shared bounded `conn.log` parser now validates optional Zeek ASCII
`#unset_field`, `#empty_field` and `#path` metadata. If present, they
must occur once before the first flow record and use the standard values
`-`, `(empty)` and `conn`, respectively. Custom sentinel encodings or a
non-`conn` path fail closed rather than silently changing missingness or
log provenance. Minimal legacy fixtures without these headers still parse.

When `#empty_field\t(empty)` is explicitly declared, an encoded
`(empty)` service is decoded as the empty string, distinct from the
`#unset_field\t-` missing service (Python `None`). Without the
declaration, legacy minimal logs retain their original literal values.
The existing strict `--require-zeek-types` check remains separate.
`#set_separator` and `#open` are not authenticated by this change.

Run the synthetic regressions with
`py -3.12 -m pytest -q tests/test_zeek_telemetry.py tests/test_zeek_manual_triage.py`.
A matching metadata header does not prove original PCAP provenance, physical
Host-only isolation, independent attack labels, or model performance.
Do not edit the original lab capture to satisfy this gate.


## Optional Zeek ASCII open/set metadata integrity (29/10/2026)

The shared offline conn.log parser validates optional #set_separator and #open
metadata rather than silently ignoring them. A declared #set_separator must
use the canonical comma and occur only once before #fields. A declared #open
must be unique, precede #fields, and contain a calendar-valid
YYYY-MM-DD-HH-MM-SS timestamp. Malformed, duplicate and late declarations
are rejected before manual SOC case creation. Minimal legacy fixtures
without these headers remain accepted.

This is structural validation of strings in a file, NOT authentication of
the Zeek process, capture start time, VM clocks, Host-only isolation,
attack labels or AI accuracy. Do not infer event-to-alert latency from
#open. Preserve original private PCAP and conn.log with SHA-256 and test
malformed copies rather than editing source evidence.

Windows Python 3.12.9 regression:
py -3.12 -m pytest -q tests/test_zeek_telemetry.py tests/test_zeek_manual_triage.py
