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
