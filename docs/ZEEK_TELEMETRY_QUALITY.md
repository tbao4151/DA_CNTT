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
