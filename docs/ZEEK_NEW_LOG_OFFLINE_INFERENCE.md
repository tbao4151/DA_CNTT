# DA005 — Offline new-log Zeek research scoring (private, not live)

This feature consumes a **new**, operator-owned Zeek ASCII conn.log that has
not been used in TRAIN, VALIDATION **or the pre-registered held-out TEST**.
It uses the separate Zeek Logistic Regression JSON research artifact; it does
**not** load the UNSW-NB15 Random Forest, retrain, select a threshold, evaluate
ground-truth labels, create SOC cases, or send network traffic.

Prerequisites: Python 3.12.9, installed application dependencies, a JSON model
exported from independent labeled Zeek experiments, its SHA-256 written in a
**separate trusted notebook**, a new Host-only capture and its separately
recorded SHA-256, verified operator authorization and VMware Host-only isolation.
The CLI checks byte integrity and declared RFC1918 scope, but it **cannot**
prove physical isolation, model authorship, genuine ground truth or that the
capture was not previously used as the held-out TEST set.

On Windows, verify the new log digest independently (record the exact digest
and capture session in the private experiment notebook):

```powershell
Get-FileHash "C:\DA005-private\new-capture\conn.log" -Algorithm SHA256
```

Run from the repository root, replacing both placeholder hashes and the
example CIDR with the actual independently recorded values:

```powershell
py -3.12 scripts/score_zeek_new_log.py `
  --model "C:/DA005-private/zeek-experiment/zeek-research-model.json" `
  --expected-model-sha256 "<64 lowercase hex digits from separate record>" `
  --log "C:/DA005-private/new-capture/conn.log" `
  --expected-log-sha256 "<64 lowercase hex digits from separate record>" `
  --cidr "192.168.56.0/24" `
  --output "C:/DA005-private/new-capture/new-predictions.json"
```

The CLI refuses models and captures inside the repository, invalid or changed
hashes, untrusted model schemas, direct symlinks, oversized logs, out-of-scope
IPs, duplicate UIDs, reuse of model TRAIN/VALIDATION source hashes, output
outside the capture's private directory, and existing output files. There is
no implicit fallback to a model without its independently pinned SHA-256.
Input model and capture remain read-only; output is exclusively created.

The private JSON includes source/model SHA-256, a hashed scope declaration,
original Zeek UID, timestamps and endpoints **only as observed in the source
log**, research probabilities, and threshold-based research candidates. It
includes **no ground-truth labels**, accuracy estimates, invented timestamps,
operational alerts or SOC writes. Treat IPs and UIDs as private research data;
never commit this JSON or the original capture to GitHub.

A source hash different from TRAIN/VALIDATION is insufficient to prove the
capture was not the reserved TEST set. This is an explicit operator obligation,
reported as `test_partition_exclusion_verified: false`. Also, SHA-256 checks
byte integrity against the supplied reference, not authorship. These scores
must not be described as verified attack detection or production SIEM alerts.
Model validity and deployment quality still require independently labeled
Host-only experiments, repeatability and false-positive analysis. For a
separate manual analyst-to-SOC review, follow the existing research triage
workflow; this CLI deliberately does not create a case.

CI tests use synthetic Zeek fixtures only. Windows laptop execution and
physical Host-only isolation have not been verified by CI. If output writing
is interrupted, inspect the partial file privately; a rerun must use a new
output filename rather than overwrite evidence.
