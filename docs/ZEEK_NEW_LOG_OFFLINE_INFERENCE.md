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
physical Host-only isolation have not been verified by CI. Prediction JSON publication now stages UTF-8 bytes in a private temporary file\nin the same directory, flushes them to storage, then uses a no-overwrite\nhard link to expose only the complete file. It never replaces an existing\nreport, including one created concurrently. The staging file is removed on\nordinary success/failure. If the filesystem does not support hard links, the\ncommand fails closed; use a local NTFS directory on Windows rather than\nweakening this guarantee. An abrupt process or power failure may leave a\nprivate hidden staging file; inspect it without treating it as a published\nreport. This is not a cryptographic signature, multi-file transaction or\nguarantee against a malicious administrator.\n\nSynthetic filesystem regression: `py -3.12 -m pytest -q tests/test_zeek_new_log_atomic_output.py`.


## Optional pinned PCAP provenance gate (29/10/2026)

When a new `conn.log` was generated with `scripts/import_offline_pcap.py`,
the scorer can **first** verify the original classic PCAP, Zeek output and
import report against a separately recorded report SHA-256. This is an
opt-in extension of the existing offline CLI; all three new options must
be present together, otherwise scoring refuses to run. It does not run
Zeek, create network traffic or modify existing reports.

After independently recording the SHA-256 of
`offline_import_report.json`, add the following arguments to the existing
`score_zeek_new_log.py` command (retain all the required model, log, CIDR
and output arguments above):

```powershell
  --offline-import-report "C:/DA005-private/capture-001/zeek-run-001/offline_import_report.json" `
  --expected-offline-import-report-sha256 "<64 lowercase hex digits from independent notebook>" `
  --offline-import-pcap "C:/DA005-private/capture-001/input.pcap"
```

The `--log` must point to the original `conn.log` in the same directory
as that import report. The `--cidr` declaration must be identical to the
scope used at import; the scorer checks that its independently pinned log
SHA-256 matches the verified import's Zeek digest. Invalid pins, changed
PCAP/log, missing flags, out-of-scope endpoints or mismatched source bytes
block prediction output. Keep all input files and the resulting prediction
JSON outside the public repository. The existing CLI without these optional
flags remains compatible for new Zeek logs not produced by the PCAP importer.

The prediction JSON schema is **unchanged** so that existing review/triage
tools remain compatible. The PCAP report and independently pinned digest
must be retained separately; the prediction's `source_sha256` links it
to the verified `conn.log`. This is a byte-integrity and scope check,
not proof of PCAP origin, authorized isolation, trusted Zeek execution,
independent attack labels, exclusion from the reserved TEST partition or
real attack detection. No SOC case or operational alert is created.

Synthetic integration regression (the PCAP import fixture mocks Zeek):

```powershell
py -3.12 -m pytest -q tests/test_offline_pcap_scoring_gate.py
```

A student must still execute **real** `zeek -r` on an authorized PCAP
inside a Linux VM, inspect Host-only adapters/routes and retain a signed-off
scenario notebook before interpreting any result as lab evidence.


## Optional pinned TRAIN/VALIDATION/TEST exclusion at the scoring boundary (29/10/2026)

The new-log scoring CLI can now perform the **existing declared partition
non-reuse checks inside the scoring command**, before any prediction JSON is
created. This avoids treating a separately executed preflight as sufficient
evidence for a later scoring operation. Supply **both** additional flags:

```powershell
  --manifest "C:/DA005-private/zeek-experiment/manifest.json" `
  --expected-manifest-sha256 "<independently recorded 64 lowercase hex SHA-256>"
```

This optional gate requires `labels_sha256` in **every** capture entry of the
operator-declared manifest. Preserve those annotation digests independently
before the run. The CLI reopens the original TRAIN/VALIDATION/TEST logs and
labels, checks the manifest digest and labeled dataset contract, verifies that
the model belongs to that manifest, rejects exact-byte reuse of **any** split
(including reserved TEST), and screens normalized UID/time/five-tuple overlap
against all original declared captures. Missing or partial flags, modified
annotations, inconsistent model provenance, or reused flow identities fail
before the output file is created. The model and capture still require their
own independent SHA-256 pins and the declared private CIDR.

The **existing prediction JSON schema remains unchanged**, including
`test_partition_exclusion_verified: false`: the software only checks the
operator-supplied, pinned **declared** partition set, not the completeness or
authenticity of historical captures. Successful CLI output prints a separate
confirmation of this declared screen; it does **not** mean independent history,
ground truth, real detection, Host-only isolation or operational alerts have
been verified. The older CLI invocation without the two flags remains
compatible and performs no declared TEST exclusion check. For research claims,
prefer the pinned mode and retain the private original inputs and lab notebook.

Synthetic-only regression:
`py -3.12 -m pytest -q tests/test_zeek_new_log_scoring_partition_gate.py`.
CI results must not be presented as Windows laptop experiments.
