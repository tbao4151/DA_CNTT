# DA005 — Optional Zeek originator-address split screen

This is an **offline research-input consistency check**, not a sensor, host
identity attestation, traffic generator, attack detector or new model.

## Why this exists

The manifest's `host_group` is an operator-assigned string. Distinct strings
alone do not rule out the **same Zeek originator IP** appearing in TRAIN and
TEST, potentially invalidating a claimed originator-disjoint evaluation.
The optional `--require-originator-ip-disjoint` flag parses each already-pinned
Zeek `conn.log` and refuses any normalized `id.orig_h` appearing in more than
one of TRAIN / VALIDATION / TEST, even when Zeek UIDs, timestamps and declared
`host_group` values differ. The same originator can appear repeatedly
**within** one split. A shared `id.resp_h` server across splits is permitted.

This gate is intentionally **not** included in `--strict-input-gates`: a
small lab can reuse DHCP addresses, NAT gateways or shared clients, and
`id.orig_h` describes a **connection originator**, not a verified physical
host. Those conditions can cause legitimate experiments to be refused. A clean
result does not prove distinct hosts, independent sessions, independent
ground truth or VMware Host-only isolation. Operator must choose an appropriate
split policy **before** viewing final held-out metrics.

## Private Windows preflight

First independently record the manifest, Zeek log and annotation SHA-256,
lab authorization, host-only adapter/routes, clock and capture/session
boundaries. Keep PCAPs, logs, labels and evidence outside public Git.

```powershell
py -3.12 scripts/evaluate_zeek_lab.py `
  --manifest "C:/DA005-private/experiment/manifest.json" `
  --expected-manifest-sha256 "<INDEPENDENT_MANIFEST_SHA256>" `
  --cidr "<ACTUAL_HOST_ONLY_CIDR>" `
  --strict-input-gates `
  --require-originator-ip-disjoint `
  --preflight
```

Only after inspecting the preflight result, reuse the same manifest pin and
flags for `--output` (new private path) or `--trace-output`. If rejected,
review original private source records; **do not relabel hosts, alter Zeek
bytes or move records between splits merely to make a check pass**. Document
NAT/DHCP/shared-server limitations, and if necessary design a different
independently justified holdout.

The aggregate report includes per-split **unique originator counts**, zero
cross-split overlaps on success and explicit `host_identity_verified: false`.
It never exports raw IPs, UIDs, host labels, private paths or reference notes.
No flag means existing CLI behavior is unchanged. This option does not alter
the official UNSW-NB15 benchmark or Red Team network-disabled behavior.

Synthetic software regression (Windows and Ubuntu):

```powershell
py -3.12 -m pytest -q tests/test_zeek_originator_split.py
```

CI passing is not evidence of an authorized VMware capture, scientifically
valid attack labels, attack detection, Precision/Recall/FPR or measured
event-to-alert/SOC timing. Those require independently documented experiments
on the student's Windows 11 / VMware Host-only environment.
