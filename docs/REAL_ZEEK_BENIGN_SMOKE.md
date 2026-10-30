# DA005 — Real Zeek binary smoke on a BENIGN synthetic offline PCAP

## Purpose and scientific boundary

This is an **operator-triggered local acceptance check**, not a VMware experiment.
The script creates a deterministic classic Ethernet PCAP containing two benign
IPv4/UDP packets between `192.168.56.10` and `192.168.56.20`. It invokes
the installed **real** `zeek --version` and `zeek -r` executable, then uses the
existing offline importer and verifier. No interface is opened, no packets are
sent, no attacks are executed, and no AI model or SOC database is touched.

The `smoke_report.json` explicitly labels the source
`synthetic_benign_udp_fixture`. A successful check proves only that the
installed local Zeek toolchain processed this fixture into a parseable,
CIDR-bounded `conn.log`, whose **single flow matches the generated fixture's**
source/destination IPs, UDP ports, protocol and first-packet timestamp, and whose bytes were self-consistent at the
time of checking. It **does not** establish VMware isolation, capture
authenticity, attack ground truth, held-out model performance or alert latency.
The report SHA-256 is computed immediately from the report for a consistency
check; it is **not an independently pre-recorded trust anchor**.

## Run on a Linux VM with Zeek installed

From the repository root, with Python 3.12.x and Zeek available on `PATH`:

```bash
zeek --version
mkdir -p "$HOME/da005-private"
python3 scripts/smoke_zeek_offline.py \
  --output-dir "$HOME/da005-private/benign-zeek-smoke-001" \
  --confirm-synthetic-only
```

The output directory must **not already exist**, must be absolute, and must
reside outside the repository. A failure retains partial private evidence
without overwriting or deleting existing files. Do not reuse a directory;
choose a new numbered name for each attempt.

The output directory contains:

- `benign_synthetic.pcap`: synthetic fixture generated locally, not captured.
- `zeek-import/conn.log`: actual Zeek offline output if Zeek succeeded.
- `zeek-import/offline_import_report.json`: importer report and hashes.
- `smoke_report.json`: only after importer, verifier and exact fixture-flow
  checks succeed; includes the reported Zeek version, fixture-flow identity
  and timestamp check flags, and explicit non-claims.

Inspect the generated log and retain terminal output, Zeek version and hashes.
The program does not run Zeek through a shell or use `-i`.

## Automated tests versus real acceptance

```bash
python3 -m pytest -q tests/test_zeek_real_smoke.py
```

These tests validate deterministic PCAP structure, IPv4 checksums, strict
fixture-flow identity/timestamp checks, refusal conditions and orchestration
using a **mocked Zeek subprocess**. Passing
GitHub Actions CI is **not** evidence that a real Zeek binary was executed.
The local command above must be run separately by a student inside the Linux
VM; record its result and Zeek version honestly.

## Next step for genuine research

After configuring and manually verifying VMware Host-only isolation, collect
a separately authorized private PCAP with capture/session/host notes, use
`scripts/import_offline_pcap.py` on that **genuine** PCAP, pin the import
report SHA-256 independently and run the existing provenance/scoring/review
pipeline. Keep synthetic smoke outputs out of any TRAIN/VALIDATION/TEST
experiment and never report them as detected attacks.


## Dedicated GitHub Actions real-binary check (separate from laptop acceptance)

The workflow `.github/workflows/real-zeek-offline-smoke.yml` is designed to run the **official Zeek 9.0.1 Docker image** against the same deterministic benign PCAP on an Ubuntu runner. The container is launched with `--network none`, dropped Linux capabilities, a read-only root filesystem and a writable temporary evidence directory. The host Python verifier checks the **actual Zeek-generated** ASCII `conn.log` against the expected single flow, protocol, addresses, ports, timestamp and private CIDR. It uploads only synthetic fixture evidence with seven-day retention.

This check is distinct from the standard `tests/test_zeek_real_smoke.py` unit tests, which mock Zeek. **Do not claim real-binary CI success before its workflow actually succeeds.** Even if successful, it establishes only Zeek decoding of a benign synthetic fixture on a GitHub-hosted Linux runner, not Windows/VMware acceptance, authentic capture, Host-only isolation, attack labels, model accuracy or SOC latency. The image uses a fixed version tag rather than an immutable digest; the workflow logs the resolved local image ID. Student local execution remains necessary.


### First verified runner result (not student-machine acceptance)

The dedicated workflow [#40765032431](https://github.com/tbao4151/DA_CNTT/actions/runs/40765032431) succeeded with actual **Zeek 9.0.1** in a network-disabled Docker container. Its `conn.log` passed the one-flow fixture identity/timestamp check. The artifact is synthetic-only and retained for seven days. This result does not replace the Linux VMware local acceptance procedure above; no genuine capture or attack detection is established.


## Zeek → lab feature projection smoke (synthetic only)

The same benign offline smoke now checks that the actual Zeek `conn.log`
passes `extract_zeek_feature_rows` with exactly the nine v1 Zeek-lab
features, in the declared order. Source/destination IP, UID, timestamp,
source digest, labels and predicted verdicts are **not** model features.
Optional Zeek measurements remain `None` when absent; they are not
silently replaced by zero. A malformed numeric field, unexpected fixture
flow, or schema mismatch fails the smoke instead of producing a success
report. The CI JSON records schema version/column names and a projection
flag, not a fabricated prediction or metric.

This verifies the **telemetry-to-feature boundary** with a real Zeek binary
in GitHub Actions (when its workflow passes). It does not fit/load an AI
model, emit alerts, create SOC cases, authenticate genuine captures, or
validate student VMware Host-only isolation. Run the local smoke separately
in the Linux VM and keep the synthetic fixture out of research splits.


### Verified real Zeek feature projection on GitHub runner (29 October 2026)

[PR #149](https://github.com/tbao4151/DA_CNTT/pull/149) passed the
[real Zeek 9.0.1 binary check](https://github.com/tbao4151/DA_CNTT/actions/runs/40769267570)
and the [full Python 3.12.9 quality gate](https://github.com/tbao4151/DA_CNTT/actions/runs/40769267520)
(753 passed, 2 skipped, 2 existing warnings). Post-merge
[main CI](https://github.com/tbao4151/DA_CNTT/actions/runs/40769902214)
also passed. The genuine Zeek-generated synthetic `conn.log` was projected
onto **nine Zeek-lab v1 feature columns**, with identity and label fields
excluded; the report records `feature_projection_verified=true`.
This does **not** establish AI inference, true attack labels, a genuine VMware
capture, local Windows acceptance, automatic SOC alerts or detection latency.


## Production offline importer with actual Zeek in CI (PR #151)

The real-Zeek workflow now additionally exercises the **existing production**
`import_offline_pcap` function against the deterministic benign PCAP.
The host Python importer invokes `zeek -r` through a CI-only executable
proxy, which accepts **only** `-r <existing-pcap>` and runs the actual Zeek
9.0.1 binary in a `--network none`, read-only, capability-dropped Docker
container. The importer itself is not monkeypatched. Its resulting
`conn.log` and import report are checked with
`verify_offline_pcap_import` and the exact fixture-to-nine-feature contract.
A second CI report (`ci_importer_real_report.json`) records this result
separately from the earlier direct-binary smoke.

This verifies importer orchestration and offline decoding on a GitHub-hosted
Linux runner **only if the corresponding workflow run succeeds**. The
import-report digest is computed in the same CI run and does not independently
authenticate the PCAP or capture provenance. This does not demonstrate
student-machine acceptance, VMware isolation, real attack ground truth,
model inference, automatic alerting, SOC case creation, or detection latency.
No active Red Team traffic is generated. The local CLI and official
UNSW-NB15 benchmark remain unchanged.


### Verified production importer execution on CI (29 October 2026)

The final [PR #151](https://github.com/tbao4151/DA_CNTT/pull/151)
head passed both the
[actual Zeek 9.0.1 importer workflow](https://github.com/tbao4151/DA_CNTT/actions/runs/40773929990)
and the
[Python 3.12.9 quality gates](https://github.com/tbao4151/DA_CNTT/actions/runs/40773928870)
before merge. The real offline importer generated `conn.log` from the
deterministic synthetic PCAP using the network-disabled container and
passed the offline import verifier plus nine-feature contract.
This is **GitHub Linux CI only**: no student Windows/VMware run, actual
Host-only capture, attack detection, independently labeled evaluation,
AI alert, or SOC case is established.


## Verified real Zeek → pinned research scoring/review CI (29 October 2026)

[PR #153](https://github.com/tbao4151/DA_CNTT/pull/153) extended the
network-disabled real-Zeek workflow with the **existing production**
`score_zeek_new_log.py` and `verify_zeek_new_log_report.py` CLIs.
The final PR head passed [real Zeek CI #40778318436](https://github.com/tbao4151/DA_CNTT/actions/runs/40778318436)
and [Python quality gates #40778318423](https://github.com/tbao4151/DA_CNTT/actions/runs/40778318423)
(764 passed, 2 skipped, 2 existing warnings); post-merge
[main CI #40778687801](https://github.com/tbao4151/DA_CNTT/actions/runs/40778687801)
also passed. The actual Zeek 9.0.1 binary decoded a deterministic benign
synthetic PCAP and the production offline importer generated `conn.log`.
A **CI-only** Logistic Regression fitted on arbitrary synthetic labels was
serialized as a data-only JSON model. The scorer checked SHA-256 pins and
the original PCAP import report, and the independent verifier recomputed
every prediction. Modified probabilities and an invalid model hash were
deliberately rejected. The uploaded CI artifact contains a synthetic-only
summary, not the synthetic model or prediction JSON.

This is a **software integration acceptance**, not evidence of attack
detection. The model was trained on synthetic fixture labels without
independent ground truth; model/report pins were generated in the same CI
run, not independently preregistered. Candidate counts are not accuracy,
and no SOC case or operational alert was generated. Student Windows/VMware
execution, actual Host-only isolation, authorized real capture, independent
labels, held-out evaluation, and event-to-SOC latency remain unverified.
Run the documented local Zeek smoke separately and **never use the CI-only
synthetic model for a research claim or deployment**.


## CI research scoring: PCAP/Zeek time gate before model and manual SOC (30 October 2026)

The real-Zeek workflow's existing `tests/ci_real_zeek_scoring.py` now calls the
opt-in one-second PCAP/Zeek timestamp-presence checker **before** fitting the
CI-only synthetic research model, scoring, report review or manual SQLite case.
It checks the genuine Zeek `conn.log` produced from the deterministic benign
UDP PCAP. A second, in-memory copy shifts the timestamp of **every** PCAP
packet by 120 seconds while leaving five-tuples/payloads unchanged. The
legacy tuple-only check must accept that shifted copy; the timestamp check
must reject it. Neither the shifted copy nor the synthetic model is a lab
capture or a trusted attack detector.

The short-lived `ci_real_zeek_scoring_report.json` records explicit
`pcap_zeek_timestamp_presence_verified_ci_only`,
`shifted_pcap_timestamp_gate_rejected_ci_only` and
`pcap_to_zeek_derivation_proven=false` fields. These claims become verified
**only after exact-head real-Zeek and quality CI succeed**. The CI check does
not change the production scoring or SOC CLI, is not a general-purpose
packet-to-flow derivation proof, and does not attest VMware Host-only
isolation, independently adjudicated labels or detection latency.

On Windows, run `py -3.12 -m pytest -q tests/test_ci_real_zeek_scoring.py`
for synthetic regression. Genuine capture acceptance still requires the
student's private PCAP, matching Zeek log, independent SHA-256 pins, and
manual isolation/clock documentation. Never upload sensitive captures.


## Production timestamp-gated scoring acceptance on real Zeek synthetic output (30 October 2026)

The dedicated network-disabled Real Zeek workflow now also invokes the
**production** `scripts/score_zeek_new_log.py` with
`--require-pcap-zeek-timestamp-corroboration` on the actual Zeek-generated
`conn.log` and deterministic benign synthetic PCAP. It compares the resulting
prediction JSON with the same fixed CI-only model scored through the legacy
(non-temporal) CLI: the optional gate must not alter inference results.

A negative CI fixture shifts every packet timestamp by +120 seconds without
changing packet payloads or five-tuples. A fresh **fabricated CI-only**
import-report copy is re-pinned to the shifted PCAP and unchanged Zeek log.
This intentionally tests the timestamp gate after the existing hash and scope
checks pass; the legacy scorer must accept this self-consistent negative fixture,
while the opt-in production gate must refuse it **without publishing a JSON
prediction**. The negative report is not authentic Zeek provenance and must
never be used as evidence of a real import or attack.

The CI summary records four explicit acceptance flags and
`repinned_negative_import_metadata_authentic=false`. The synthetic model
and all pins are generated in CI. This test is **not** independent ground
truth, student VMware acceptance, attack-detection performance, production
alerting, or a capture-to-SOC latency measurement. The old CLI remains the
default and Dataset Mode is unchanged. The acceptance is a proposed test until
the PR's exact-head real-Zeek workflow and quality CI complete successfully.
