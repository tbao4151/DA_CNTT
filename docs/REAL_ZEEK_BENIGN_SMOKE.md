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
