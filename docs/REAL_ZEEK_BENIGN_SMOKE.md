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
