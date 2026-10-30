# DA005 — Two-pass offline Zeek reproduction (operator-owned PCAP)

This is an **opt-in, local-only** reproducibility experiment, not live monitoring.
The new `scripts/replay_zeek_twice_offline.py` runs the already existing
`import_offline_pcap` function **twice**, each time invoking exactly
`zeek -r <original-pcap>` in a different newly created private directory.
No `zeek -i`, packet generation, Red Team action, model training, attack
classification or SOC write is performed.

## Prerequisites

Use an authorized, independently preserved **classic Ethernet IPv4 TCP/UDP**
PCAP from a demonstrably isolated student-owned lab. The command must be run
in a Linux environment with Zeek installed and discoverable on PATH; Python
3.12 is required. Zeek is not installed by this script. The PCAP must contain
at least one structurally valid packet and be no larger than 64 MiB. The Zeek
ASCII `conn.log` must satisfy the existing 15 MiB/10,000-flow bounded parser,
and all Zeek endpoints must fall inside the explicitly supplied private CIDR.

Record the original PCAP SHA-256 **independently before invoking this script**.
Keep the PCAP, output directories and operator notebook outside the Git
repository. Verify Host-only isolation and authorization manually; the
software cannot prove them.

Example in a private Linux VM:

```bash
sha256sum /home/student/da005-private/owned.pcap
zeek --version
python3 scripts/replay_zeek_twice_offline.py \
  --pcap /home/student/da005-private/owned.pcap \
  --expected-pcap-sha256 '<INDEPENDENT_LOWERCASE_SHA256>' \
  --first-output-dir /home/student/da005-private/zeek-pass-1 \
  --second-output-dir /home/student/da005-private/zeek-pass-2 \
  --cidr 192.168.56.0/24 \
  --confirm-offline-only
```

Both output directories must be **new**, distinct, non-nested, absolute paths
with existing private parents. The tool rejects malformed PCAP framing, bad
independent hash, invalid scope, missing consent, unsafe paths and timeout
values before starting either import. Each pass is bounded to 120 seconds
(default, adjustable with `--timeout-seconds` up to 600). It checks the PCAP
digest after each subprocess, independently checks the generated log hashes,
then compares all raw non-UID Zeek fields as a multiset and checks IPv4 TCP/UDP
five-tuple presence in the original PCAP for **both** logs.

Success (exit 0) emits a single JSON summary with PCAP/log hashes, counts and
explicit `false` scientific claims. Redirect stdout to a **private** report
file if desired; the script itself does not create a combined report. Each
pass also creates its own `offline_import_report.json`. On any failure (exit
2), **no success JSON is emitted** and all existing private partial output
directories/files are retained for manual examination; never silently retry
using those directories. Use two new directory names for a repeat.

The comparison is deliberately strict: raw numeric representation,
`conn_state`, `history`, additional Zeek fields and duplicate multiplicity
must match; Zeek UIDs, row order and `#open`/`#close` timestamps may differ.
Some legitimate differences between runs can therefore cause a refusal.
Unsupported link types, VLAN, IPv6 or fragmented packets also refuse rather
than being treated as successfully corroborated.

## Optional independent Zeek executable fingerprint

For stronger **executable-byte consistency** across both offline passes, record
the SHA-256 of the PATH-selected Zeek executable independently before running.
On Linux, resolve a possible symlink to its actual target first:

```bash
command -v zeek
readlink -f "$(command -v zeek)"
sha256sum "$(readlink -f "$(command -v zeek)")"
```

Append this flag to the existing two-pass command:

```bash
  --expected-zeek-binary-sha256 '<INDEPENDENT_LOWERCASE_ZEEK_BINARY_SHA256>'
```

With the flag, the tool checks the PATH-selected regular executable (maximum
256 MiB) before either import and again after **each** pass. A missing binary,
bad digest, changed binary or changed resolved executable path causes refusal
with no success JSON. Private partial outputs remain untouched. Successful
JSON includes `zeek_binary_sha256_pinned=true` and the pinned digest; the
default backward-compatible mode reports `false` without a binary digest.
No executable path is written to the success JSON.

**Scope limitation:** Pinning executable bytes does not authenticate the
binary's origin, record `zeek --version`, or freeze dynamic libraries, Zeek
scripts, plugins, environment variables or runtime configuration. The report
therefore continues to set `zeek_binary_version_verified=false`. Independently
archive the version output, installed scripts/configuration and environment in
the private lab notebook. Do not call a successful synthetic GitHub test a
real Zeek/VMware experiment.

## Scientific boundaries

Two successful subprocesses and matching logs provide stronger **procedural
reproducibility evidence** than comparing two operator-supplied files, but do
not authenticate the Zeek binary/version/scripts, operator identity, original
capture, packet-to-flow identity, VMware isolation, independent labels or
attack-detection performance. Record Zeek version, installed scripts,
operating system, exact command, source PCAP hash, output hashes, exit codes,
Host-only adapters/routes and operator consent in a separate private notebook.
The output JSON deliberately does not contain IPs, UIDs or payloads.

The current UNSW-NB15 Dataset Mode benchmark is unchanged. Do not interpret
this workflow as live attack detection or an AI evaluation. For a full DA005
research demo, separately collect independently labeled, host/session-disjoint
data and run the existing Blue Team inference/Research Alert/SOC workflow.

Synthetic regression only (does not run a Zeek binary):

```powershell
py -3.12 -m pytest -q tests/test_two_pass_offline_zeek.py
```

Windows 11 may run the test above directly; the actual two-pass import
requires Zeek in a compatible Linux VM or WSL environment. Do not label a
GitHub Actions Windows test as evidence of a real student VMware capture.
