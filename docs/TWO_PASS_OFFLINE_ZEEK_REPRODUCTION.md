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

When a binary pin is supplied, the two-pass runner now passes the verified
resolved **absolute executable path** to each offline importer. The subprocess
uses that path directly with `-r`, rather than looking up `zeek` on PATH
again. Without a pin, the legacy `zeek -r` PATH invocation is unchanged.
Invalid explicit paths are refused before output directory creation. This
closes the PATH re-resolution gap but **does not** eliminate in-place binary
replacement between a checksum check and operating-system execution; it also
does not pin dynamic libraries, plugins or Zeek scripts. Mocked regression
checks validate the exact subprocess argv, not real Zeek execution.

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

## GitHub real-Zeek two-pass CI acceptance (synthetic fixture only)

The `Real Zeek offline synthetic smoke` workflow now **attempts** an
integration check of the production two-pass CLI using the deterministic benign
UDP PCAP and two separate `zeek -r` invocations in a Docker container with
`--network none`. The check first supplies an incorrect Zeek executable
SHA-256 and requires refusal before either output directory exists; it then
runs with a correctly pinned **host-side Docker proxy script**. The pin covers
the proxy script bytes, **not the Zeek executable inside the container**.
The CI assertion checks both independently hashed `conn.log` files, strict
non-UID equality, PCAP tuple presence and explicit false scientific claims.

The workflow uploads `ci_two_pass_real_zeek_report.json` and both private-to-CI
import directories as short-lived synthetic artifacts **only if the CI job
succeeds**. This addition is not considered verified until the exact PR-head
workflow completes successfully. The test does not establish authentic capture
provenance, student VMware isolation, independent attack labels, model
performance, real capture-to-alert latency or Windows laptop acceptance.

## CI container Zeek binary fingerprint gate (pending verification)

The synthetic-only GitHub workflow now records the Docker image ID and the
SHA-256 of the resolved **Zeek executable inside** the network-disabled
container before the first offline import. The host-side proxy still has its
separate SHA-256 pin; the proxy additionally checks the in-container executable
hash immediately before **each** subsequent `zeek -r` invocation. A negative
CI test supplies a deliberately wrong container digest and requires rejection
without a new `conn.log`. The short-lived artifact includes
`zeek_container_binary.sha256`, `zeek_image_id.txt` and JSON reports with
explicit scope flags. These changes require exact-head CI success before being
called verified.

This closes the prior **proxy-only fingerprint gap in CI**, but the container
binary hash is observed at runtime rather than independently trusted, and the
check is not an execution attestation or a defense against every time-of-check
race. Image IDs are local image-content identifiers, not signatures or
independent supply-chain provenance. It does not verify the dynamic libraries,
Zeek scripts, plugins, PCAP origin, VMware isolation or attack ground truth.
The student Linux-VM protocol above remains unchanged; no live traffic is
created.
