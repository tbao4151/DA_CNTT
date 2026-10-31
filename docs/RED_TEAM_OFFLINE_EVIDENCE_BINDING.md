# DA005 — Bind an offline Red Team proposal to private PCAP/Zeek evidence

This is a **read-only, non-executing research handoff**, not a replay tool or
attack. It connects a pending, reproducible UCB1/random **scenario label**
exported from the Red Team Streamlit page to a separately SHA-pinned,
already-existing offline PCAP/Zeek import. It never opens a socket, runs Zeek,
replays packets, writes SOC cases or decides that Blue Team detected anything.

Prerequisites: export the Red Team **timeline JSON** while a proposal is
pending; preserve the original file outside Git. Independently record its
SHA-256 and the SHA-256 of an existing `offline_import_report.json` from the
approved private PCAP -> Zeek import. Manually review the original PCAP,
Zeek conn.log, approved CIDR, scenario relevance, authorization and actual
VMware Host-only isolation. The tool **cannot independently verify** any of
those operator declarations or match packet content to the scenario label.

From the repository root, with Python 3.12.9:

```powershell
py -3.12 scripts/bind_red_team_offline_fixture.py `
  --audit "C:/DA005-private/red-team-audit.json" `
  --expected-audit-sha256 "<INDEPENDENT_AUDIT_SHA256_LOWERCASE>" `
  --report "C:/DA005-private/session-001/zeek-run-001/offline_import_report.json" `
  --expected-report-sha256 "<INDEPENDENT_IMPORT_REPORT_SHA256_LOWERCASE>" `
  --pcap "C:/DA005-private/session-001/original.pcap" `
  --log "C:/DA005-private/session-001/zeek-run-001/conn.log" `
  --cidr "<ACTUAL_APPROVED_HOST_ONLY_CIDR>" `
  --confirm-authorized --confirm-offline-only --confirm-fixture-reviewed
```

The command prints a bounded JSON result to stdout and does not create files.
Save stdout privately only if needed; do not publish IP-bearing originals.
The audit is checked for duplicate keys, SHA mismatch, malformed policy
history, altered summary flags and missing pending proposal. The offline
import is independently rechecked against its pinned report, PCAP packet
framing, Zeek log SHA-256 and declared CIDR. A mismatch fails closed.
The result records the pending proposal ID, strategy, scenario ID and original
hashes without embedding paths, IP addresses or packet contents.

**Interpretation:** the result means only that an operator associated an
unexecuted scenario *label* with software-consistent, private offline evidence.
It does **not** establish scenario-specific traffic, authorized capture,
VMware isolation, attack ground truth, Red Team execution, Blue Team
detection, AI-vs-AI comparison or SOC latency. The planner's manual feedback
remains unverified; never convert it to measured reward. Do not claim a
real student-laptop run from synthetic GitHub CI.

Regression (synthetic bytes, no real Zeek/VMware):

```powershell
py -3.12 -m pytest -q tests/test_red_team_offline_fixture_binding.py
```

Next: collect an actual authorized Host-only capture with independently
reviewed scenario correspondence, predeclare TRAIN/VALIDATION/TEST splits
and evaluate the separate Zeek-schema Blue Team model on held-out labels.
Only then consider an operator-controlled offline replay engine with explicit
scope/rate/kill-switch controls. Active Red Team remains OFF.
