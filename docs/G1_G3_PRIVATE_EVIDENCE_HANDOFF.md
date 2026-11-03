# DA005 — G1–G3 private evidence handoff and acceptance gate

Status: **operator checklist only; NOT a completed experiment**. This document does not certify a network, perform a capture, execute Red Team actions, train a model or create a SOC case. Follow [the first Host-only evidence session](FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md) for actual commands and [the scope-screen contract](ZEEK_LAB_SCOPE_CHECK.md) for the limitations of log-only checks.

## Evidence ownership and provenance

Use a unique, private session directory **outside the Git working tree** (for example `C:/DA005-private/session-001/`). Never commit PCAP, raw `conn.log`, screenshots with internal addresses, approval records, private keys, or SQLite cases. Maintain an independently dated notebook with operator, authorization/scope, VM inventory, exact VMnet and CIDR, NICs, routes, capture interface, tool versions, command lines, clock/timezone and original SHA-256 values. A checksum establishes byte integrity after recording, **not authenticity or permission**.

| Gate | Required original evidence (private) | Acceptance decision |
| --- | --- | --- |
| G1: authorization and isolation | Approval and scope; VMware Virtual Network Editor screenshot; NIC configuration of **every** participating VM; host/guest IPv4 and IPv6 routes, policy rules and forwarding checks | Human reviewer confirms all participating NICs are Host-only on approved VMnet, no NAT/bridged/secondary path or external route, and no ambiguous IPv6 egress. Any missing proof = **PENDING**, contradiction = **FAIL/STOP**. |
| G2: original bounded capture | Capture command, selected interface, start/end clock, tool/version, untouched classic PCAP, immediately recorded SHA-256 | Only an approved benign session, owned machines, bounded capture and immutable source. No packet generation by this checklist. A synthetic or downloaded PCAP cannot be relabeled as a new lab capture. |
| G3: Zeek derivation and custody | Original `conn.log`, Zeek version/command, SHA-256 of original PCAP and log, import/chain reports and independently pinned source hashes | Reviewer verifies chain, source hashes and time/IP provenance, and checks log scope against the **actual** approved CIDR. Reports alone cannot prove physical isolation or capture authenticity. |

## Mandatory decision procedure

1. Start with **PENDING** for G1, G2 and G3. Record reviewer and review time separately from machine-produced reports.
2. Review G1 manually **before** generating or capturing any traffic. If any guest has NAT/bridged NIC, ambiguous route/forwarding, unapproved scope, or missing evidence, **STOP**; do not proceed to G2.
3. Capture only approved, non-destructive baseline traffic, then hash and preserve original bytes. Do not edit originals to make a parser or scope check pass.
4. Run existing offline import and verification commands from the linked runbook. Keep generated outputs distinct from original evidence; never use a chain/index report as its own approval or capture-origin proof.
5. Compare the captured endpoints to the authorized CIDR. An out-of-scope address is a stop-and-investigate finding, **not** permission to widen the CIDR.
6. Record G1/G2/G3 as PASS only after human review of all required evidence. Record failures with the exact reason, evidence hash, and corrective action; do not overwrite a prior failed session.
7. Only after G1–G3 review may the group plan G4–G6. Independently labeled ground truth and host-disjoint holdout are still required; a Zeek research score is **not** a confirmed attack alert.

## Private review record template

Copy this into a private notebook (do not commit filled values):

```text
session_id:
operator:
reviewer:
reviewed_at_utc:
authorization_reference_private:
vmnet_and_approved_cidr:
vm_inventory_and_all_nics:
ipv4_ipv6_routes_forwarding_evidence_hashes:
original_pcap_sha256:
original_conn_log_sha256:
zeek_version_and_import_command:
scope_report_sha256:
G1: PENDING | PASS | FAIL
G2: PENDING | PASS | FAIL
G3: PENDING | PASS | FAIL
blocking_findings:
next_action:
```

## Research boundaries

GitHub Actions and synthetic regression tests cannot certify the student's Windows laptop, VMware Host-only isolation, an original PCAP, an independently verified Attack/Normal label, live alert latency, or Precision/Recall/FPR. Keep Dataset Mode UNSW-NB15 results separate from Zeek research experiments. Red Team stays disabled until explicit scope approval and the safe scenario controls are reviewed.
