# DA005 — offline Zeek lab-scope screening (research helper)

`check_zeek_lab_scope.py` screens **an already-collected** Zeek ASCII `conn.log` against 1–4 explicit RFC1918 IPv4 lab CIDRs. It performs no packet capture, network connection, replay, Red Team action, model training, AI inference, alerting or SOC writes. A successful result means only that the **addresses written in this log** are within the operator-declared CIDRs. It cannot prove VMware Host-only isolation, authorization, capture authenticity, independent ground truth or attack detection.

## Windows use after an authorized Host-only capture

Keep the original log and all output **outside the Git repository** (for example `D:\DA005-private\`). First inspect VMware virtual network editor, verify every VM adapter uses the intended Host-only virtual network, and retain private screenshots, timestamps, Zeek version, VM inventory and scenario notes. Do not connect test traffic to external networks. Use the exact IPv4 subnet configured in your own lab; the example below is **not** a discovered or verified local subnet.

```powershell
py -3.12 scripts/check_zeek_lab_scope.py `
  --log "D:\DA005-private\capture-01\conn.log" `
  --cidr "192.168.56.0/24" `
  --output "D:\DA005-private\capture-01\scope-report.json"
```

For two separately approved lab subnets, repeat `--cidr`. All source and destination endpoints must belong to at least one declared subnet. Public, IPv6, noncanonical, overly broad (< /16), or out-of-scope CIDRs are refused; an out-of-scope endpoint refuses the **entire** log. Mixed or NAT/internet-connected captures are not suitable for this strict screen. This is intentionally conservative: an out-of-scope address can indicate configuration drift, but may also reflect a legitimate capture detail that needs independent investigation. Do not widen the allowlist merely to make the command pass.

The report is created only if absent, outside the repository. It contains SHA-256 of the original log bytes, SHA-256 of the canonical declared CIDR set, counts of flows and distinct endpoints, first/last **log-declared** UTC timestamps, and explicit `false` flags for unverified isolation/authenticity/authorization/ground truth. It contains **no raw IP, UID, port, or path**. Counts and timestamps may still be sensitive; keep the report private. A matching SHA-256 verifies byte consistency, not the origin or trustworthiness of the log. Do not upload private captures or reports to a public GitHub repository.

Run the source/annotation helper and `evaluate_zeek_lab.py --preflight` only **after** this manual isolation review and independent UID labeling. Those tools validate different properties: the scope screen checks declared address membership; annotation/preflight checks exact UID labels, hashes and host-disjoint split contracts. None of them proves the lab is physically isolated or that AI detects attacks. Retain separate evidence and obtain advisor review before any active Red Team execution.

Developer check (synthetic-only):

```powershell
py -3.12 -m pytest -q tests/test_zeek_lab_scope.py
```
