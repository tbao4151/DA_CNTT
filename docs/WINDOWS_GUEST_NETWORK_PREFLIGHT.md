# DA005 — Windows guest network configuration preflight (offline)

Run the collector **inside a Windows guest VM owned by the student**. It reads local adapter, IPv4/IPv6, route and DNS configuration only. It never sends traffic, changes NIC/firewall/VMware settings, or attests physical isolation. The verifier checks a separately SHA-256-pinned snapshot, not the actual state of the VM at verification time. **Do not use a passing report as authorization to run Red Team scenarios.**

After separately configuring VMware Virtual Network Editor to Host-only, disabling NAT/bridged interfaces for the guest, and recording authorized scope, open PowerShell **inside that guest**. Use an existing private directory outside Git and a new filename:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/collect_windows_guest_network_snapshot.ps1 `
  -OutputPath 'C:\DA005-private\guest-network\guest.json'
```

Copy the collector and checker code into the Windows guest if the repository is not installed there. Record the printed SHA-256 independently. On the guest or on the host, run:

```powershell
py -3.12 scripts/check_guest_network_preflight.py `
  --snapshot 'C:\DA005-private\guest-network\guest.json' `
  --expected-snapshot-sha256 '<INDEPENDENT_64_CHAR_LOWERCASE_SHA256>' `
  --adapter '<ACTUAL_GUEST_NIC_NAME>' `
  --cidr '<ACTUAL_APPROVED_RFC1918_LAB_CIDR>'
```

The checker requires exactly one **Up** adapter, matching its expected name and IPv4 subnet/prefix; other listed adapters must not have IP addresses. It rejects any recorded IPv4/IPv6 default route, any DNS server, any non-link-local IPv6 address, malformed/duplicate JSON keys, changed bytes and oversized input. This is deliberately restrictive: a Windows guest with a normal NAT/default route must fail. A configuration with legitimate lab DNS may also fail and requires separate manual review rather than bypassing the gate. If the guest has IPv6 link-local addresses with scope identifiers, this strict v1 checker refuses them pending explicit normalization review. It does not prove that the collector saw every interface or that VMware settings and the host match the snapshot.

**Independent mandatory checks:** preserve screenshots of VMware Virtual Network Editor, host-side adapter preflight, *every guest* NIC and route table, approved network scope, and evidence of no unintended egress. Repeat after changes. Keep original PCAP, Zeek `conn.log`, private labels, model, manifest and hashes outside Git. Never claim live attack detection, physical isolation or event-to-SOC latency based on this report.

Synthetic-only regression (no VMware):

```powershell
py -3.12 -m pytest -q tests/test_guest_network_preflight.py
pwsh -NoProfile -ExecutionPolicy Bypass -File tests/windows_guest_snapshot_smoke.ps1
```
