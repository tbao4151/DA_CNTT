# DA005 — Windows host-only adapter evidence preflight (offline)

This is a **host-side configuration snapshot and fail-closed preflight**, not proof of VMware Host-only isolation. It does not access guests, inspect the VMware Virtual Network Editor, disable NAT/bridging, change firewall/routes, send traffic, capture packets, authorize experiments, detect attacks or create SOC cases. All output is labeled as host-side only. No network activity is performed.

## On the student's Windows 11 laptop (PowerShell)

Before using any lab traffic, configure the VMware virtual network as **Host-only**, with NAT/bridged connectivity disabled for the selected VMnet; verify each guest has only the approved lab NIC and no egress/default route, and obtain permission for the test scope. These are **manual checks**; the script cannot establish them. Do not run active Red Team operations based only on this report.

From the repository root, choose the **actual** VMware Host-only Windows adapter name and the **actual** approved RFC1918 subnet. Store snapshots outside Git, e.g. `C:\DA005-private\network\`. The directory must already exist. The collector now refuses relative output paths and ordinary resolved output directories inside the Git repository, as well as existing snapshots. Keep the private directory outside Git; inspect junctions/reparse points manually because this path check is not a filesystem security boundary.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/collect_windows_hostonly_snapshot.ps1 `
  -AdapterName 'VMware Network Adapter VMnet1' `
  -OutputPath 'C:\DA005-private\network\host-adapter.json'
```

The collector queries the named Windows host adapter, IPv4 address/prefix, any default route attached to that adapter, and DNS servers; it writes JSON and prints its SHA-256. This file may contain private network information; do not commit it. It does not inspect guests or prove VMware network mode. Record the printed SHA-256 independently and run the offline checker:

```powershell
py -3.12 scripts/check_host_only_preflight.py `
  --snapshot 'C:\DA005-private\network\host-adapter.json' `
  --expected-snapshot-sha256 '<ACTUAL_64_CHAR_SHA256>' `
  --adapter 'VMware Network Adapter VMnet1' `
  --cidr '<ACTUAL_APPROVED_RFC1918_SUBNET>'
```

Success requires an active matching adapter, exactly one IPv4 address in the expected narrow private subnet, and **no default route or DNS servers on that adapter**. Failure is generic and prints no IPs or private file paths. A pass establishes only that the *supplied snapshot* matches these host-side checks. It does **not** independently authenticate the snapshot, confirm that other host adapters cannot route traffic, confirm the VMware Virtual Network Editor settings, check guest NICs, establish physical isolation or grant authorization.

Keep separate screenshots/exports of VMware Virtual Network Editor (Host-only selected, NAT/bridging off), each guest's NIC inventory and route table, a documented approved scope, and a timestamped network topology. Preserve PCAP, Zeek `conn.log`, annotations and hashes privately when experiments are conducted. Recheck after any adapter/VMware change. Never use this snapshot as an operational alert or an attack-detection metric.

Software regression (synthetic host snapshots, not real VMware):

```powershell
py -3.12 -m pytest -q tests/test_host_only_preflight.py
powershell -NoProfile -ExecutionPolicy Bypass -File tests/windows_hostonly_snapshot_smoke.ps1
```

The PowerShell smoke test mocks Windows networking cmdlets; it neither reads a real VMware adapter nor changes network configuration. GitHub CI is not evidence of isolation on the student's laptop.


## Snapshot v2: host adapter IPv6 visibility (31/10/2026)

The read-only PowerShell collector now writes `schema_version=2`, adding
`adapter_ipv6`, `adapter_default_routes_ipv6` and
`adapter_dns_servers_ipv6` for the **selected host adapter**. The offline
checker refuses non-link-local IPv6 addresses (including global and ULA),
IPv6 default routes or IPv6 DNS servers, malformed addresses, duplicates,
and unexpected fields. Windows link-local zone suffixes such as `%11` are
accepted only when numeric. The paired host/guest checker also accepts v2.

Legacy v1 evidence remains readable to avoid breaking old local scripts,
but reports `host_ipv6_screened=false` and null IPv6 conclusions. **Do not
interpret a v1 pass as an IPv6 safety check.** Collect a fresh v2 snapshot
under a new private filename, record its SHA-256 independently, and rerun
host and paired preflights before any authorized activity. Neither v2 nor
passing host/guest snapshots verifies other host adapters, all Linux guest
routes, VMware's actual virtual network mode, authorization, or isolation.
The Windows CI PowerShell smoke uses mocked network cmdlets only.
