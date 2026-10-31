# DA005 — Pinned offline Windows host/guest configuration pair

This read-only tool compares two **separately pinned original** Windows network
configuration snapshots for an operator-declared VMware Host-only subnet. It
checks each snapshot using the existing host/guest gates, then rejects duplicate
host/guest IPv4 addresses. It does not query VMware, send packets, modify the
guest or establish physical isolation, permission, attack detection or live status.

Collect the host adapter JSON using
`scripts/collect_windows_hostonly_snapshot.ps1` on Windows 11 and the guest
JSON using `scripts/collect_windows_guest_network_snapshot.ps1` inside the
owned Windows guest. Keep both originals **outside the Git repository** and
record their SHA-256 independently before checking. Use absolute file paths.

Example (replace every placeholder with the actual private values):

```powershell
py -3.12 scripts/check_paired_network_preflight.py `
  --host-snapshot 'C:\DA005-private\host.json' `
  --expected-host-sha256 '<INDEPENDENT_HOST_SHA256>' `
  --host-adapter 'VMware Network Adapter VMnet1' `
  --guest-snapshot 'C:\DA005-private\guest.json' `
  --expected-guest-sha256 '<INDEPENDENT_GUEST_SHA256>' `
  --guest-adapter 'Ethernet0' `
  --cidr '192.168.77.0/24'
```

The tool fails closed on duplicate JSON keys, changed/oversized bytes,
symlinks, same-file inputs, non-private paths inside Git, malformed metadata,
wrong CIDRs, DNS/default routes, unexpected guest NICs, global IPv6 and
host/guest IPv4 collision. It prints no original IPs or adapter inventory,
only verification flags and the supplied digests. A passing result means only
that two **operator-supplied snapshots are mutually consistent**. Their
authenticity, completeness, simultaneity, actual VMnet configuration, absence
of unintended egress and authorization remain unverified.

Independently inspect VMware Virtual Network Editor, every NIC and route on
host and guest, NAT/bridging settings and written lab scope. Preserve
screenshots, hashes, PCAP, Zeek conn.log and signed-off scenario records
privately. Do not perform active scenarios until those checks are complete.

Synthetic-only regression (no student VMware evidence):

```powershell
py -3.12 -m pytest -q tests/test_paired_network_preflight.py
```


## Optional strict IPv6 gate for the integrated evidence chain (31/10/2026)

The paired preflight CLI above continues to accept legacy v1 host snapshots for
historical review, but its `host_ipv6_screened=false` output is **not**
IPv6 clearance. For the first authorized evidence session, use the **separate**
`scripts/verify_lab_evidence_chain.py` command with
`--require-host-ipv6-screened` (alongside the existing independent original
pins and PCAP framing flags). That opt-in refuses v1 and requires the v2 host
adapter IPv6 address/default-route/DNS checks to pass. It reports both
`host_ipv6_screened` and `host_ipv6_screening_required`, without exposing
addresses. It is still only a pinned metadata consistency check, not proof of
isolation, authorization, live collection or attack detection.
