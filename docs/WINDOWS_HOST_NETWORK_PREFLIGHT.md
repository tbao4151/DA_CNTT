# DA005 — Windows host-only network preflight evidence (read-only)

This helper captures **host Windows network configuration only** before an
authorized VMware Host-only Zeek experiment. It is not a VM configuration
utility, packet capture, isolation test, attack simulator, or AI detector.
It never runs a network probe or changes an adapter, firewall or route.

## On the student's Windows 10/11 laptop

Create a private folder **outside** the repository, e.g.
`C:/DA005-private/capture-001/host-preflight/`. Do not use a shared/public
folder. Run PowerShell from the repository root:

```powershell
New-Item -ItemType Directory -Force "C:/DA005-private/capture-001/host-preflight"
py -3.12 --version
py -3.12 scripts/record_windows_host_network.py `
  --output-dir "C:/DA005-private/capture-001/host-preflight" `
  --confirm-private-evidence
```

The command saves three original command outputs (`ipconfig /all`,
`route print -4`, `netsh interface ipv4 show interfaces`) and a JSON
inventory with their SHA-256 digests. It requires explicit opt-in, an
existing absolute private directory and unused output filenames. It
refuses non-Windows systems, failed/empty/oversized command output, symlink
output directory and in-repository destinations. It does not silently
overwrite previous evidence. Files can contain hostnames, IPs, gateways
and DNS settings; **do not commit or upload them**. Keep the JSON alongside
the original outputs, but record independent hashes in your lab notebook.

## Mandatory manual isolation review (not automated)

1. Open VMware Virtual Network Editor and record the VMnet number,
   Host-only mode, actual subnet/CIDR and whether NAT/bridging is disabled.
2. Inspect **each guest VM**: all virtual network adapters, guest
   `ipconfig`/`ip addr`, IPv4/IPv6 routes and any other physical, NAT,
   bridged, VPN or shared adapter. Capture screenshots privately.
3. Review the host outputs from this helper, matching the VMnet adapter
   to the declared subnet. A host route or a VMnet name alone does **not**
   prove the guests cannot reach outside networks.
4. Confirm authorization and the non-destructive scenario in a dated
   operator notebook. Do not run Red Team active traffic until the
   isolation boundary is independently approved.
5. Capture Zeek `conn.log` from the approved environment, preserve its
   original bytes and independently record its SHA-256. Follow
   [capture evidence inventory](WINDOWS_VMWARE_CAPTURE_EVIDENCE.md)
   for the log, screenshots, Zeek version and scenario notebook.

The helper does **not** inspect guests or validate Host-only isolation.
It does not validate Zeek labels, model quality or event-to-alert latency.
GitHub Actions tests use synthetic mocked Windows command output and do
not count as a real Windows/VMware acceptance run.

```powershell
py -3.12 -m pytest -q tests/test_windows_host_preflight.py
```
