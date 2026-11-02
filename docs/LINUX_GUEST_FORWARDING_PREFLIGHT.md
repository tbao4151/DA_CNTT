# DA005 — Pinned Linux guest forwarding sysctl screen (offline)

This **read-only** CLI checks seven explicitly selected forwarding settings in
one operator-provided, independently SHA-256-pinned text snapshot. It neither
runs `sysctl` nor contacts VMware. It supplements, and does not replace,
`LINUX_GUEST_COMBINED_PREFLIGHT.md`.

On the **owned Linux Zeek guest**, determine the real approved Host-only
interface name first. Replace `ens33` below with that interface. Do not
change forwarding settings to force a PASS. In a private directory outside
the Git repository, capture the original stdout **and exit status**:

```bash
mkdir -p "$HOME/da005-private/session-001/network"
sysctl net.ipv4.ip_forward \
  net.ipv4.conf.all.forwarding \
  net.ipv4.conf.default.forwarding \
  net.ipv4.conf.ens33.forwarding \
  net.ipv6.conf.all.forwarding \
  net.ipv6.conf.default.forwarding \
  net.ipv6.conf.ens33.forwarding \
  > "$HOME/da005-private/session-001/network/forwarding.txt"
echo "sysctl exit code: $?"
sha256sum "$HOME/da005-private/session-001/network/forwarding.txt"
```

If `sysctl` fails, a key is unavailable, or a value is nonzero, **stop and
investigate**. Do not fabricate missing keys or edit original evidence. Record
the command, actual interface, capture time, exit code and original SHA-256 in
a separate private notebook before running the verifier. Copy unchanged bytes
to Windows and independently verify the hash again.

On Windows 11, from the repository root:

```powershell
Get-FileHash 'C:/DA005-private/session-001/network/forwarding.txt' -Algorithm SHA256
py -3.12 scripts/check_linux_guest_forwarding_preflight.py `
  --snapshot 'C:/DA005-private/session-001/network/forwarding.txt' `
  --expected-sha256 '<ACTUAL_LOWERCASE_SHA256>' `
  --adapter '<ACTUAL_LINUX_HOST_ONLY_INTERFACE>'
```

A PASS requires **exactly seven distinct keys with value 0**, a matching
SHA-256, an absolute non-symlink file outside the repository, and no extra
lines. The parser accepts Linux `sysctl key = value` output with LF or CRLF.
Exit 1 emits a generic refusal without private paths/IPs. A success JSON
explicitly says `all_interfaces_forwarding_checked=false`,
`live_kernel_state_verified=false` and
`vmware_hostonly_isolation_verified=false`. It does **not** verify other
interfaces, packet forwarding in the live kernel, DNS, firewall, VMnet/NIC
assignments, IPv6 routes, capture authenticity or authorization. The
snapshots are not atomic and can be forged. Independently review all guest
and host interfaces, VMnet modes, firewall, DNS, routing and written scope.

Synthetic regression (not a student laptop or VMware experiment):

```powershell
py -3.12 -m pytest -q tests/test_linux_guest_forwarding_preflight.py
```
