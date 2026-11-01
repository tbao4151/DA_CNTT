# DA005 — Linux Zeek guest Host-only offline configuration screen

This is a **read-only, SHA-256-pinned** screen of three operator-produced
`iproute2` JSON files. It performs no network activity, does not change
interfaces, and does **not** attest VMware isolation or authorization.
It is complementary to the Windows host/guest snapshots and human review.

On the **owned Linux Zeek guest**, before generating any traffic, manually
inspect VMware Virtual Network Editor and all guest NICs. Save the three
original snapshots in a private directory outside the repository:

~~~bash
mkdir -p "$HOME/da005-private/session-001/network"
ip -j address show > "$HOME/da005-private/session-001/network/linux-addresses.json"
ip -j -4 route show > "$HOME/da005-private/session-001/network/linux-routes-v4.json"
ip -j -6 route show > "$HOME/da005-private/session-001/network/linux-routes-v6.json"
sha256sum "$HOME/da005-private/session-001/network/"*.json
ip -j -4 route show table all
ip -j -6 route show table all
cat /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv6/conf/all/forwarding
~~~

The last four commands require **manual** inspection; the verifier reads only
the first three pinned files, representing the main routing table. Check
DNS, IPv4/IPv6 policy-routing tables, forwarding, NAT/bridged NICs and
VMware VMnet separately. Record the hashes independently in a dated notebook,
then copy the unchanged JSON files to a private Windows directory if desired.

From the repository root on Windows Python 3.12.9 (or Linux Python 3.12):

~~~powershell
py -3.12 scripts/check_linux_guest_network_preflight.py `
  --addresses 'C:/DA005-private/session-001/network/linux-addresses.json' `
  --expected-addresses-sha256 '<INDEPENDENT_LOWERCASE_SHA256>' `
  --routes-v4 'C:/DA005-private/session-001/network/linux-routes-v4.json' `
  --expected-routes-v4-sha256 '<INDEPENDENT_LOWERCASE_SHA256>' `
  --routes-v6 'C:/DA005-private/session-001/network/linux-routes-v6.json' `
  --expected-routes-v6-sha256 '<INDEPENDENT_LOWERCASE_SHA256>' `
  --adapter '<ACTUAL_LINUX_HOSTONLY_NIC>' `
  --cidr '<ACTUAL_APPROVED_RFC1918_CIDR>'
~~~

The screen requires one active non-loopback lab NIC with exactly one scoped
IPv4 address, no extra active/addressed NIC, no non-link-local IPv6 address,
no unexpected or duplicate address on `lo` (only `127.0.0.1/8` and
`::1/128` are permitted there),
and only direct lab/link-local routes in the **declared main-table snapshots**.
The IPv4 lab subnet must be a narrow RFC1918 CIDR. It rejects a default route,
gateway, out-of-scope route, malformed JSON, duplicate JSON keys and changed
source bytes. For a route with an explicit `prefsrc`, the source must be an
address assigned to the approved NIC and match the route IP family. The screen
also rejects route encapsulation, nested next hops, source-specific route
selectors, and explicit non-main routing-table entries; these are not needed
for the minimal approved Host-only topology. Standard iproute2 route flags and
a matching local `prefsrc` remain supported. It does not export raw
addresses, interface names or file paths.

**Important limitation:** A PASS is only configuration consistency for
operator-provided bytes. The script cannot inspect hidden policy routes,
iptables/nftables, DNS, forwarding, VMware adapter mode, physical egress,
authorization, or capture authenticity. A forged snapshot can pass. Do not
generate traffic until the operator independently checks every VM and
approves the exact Host-only scope. Do not modify originals to force PASS.

Synthetic-only cross-platform regression (not a VMware experiment):

~~~powershell
py -3.12 -m pytest -q tests/test_linux_guest_network_preflight.py
~~~
