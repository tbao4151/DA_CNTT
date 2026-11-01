# DA005 — Combined pinned Linux guest network + RPDB preflight (offline)

This read-only entrypoint runs **both existing Linux guest screens together**:
the NIC/IPv4-IPv6 main-route screen and the IPv4/IPv6 routing-policy-rule
(RPDB) screen. It is useful before the first authorized VMware Host-only
capture because neither individual PASS is sufficient on its own.

On the **owned Linux Zeek guest**, with no network test traffic, collect
the five original JSON files in a private folder outside Git:

```bash
mkdir -p "$HOME/da005-private/session-001/network"
ip -j address show > "$HOME/da005-private/session-001/network/addresses.json"
ip -j -4 route show > "$HOME/da005-private/session-001/network/routes-v4.json"
ip -j -6 route show > "$HOME/da005-private/session-001/network/routes-v6.json"
ip -j -4 rule show > "$HOME/da005-private/session-001/network/rules-v4.json"
ip -j -6 rule show > "$HOME/da005-private/session-001/network/rules-v6.json"
sha256sum "$HOME/da005-private/session-001/network/"*.json
ip -j -4 route show table all
ip -j -6 route show table all
```

Record each original SHA-256 independently, with collection time, guest
identity, interface name, VMnet configuration and authorization. Preserve
unchanged bytes when copying to the private Windows host directory.

From the repository root on Windows 11 / Python 3.12:

```powershell
py -3.12 scripts/check_linux_guest_combined_preflight.py `
  --addresses 'C:/DA005-private/session-001/network/addresses.json' `
  --expected-addresses-sha256 '<ADDRESS_SHA256_LOWERCASE>' `
  --routes-v4 'C:/DA005-private/session-001/network/routes-v4.json' `
  --expected-routes-v4-sha256 '<ROUTES_V4_SHA256_LOWERCASE>' `
  --routes-v6 'C:/DA005-private/session-001/network/routes-v6.json' `
  --expected-routes-v6-sha256 '<ROUTES_V6_SHA256_LOWERCASE>' `
  --rules-v4 'C:/DA005-private/session-001/network/rules-v4.json' `
  --expected-rules-v4-sha256 '<RULES_V4_SHA256_LOWERCASE>' `
  --rules-v6 'C:/DA005-private/session-001/network/rules-v6.json' `
  --expected-rules-v6-sha256 '<RULES_V6_SHA256_LOWERCASE>' `
  --adapter '<ACTUAL_LINUX_HOST_ONLY_INTERFACE>' `
  --cidr '<ACTUAL_HOST_ONLY_CIDR>'
```

The five input files must be distinct, absolute, private, non-symlink
paths, and each must match its independently recorded SHA-256. A failure
in **either** existing validator produces exit code 1, a generic refusal
on stderr and **no success JSON**. The command does not change the
individual CLIs or any historical benchmark. A success report contains
no raw IP addresses or private paths.

The output explicitly keeps
`vmware_hostonly_isolation_verified=false`,
`traffic_authorized=false`, `other_routing_tables_checked=false`,
`dns_and_forwarding_checked=false` and
`network_activity_performed=false`. This is **not** a certificate of
isolation, authorization, capture authenticity, or AI detection. Stale
or forged snapshots can pass. Inspect every VM NIC/VMnet mode, all route
tables, firewall, DNS, forwarding, IPv6 and written scope manually;
stop on ambiguity. Never alter routing or expand CIDRs just to pass.

Synthetic regression on Windows (not a VMware experiment):

```powershell
py -3.12 -m pytest -q tests/test_linux_guest_combined_preflight.py
```

The original individual procedures remain documented in
[Linux guest NIC/main-route preflight](LINUX_GUEST_HOSTONLY_PREFLIGHT.md)
and [Linux policy-rule preflight](LINUX_GUEST_POLICY_RULES_PREFLIGHT.md).
The broader evidence sequence is
[First VMware Host-only evidence session](FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md).


## Optional seven-snapshot all-routing-table consistency check

The original five-snapshot command remains supported. To additionally screen
operator-provided **all-table** route inventories, collect two more original
files on the same owned Linux Zeek guest, as close in time to the five
snapshots as possible:

    ip -j -4 route show table all > "$HOME/da005-private/session-001/network/routes-all-v4.json"
    ip -j -6 route show table all > "$HOME/da005-private/session-001/network/routes-all-v6.json"
    sha256sum "$HOME/da005-private/session-001/network/routes-all-v4.json" "$HOME/da005-private/session-001/network/routes-all-v6.json"

Add **both** optional pairs to the existing Windows command:

    --routes-all-v4 'C:/DA005-private/session-001/network/routes-all-v4.json' `
    --expected-routes-all-v4-sha256 '<ALL_V4_SHA256_LOWERCASE>' `
    --routes-all-v6 'C:/DA005-private/session-001/network/routes-all-v6.json' `
    --expected-routes-all-v6-sha256 '<ALL_V6_SHA256_LOWERCASE>'

The extra gate requires seven distinct, absolute, non-symlink, independently
pinned files. It rejects unknown routing tables, unsafe local-table entries,
default routes and missing/extra main-table routes when comparing the
all-table snapshots to the original main-table snapshots. In seven-file mode,
local-table destinations are also screened: IPv4 on the approved guest NIC
must stay within the declared Host-only CIDR, IPv6 on that NIC within
link-local fe80::/10, and loopback entries within 127.0.0.0/8 or ::1/128.
Kernel multicast entries are allowed only with a multicast route type and
multicast destination; the conventional IPv4 limited broadcast address is
allowed on the approved NIC with broadcast type. Out-of-scope local-table
addresses are refused even if their route metadata otherwise looks valid.
This is a conservative policy and may reject legitimate advanced routing. It may reject
legitimate advanced Linux routing; **investigate**, do not modify evidence to
force PASS. The snapshots can change between commands and cannot prove they
represent one atomic kernel state.

A seven-file PASS sets
`all_routing_tables_in_supplied_snapshots_checked=true`, but deliberately
keeps `other_routing_tables_checked=false` because no live kernel state was
inspected. Both five-file and seven-file modes keep
`vmware_hostonly_isolation_verified=false` and
`traffic_authorized=false`. Independently review VMnet/NIC configuration,
forwarding, DNS, firewall, authorization and actual routing before traffic.
