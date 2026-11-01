# DA005 — Linux Zeek guest policy-routing rules: pinned offline screen

This is a **separate, read-only check** of the Linux guest's IPv4/IPv6
routing-policy rules (RPDB). It complements
[the main-route/NIC preflight](LINUX_GUEST_HOSTONLY_PREFLIGHT.md).
It does not contact the guest, run `ip`, send packets, modify configuration,
or establish that VMware Host-only isolation is effective.

On the **owned Linux Zeek guest**, save unchanged command output outside Git,
preferably immediately alongside the address/main-route snapshots:

```bash
mkdir -p "$HOME/da005-private/session-001/network"
ip -j -4 rule show > "$HOME/da005-private/session-001/network/linux-rules-v4.json"
ip -j -6 rule show > "$HOME/da005-private/session-001/network/linux-rules-v6.json"
sha256sum "$HOME/da005-private/session-001/network/linux-rules-v4.json" \
          "$HOME/da005-private/session-001/network/linux-rules-v6.json"
ip -j -4 route show table all
ip -j -6 route show table all
```

Record SHA-256 independently before copying the two unchanged JSON files to
the Windows host. From the repository root:

```powershell
py -3.12 scripts/check_linux_guest_policy_rules.py `
  --rules-v4 'C:/DA005-private/session-001/network/linux-rules-v4.json' `
  --expected-rules-v4-sha256 '<INDEPENDENT_LOWERCASE_SHA256>' `
  --rules-v6 'C:/DA005-private/session-001/network/linux-rules-v6.json' `
  --expected-rules-v6-sha256 '<INDEPENDENT_LOWERCASE_SHA256>'
```

The screen accepts exactly the conventional IPv4 rules: priority 0 to
`local`, 32766 to `main`, 32767 to `default`. For IPv6, priority 0 to
`local` and 32766 to `main` are required; a conventional priority 32767
to `default` is permitted. Each rule must have only `priority`, `src=all`,
and `table`; canonical numeric table IDs 255/254/253 are accepted.
Any additional selector, priority, policy table, goto, fwmark, suppression,
malformed entry, duplicate JSON key, changed hash or nonstandard rule is
refused. This strict minimal-lab profile may reject legitimate customized
Linux configurations: **do not delete or alter rules just to obtain PASS**.

The output deliberately reports
`other_routing_tables_checked=false`,
`vmware_hostonly_isolation_verified=false` and
`traffic_authorized=false`. A PASS only states that the **operator-supplied
snapshot bytes** match the minimal expected policy-rule profile. A forged or
stale snapshot may pass. The separate main-route preflight does not read
policy rules; this screen does not read the routes those rules reference.
Independently inspect **all** route tables, forwarding, DNS, firewalls,
all VMware VMnet/NIC modes, IPv6 behavior and written authorization before
generating any traffic. Preserve raw evidence, hashes, collection time,
software versions and operator sign-off privately.

Synthetic cross-platform tests (not a student VMware run):

```powershell
py -3.12 -m pytest -q tests/test_linux_guest_policy_rules.py
```
