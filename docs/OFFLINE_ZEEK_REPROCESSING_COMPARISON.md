# DA005 — Offline comparison of two Zeek conn.log processing runs

This is a read-only, **opt-in** research consistency check. It compares two
independently SHA-256-pinned, private Zeek ASCII `conn.log` files using an
**exact multiset of the supported parsed fields**. It does not execute Zeek,
read a PCAP, access any network, generate traffic, invoke AI or write SQLite.

## Scope and interpretation

The existing bounded Zeek parser supplies timestamps (UTC), direction,
IPv4/IPv6 endpoints, ports, protocol, service, duration, byte and packet
counters. These values must match exactly, including record multiplicity;
row order and Zeek run-specific UIDs may differ. Missing optional fields
normalize to `None`. Other Zeek columns (such as `conn_state` and
`history`) are **not** compared. No tolerance for timestamps or duration
is silently applied. A success means only these parsed fields agree.

This does **not** establish that either log was produced from the original
PCAP, that Zeek versions/binaries/scripts/configuration match, or that a
maliciously modified log was not independently re-pinned. It cannot prove
VMware isolation, capture authenticity, ground truth, AI accuracy or
end-to-end detection latency. For a stronger experiment, preserve the
original PCAP and independently pin its SHA-256; run `zeek -r` offline in
an approved Linux VM and retain the command, Zeek version/configuration,
capture SHA-256, both log hashes, run identifiers and operator approval.
Do not claim full Zeek output equivalence: unparsed fields are excluded.

## Windows 11 read-only comparison

Keep both files outside Git. Record each original SHA-256 **independently**
in a private notebook before comparison. Replace the example paths and
hash placeholders:

```powershell
py -3.12 scripts/compare_zeek_reprocessing.py `
  --original-log "C:/DA005-private/capture/zeek-run-1/conn.log" `
  --expected-original-sha256 "<INDEPENDENT_LOWERCASE_SHA256_1>" `
  --reprocessed-log "C:/DA005-private/capture/zeek-run-2/conn.log" `
  --expected-reprocessed-sha256 "<INDEPENDENT_LOWERCASE_SHA256_2>"
```

Exit code 0 emits JSON counts and explicit false verification claims without
IPs, UIDs or timestamps. Exit code 2 refuses mismatches or invalid pins,
without a partial-success JSON. Both logs must be distinct absolute private
regular files; no output file is created.

Synthetic-only regression (not student laptop acceptance):

```powershell
py -3.12 -m pytest -q tests/test_zeek_reprocessing_compare.py
```

Dataset Mode UNSW-NB15, existing models, SOC cases and Red Team execution
remain unchanged. A student must separately verify authorized VMware
Host-only isolation and independent experiment labels before making any
attack-detection claim.


## Opt-in strict all-field raw comparison (feature pending CI, 30/10/2026)

Add `--strict-all-fields` to the Windows command above to require equality of
**all raw ASCII Zeek columns except `uid`**, including `conn_state`, `history`
and script-defined extra columns. Both logs must declare the same field names,
matching per-field `#types` if present, and matching missing/empty/set
sentinel metadata. Field order and row order may differ. The check is
case-sensitive, format-sensitive (e.g. `100.0` vs `100.00` differs) and
preserves duplicate multiplicity. `#open`/`#close` run timestamps and UID
values remain excluded; fields that *contain* run-specific UID references
may cause an intentional conservative mismatch.

The default command remains the historical parsed-field comparison. Strict
mode first performs that comparison, then checks the full raw field multiset.
It can detect additional discrepancies but cannot prove a particular PCAP
produced either log, establish Zeek binary/config provenance, or validate
isolation, labels, attack detection or latency. The JSON output never includes
individual flows, IPs or UIDs. No Zeek executable or network is invoked.


## Optional three-file PCAP + two Zeek logs corroboration (feature PR, 30/10/2026)

The read-only comparator can additionally verify that **both** independently
SHA-256-pinned Zeek logs contain only supported IPv4 TCP/UDP 5-tuples present
in a **third**, independently pinned, private classic Ethernet PCAP. Supply
`--pcap` and `--expected-pcap-sha256` **together**; either alone is refused.
This gate is opt-in and can be combined with `--strict-all-fields`.
Without these arguments, the existing two-log comparison is unchanged.

Example Windows PowerShell command (replace all paths and SHA-256 pins
with independently recorded values):

```powershell
py -3.12 scripts/compare_zeek_reprocessing.py `
  --original-log "C:/DA005-private/capture/zeek-run-1/conn.log" `
  --expected-original-sha256 "<INDEPENDENT_LOWERCASE_SHA256_1>" `
  --reprocessed-log "C:/DA005-private/capture/zeek-run-2/conn.log" `
  --expected-reprocessed-sha256 "<INDEPENDENT_LOWERCASE_SHA256_2>" `
  --pcap "C:/DA005-private/capture/original.pcap" `
  --expected-pcap-sha256 "<INDEPENDENT_LOWERCASE_SHA256_PCAP>" `
  --strict-all-fields
```

The PCAP must be a distinct absolute private regular file, at most 64 MiB.
Both logs must independently match their pins. The bounded checker requires
classic Ethernet PCAP, untagged IPv4, unfragmented TCP/UDP and rejects
unsupported Zeek protocols, IPv6 flows, VLAN-tagged packets and fragments.
On success, JSON reports that tuple-presence checks passed for both logs,
along with counts and explicit false provenance/identity claims. It never
prints IPs, Zeek UIDs or packet payloads. Any pin, structure or tuple failure
returns code 2 and **no partial-success JSON**.

**Scientific limitation:** This combines two independently bounded checks,
not a proof of PCAP-to-Zeek derivation. A single packet tuple can match
multiple Zeek flows; timestamp, payload, connection state, Zeek binary/scripts,
operator identity, physical isolation and capture authenticity are not
authenticated. The student must still execute two separately documented
`zeek -r` passes in an authorized offline environment, preserve source
checksums, exact commands, Zeek version, scripts/config and isolation evidence
outside the public repository. CI synthetic tests are not Windows 11/VMware
acceptance or independently labeled attack detection.
