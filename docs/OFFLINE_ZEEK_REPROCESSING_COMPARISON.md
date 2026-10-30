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
