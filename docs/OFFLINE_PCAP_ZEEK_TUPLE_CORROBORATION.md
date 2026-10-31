# DA005 — Offline PCAP/Zeek IPv4 TCP/UDP tuple-presence corroboration

This is a **read-only, opt-in, conservative consistency check**, not a live
sensor, network probe, packet-to-Zeek provenance proof, AI attack detector or
operational SOC alert. It checks whether each parsed Zeek `conn.log` IPv4
TCP/UDP source/destination address+port+protocol tuple appears in at least
one packet of an independently SHA-256-pinned classic PCAP (either direction).
It never transmits traffic, starts Zeek or writes to SQLite.

Supported input is **classic Ethernet PCAP (DLT 1), untagged IPv4,
nonfragmented TCP or UDP**.

For UDP, the strict verifier additionally rejects a declared datagram length
smaller than the eight-byte UDP header or larger than the IPv4 payload length.
This prevents malformed UDP port bytes from being counted as corroborating
packet evidence, including under the opt-in timestamp gate. It does **not**
validate UDP checksums, complete payload delivery or packet-to-Zeek flow
identity; valid snaplen-truncated payloads are not rejected solely because
the full IP payload was not captured. Existing TCP behavior is unchanged.

For both TCP and UDP, the verifier now also requires the **PCAP record's
original Ethernet frame length** to be at least the 14-byte Ethernet header
plus the IPv4 header's declared total length. This rejects impossible IP
lengths even if the captured prefix contains plausible ports and timestamps.
A legitimate snaplen-truncated record may still pass when its separately
recorded original length is sufficient; no payload completeness is claimed.
 Non-IPv4 packets such as ARP are ignored for
corroboration; VLAN-tagged Ethernet, fragmented IPv4, and IPv4 packets with the RFC 791 reserved high flag bit set are refused. The valid IPv4 Don't Fragment (DF) bit remains accepted. Zeek
flows using IPv6 or non-TCP/UDP protocols are refused rather than silently
reported as verified. Classic PCAP record framing and Zeek ASCII parsing are
validated using existing bounded project parsers. Unsupported formats need
separate, reviewed implementation, not a weakened verifier.

## Windows 11 offline usage

Keep both original files outside the public repository. Record each original
SHA-256 independently in a private experiment notebook **before** verification.
Use the real path and digest values, not the example placeholders:

```powershell
py -3.12 scripts/verify_pcap_zeek_tuple.py `
  --pcap "C:/DA005-private/capture/capture.pcap" `
  --expected-pcap-sha256 "<INDEPENDENT_LOWERCASE_PCAP_SHA256>" `
  --log "C:/DA005-private/capture/conn.log" `
  --expected-log-sha256 "<INDEPENDENT_LOWERCASE_ZEEK_SHA256>"
```

Optional stricter **timestamp-presence** gate (default OFF): append
`--require-timestamp-corroboration` to the command. For each Zeek flow,
this requires at least one same-direction or reverse-direction TCP/UDP IPv4
packet whose classic-PCAP record timestamp is within **1.0 second** of the
Zeek flow start timestamp. Both microsecond and nanosecond PCAP timestamp
resolutions are supported. A matching five-tuple from a distant session no
longer suffices under this opt-in gate. The stdout report sets
`timestamps_correlated=true` and `timestamp_corroboration_window_seconds=1.0`
only when the stricter gate was requested and passed. The default retains
`timestamps_correlated=false` and the original tuple-only behavior.

This is a *bounded timestamp presence* check, not packet-to-flow identity,
Zeek clock attestation, proof of derivation, capture authenticity or measured
detection latency. Timestamp shifts from clock errors, PCAP processing or
unsupported encapsulation may cause refusal. Do not loosen the one-second
window to force a desired result; investigate discrepancies independently.

The successful stdout JSON contains counts and explicit false safety claims;
no addresses, UIDs or timestamps are emitted. Exit code `2` means refusal;
there is no partial success output. Do not upload private PCAP, Zeek logs,
original hashes tied to confidential investigations or lab notebook to a
public repository. Preserve original evidence, Zeek version, capture
configuration, Host-only isolation screenshots and operator approval privately.

**Ambiguity diagnostics (offline, non-identifying):** The JSON also reports
`distinct_zeek_bidirectional_tuples`,
`zeek_rows_with_nonunique_bidirectional_tuple`,
`distinct_supported_pcap_bidirectional_tuples` and
`potential_packet_reuse_for_multiple_zeek_flows`. Both directions are
grouped under the same tuple; for example, two Zeek rows with reverse
directions and only one matching PCAP packet are explicitly marked as
potential reuse. These counts do not contain IPs, ports, UIDs or timestamps.
A `false` reuse flag only means that duplicate bidirectional Zeek tuples
were not observed; it **never** upgrades `packet_to_flow_identity_verified`
from `false`. Packet counts are not expected to equal connection counts,
and this diagnostic is not an attack metric, capture-origin proof or
one-to-one Zeek correspondence.

**Interpretation limits:** A matching tuple is *not* evidence that the Zeek
flow was generated from that packet. A single packet can corroborate multiple
Zeek records with identical tuples; no timestamp matching by default, packet-to-flow
cardinality, connection state, payload analysis, flow completeness, NAT
reconstruction or Zeek processing reproducibility is established. Independently
pinned hashes demonstrate byte consistency with recorded digests, not
capture authenticity, physical VMware isolation or authorization. No
Precision/Recall/FPR, attack labels or event-to-alert-to-case latency can be
inferred from this check. The UNSW-NB15 Dataset Mode benchmark and Red Team
behavior are untouched.

Synthetic-only regression (not a real VMware experiment):

```powershell
py -3.12 -m pytest -q tests/test_pcap_zeek_tuple.py
```

Next, test on an authorized genuine Host-only capture and retain a separate
experiment record. For stronger provenance, run offline Zeek on the pinned
original PCAP in a reproducible environment and independently compare the
resulting flow records, explicitly accounting for Zeek versions and time.

## Timestamp offset diagnostics (01/11/2026; synthetic contract)

When the optional timestamp gate passes, the JSON reports
`timestamp_nearest_packet_offset_max_ms` and
`timestamp_nearest_packet_offset_mean_ms` across all Zeek rows. For each
row, the closest timestamp of any same/reverse-tuple packet within the fixed
±1-second window is used. **The same packet may be reused** in this
presence-only calculation. Without the timestamp gate, both fields are null.

When the additional distinct-packet gate passes, the JSON also reports
`distinct_assigned_packet_offset_max_ms` and
`distinct_assigned_packet_offset_mean_ms`. These are based on the existing
deterministic earliest-eligible greedy assignment, not a minimum-cost matching.
Without distinct mode, both assigned-offset fields are null. The integrated
private evidence-chain report exposes the two maxima under
`pcap_zeek_nearest_packet_offset_max_ms` and
`pcap_zeek_distinct_assigned_offset_max_ms`, respectively.

These **absolute millisecond differences are not detection latency**, clock
synchronization attestation, capture provenance, packet-to-flow identity, or
model performance. Zeek flow start time and packet capture time may originate
from different clocks. The values contain no raw IPs, ports or timestamps;
record real capture clock setup and uncertainty separately in the private
experiment notebook. No traffic is generated by this diagnostic.

Synthetic regression (Windows and Ubuntu CI, not VMware acceptance):

```powershell
py -3.12 -m pytest -q tests/test_pcap_zeek_timing_offsets.py
```


## Signed PCAP-to-Zeek timestamp offsets (01/11/2026; synthetic regression)

The optional timestamp gate now also returns
`timestamp_nearest_packet_signed_offset_mean_ms`. The optional distinct-packet
gate returns `distinct_assigned_packet_signed_offset_mean_ms`. Both are
aggregate **signed** means in milliseconds, with the convention
`PCAP packet timestamp - Zeek flow start timestamp`: positive means the
matched packet is later, negative means earlier. On equal absolute nearest
offsets the earlier packet wins deterministically. The integrated private
evidence-chain report exposes these as
`pcap_zeek_nearest_packet_signed_offset_mean_ms` and
`pcap_zeek_distinct_assigned_signed_offset_mean_ms`. When the relevant
opt-in gate is disabled, its signed mean is null.

Signed means can cancel: equal positive and negative offsets can produce a
zero mean despite substantial per-flow disagreement. Always interpret the
signed mean **together with** the pre-existing absolute max/mean offsets;
a nonzero mean is not proof of clock skew, and zero is not proof of
synchronization. The distinct assignment remains earliest-eligible greedy,
not minimum-cost matching. These aggregates contain no packet IPs or raw
timestamps. They are not event-to-alert latency, attack detection, capture
authenticity, or packet-to-flow provenance. This change makes no network
requests and leaves Dataset Mode and Red Team execution unchanged.

Synthetic regression only (not student VMware acceptance):

```powershell
py -3.12 -m pytest -q tests/test_pcap_zeek_signed_offsets.py
```

## Absolute offset P95 diagnostics (01/11/2026; synthetic-only contract)

The opt-in timestamp gate now also reports
`timestamp_nearest_packet_offset_p95_ms`. The additional distinct-record
gate reports `distinct_assigned_packet_offset_p95_ms`. Both use the
**nearest-rank 95th percentile**: sort absolute offsets and select the
observation at 1-based rank `ceil(0.95 * N)` (no interpolation). For
`N=1` this is the sole offset; for `N=10` it is the largest offset.
Fields are null when their corresponding gate is disabled.

The private integrated evidence-chain JSON exposes these aggregate values
as `pcap_zeek_nearest_packet_offset_p95_ms` and
`pcap_zeek_distinct_assigned_offset_p95_ms`. The presence-only P95 may
reuse the same packet for multiple Zeek rows; the distinct P95 uses the
existing earliest-eligible assignment, **not** an optimal minimum-offset
matching. Compare both with absolute max/mean and signed mean; the P95 is
not a confidence interval, synchronization proof, attack metric, or
event-to-alert detection latency. A small sample can make P95 equal the
maximum. No raw IP, UID or packet timestamp is exported.

Run synthetic-only regression (no Zeek executable, VMware, or live traffic):

```powershell
py -3.12 -m pytest -q tests/test_pcap_zeek_offset_percentiles.py
```

## Optional IPv4 header checksum gate (01/11/2026; synthetic contract)

The tuple verifier can now enforce RFC 791 **IPv4 header checksum** validity
for every IPv4 packet in the original, independently SHA-256-pinned classic
PCAP. This gate is **OFF by default** to preserve compatibility with prior
fixtures and captures where checksum offloading or capture tooling may expose
invalid/uncomputed header checksums. Add
`--require-ipv4-header-checksum` to the standalone command above.

The integrated private evidence-chain CLI uses the separate flag
`--require-pcap-ipv4-header-checksum`. It refuses this flag unless both
`--require-independent-original-pins` and
`--require-pcap-zeek-tuples` are present. Successful output reports
`pcap_ipv4_header_checksum_required=true` and
`pcap_ipv4_header_checksum_verified=true`; the standalone verifier reports
`ipv4_header_checksum_required` and `ipv4_header_checksum_verified`.
Without the opt-in flag, the values remain false.

The checksum covers the **IPv4 header only**, including any IPv4 options.
It does **not** check TCP/UDP headers or payload, nor establish cryptographic
integrity, authenticity, packet-to-flow identity, isolation, labels, or AI
detection. A failed gate is a reason to investigate and preserve the original
PCAP, **not** to rewrite its checksums or adjust the source to pass. The
existing SHA-256 pins are separate byte-consistency checks, not provenance
attestation. No live traffic, exploit or model operation is performed.

Synthetic-only regression (no VMware or real capture):

```powershell
py -3.12 -m pytest -q tests/test_pcap_ipv4_header_checksum.py
```
