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
corroboration; VLAN-tagged Ethernet and fragmented IPv4 are refused. Zeek
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
