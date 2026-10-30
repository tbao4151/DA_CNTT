# DA005 — Offline PCAP/Zeek IPv4 TCP/UDP tuple-presence corroboration

This is a **read-only, opt-in, conservative consistency check**, not a live
sensor, network probe, packet-to-Zeek provenance proof, AI attack detector or
operational SOC alert. It checks whether each parsed Zeek `conn.log` IPv4
TCP/UDP source/destination address+port+protocol tuple appears in at least
one packet of an independently SHA-256-pinned classic PCAP (either direction).
It never transmits traffic, starts Zeek or writes to SQLite.

Supported input is **classic Ethernet PCAP (DLT 1), untagged IPv4,
nonfragmented TCP or UDP**. Non-IPv4 packets such as ARP are ignored for
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

The successful stdout JSON contains counts and explicit false safety claims;
no addresses, UIDs or timestamps are emitted. Exit code `2` means refusal;
there is no partial success output. Do not upload private PCAP, Zeek logs,
original hashes tied to confidential investigations or lab notebook to a
public repository. Preserve original evidence, Zeek version, capture
configuration, Host-only isolation screenshots and operator approval privately.

**Interpretation limits:** A matching tuple is *not* evidence that the Zeek
flow was generated from that packet. A single packet can corroborate multiple
Zeek records with identical tuples; no timestamp matching, packet-to-flow
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
