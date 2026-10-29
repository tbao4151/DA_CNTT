# DA005 — Private offline lab evidence consistency gate

This **read-only** command joins two existing checks: (1) the independently SHA-256-pinned Windows host/guest configuration pair, and (2) the independently pinned original classic PCAP → Zeek `conn.log` offline import report. It does not collect packets, execute scenarios, create AI alerts/SOC cases, or write any file. It is a **consistency gate, not an isolation attestation**.

Run this **only after** the student has manually configured and inspected an owned VMware Host-only network, disabled NAT/bridging on the test guests, recorded written test scope, collected original private snapshots, and generated a permitted PCAP and its Zeek offline import. The script does not prove those actions occurred. Keep every original, screenshot, approval and independent SHA-256 pin outside Git; do not publish internal IPs, private captures or model files.

From the project root on Windows 11 (PowerShell; replace every placeholder with the actual independently recorded value):

```powershell
py -3.12 scripts/verify_lab_evidence_chain.py `
  --host-snapshot 'C:\DA005-private\network\host.json' `
  --expected-host-sha256 '<HOST_SHA256>' `
  --host-adapter 'VMware Network Adapter VMnet1' `
  --guest-snapshot 'C:\DA005-private\network\guest.json' `
  --expected-guest-sha256 '<GUEST_SHA256>' `
  --guest-adapter '<ACTUAL_GUEST_ADAPTER>' `
  --cidr '<APPROVED_RFC1918_LAB_CIDR>' `
  --pcap 'C:\DA005-private\capture\original.pcap' `
  --log 'C:\DA005-private\capture\zeek-output\conn.log' `
  --import-report 'C:\DA005-private\capture\zeek-output\offline_import_report.json' `
  --expected-import-report-sha256 '<IMPORT_REPORT_SHA256>' `
  --expected-pcap-sha256 '<INDEPENDENT_ORIGINAL_PCAP_SHA256>' `
  --expected-log-sha256 '<INDEPENDENT_ORIGINAL_CONN_LOG_SHA256>' `
  --require-independent-original-pins
```

For stronger original-evidence checking, supply **both** `--expected-pcap-sha256` and `--expected-log-sha256`, recorded separately when the original files were archived. These options are backward compatible and optional as a pair; supplying only one, malformed digests or a mismatch fails closed. The output field `independent_original_pcap_zeek_pins_verified` is `true` only when both independently supplied digests match the original bytes already verified against the pinned import report; otherwise it is `false`. Hashes are consistency evidence, not signatures or proof of independent recording, genuine capture origin or attack labels.

The import report and `conn.log` must be in the same directory and must be the original products of the offline import workflow. The command requires five **distinct absolute, private files** and compares all pins with their original bytes; the host and guest snapshots must match the same declared subnet, have distinct IPv4 addresses, and pass their existing strict offline validators. The import verifier rechecks PCAP and Zeek bytes, declared endpoints and flow count. The output is sanitized JSON on stdout, containing SHA-256 digests and a flow count but no IPs, paths or UIDs. Failure returns exit code 1 with a generic error and no partial JSON.

A successful report explicitly sets `vmware_isolation_verified`, `capture_authenticity_verified`, `traffic_authorized`, `independent_labels_verified`, `ai_inference_performed`, `operational_alerts_created`, `soc_case_created` and `live_detection_latency_measured` to `false`. Preserve a copy of stdout **privately** only after verifying it describes the actual original evidence. Independent source authentication, capture timing, labels and ground truth require additional student evidence; this gate does not make them true. Do not use a pass as permission to generate active traffic.

Synthetic regression only (GitHub Ubuntu/Windows CI is not laptop acceptance):

```powershell
py -3.12 -m pytest -q tests/test_lab_evidence_chain.py
```

On the student's machine, also retain VMware Virtual Network Editor screenshots, every guest NIC/route inventory, the approval/scope record, PCAP and Zeek version/command, hashes captured independently, the test-label adjudication protocol and any genuine event-to-alert/SOC timestamps. Record Dataset Mode UNSW-NB15 benchmark separately from Cyber Lab findings. Never report CI synthetic results as real attack-detection performance.

## Strict original-evidence gate (30/10/2026)

For a research acceptance check, add `--require-independent-original-pins` as shown above. The command now **refuses** a missing pair of independently recorded original PCAP and Zeek SHA-256 pins, rather than returning success with the weaker `independent_original_pcap_zeek_pins_verified=false` status. Successful strict output explicitly sets `independent_original_pcap_zeek_pins_required=true` and `independent_original_pcap_zeek_pins_verified=true`. The flag does not change existing invocations: omitting it retains the earlier optional paired-pin behavior and reports `independent_original_pcap_zeek_pins_required=false`.

Strict checking verifies only the supplied byte digests and consistency with the pinned import report. It cannot prove the hashes were recorded independently, that VMware was isolated, that traffic was authorized, or that attacks were detected. Do not describe a strict PASS as a live-lab acceptance or SOC detection result. Synthetic regression: `py -3.12 -m pytest -q tests/test_lab_evidence_chain.py`.


## Optional guest-endpoint presence check (30/10/2026)

When the research question specifically requires traffic involving the declared
Windows guest, add `--require-guest-endpoint` **alongside**
`--require-independent-original-pins` and both original PCAP/Zeek digests.
The read-only verifier rechecks the Zeek file SHA-256 against the already
verified offline import and requires at least one Zeek flow with the guest's
validated IPv4 address as source **or** destination. It fails closed when the
guest is absent, when the log changed during verification, or when strict
original pins are not enabled.

The sanitized JSON distinguishes
`guest_endpoint_presence_required` and
`guest_endpoint_observed_in_verified_log`. Both are `false` when the
optional check was not requested; `true` indicates only a matching address
in verified log bytes. Neither the guest address nor any flow identifiers are
printed. This check is **not appropriate** for passive monitoring guests that
only observe traffic between other VMs. It does not prove that the PCAP
originated on the declared guest, that its IP was not spoofed, that a packet
capture and Zeek log are independently authenticated, or that VMware is
physically isolated. Confirm NIC assignments, isolation, authorization,
capture origin and independent labels outside this software gate.

Synthetic regression: `py -3.12 -m pytest -q tests/test_lab_evidence_chain.py`.


## Optional strict classic-PCAP framing in the integrated gate (30/10/2026)

The integrated read-only evidence verifier now accepts `--require-pcap-framing`.
Add it to the full command above **together with**
`--require-independent-original-pins` and both independently recorded
original PCAP/Zeek SHA-256 digests. The integrated verifier delegates to the
existing bounded classic-PCAP v2.4 packet-record validator. It fails closed
for missing strict pins, header-only files, invalid packet lengths, truncated
packet records or malformed timestamps. No packet bytes or private IPs are
printed. Existing invocations remain compatible and report
`pcap_framing_required=false`, `pcap_framing_verified=false` and
`pcap_packet_count=null` when the optional check is not requested.

A strict pass reports `pcap_framing_verified=true` and the structural
`pcap_packet_count`; it does **not** establish correspondence between those
packet records and Zeek flows. The parser does not decode protocols or
authenticate packet contents, timestamps, capture origin, VMware isolation,
operator authorization, independent attack labels, AI detections or SOC
latency. PCAPNG is not supported by this strict classic-PCAP gate.

Regression only: `py -3.12 -m pytest -q tests/test_lab_evidence_chain.py`.
These synthetic tests are not a Windows 11/VMware experiment.
