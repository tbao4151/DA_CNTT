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
  --expected-import-report-sha256 '<IMPORT_REPORT_SHA256>'
```

The import report and `conn.log` must be in the same directory and must be the original products of the offline import workflow. The command requires five **distinct absolute, private files** and compares all pins with their original bytes; the host and guest snapshots must match the same declared subnet, have distinct IPv4 addresses, and pass their existing strict offline validators. The import verifier rechecks PCAP and Zeek bytes, declared endpoints and flow count. The output is sanitized JSON on stdout, containing SHA-256 digests and a flow count but no IPs, paths or UIDs. Failure returns exit code 1 with a generic error and no partial JSON.

A successful report explicitly sets `vmware_isolation_verified`, `capture_authenticity_verified`, `traffic_authorized`, `independent_labels_verified`, `ai_inference_performed`, `operational_alerts_created`, `soc_case_created` and `live_detection_latency_measured` to `false`. Preserve a copy of stdout **privately** only after verifying it describes the actual original evidence. Independent source authentication, capture timing, labels and ground truth require additional student evidence; this gate does not make them true. Do not use a pass as permission to generate active traffic.

Synthetic regression only (GitHub Ubuntu/Windows CI is not laptop acceptance):

```powershell
py -3.12 -m pytest -q tests/test_lab_evidence_chain.py
```

On the student's machine, also retain VMware Virtual Network Editor screenshots, every guest NIC/route inventory, the approval/scope record, PCAP and Zeek version/command, hashes captured independently, the test-label adjudication protocol and any genuine event-to-alert/SOC timestamps. Record Dataset Mode UNSW-NB15 benchmark separately from Cyber Lab findings. Never report CI synthetic results as real attack-detection performance.
