# DA005 — First owned VMware Host-only evidence session (Windows 11)

This is an **operator-executed acceptance runbook**, not evidence that the student has performed an experiment. It joins existing offline tools into one first-session sequence; it adds no packet capture, attack generation, AI model, or automatic SOC alert. **Stop before any network traffic** unless the group owns the VMs, has written authorization, and has manually inspected isolation. Do not expose Streamlit or share private evidence publicly.

## 0. Scope and STOP conditions (record privately before starting)

Record session ID, operator, approval/scope, exact VMnet/CIDR, all VM NICs and routes, local time/timezone, Zeek/Python versions, intended benign activity, and where original bytes will be archived. Use three distinct roles when available: Windows 11 host, one Windows guest, and one Linux guest with Zeek. **Every participating guest must have only the approved Host-only NIC**, with no bridged/NAT/secondary adapters, forwarding, default route to an external gateway, or unintended IPv6 egress. Verify this manually in VMware Virtual Network Editor and inside each guest; the software cannot attest physical isolation.

Stop if an adapter/route is ambiguous, the declared CIDR differs from the actual VMnet, the approval is absent, the PCAP includes an out-of-scope endpoint, or an original file changes after hashing. Do not widen CIDRs to bypass a refusal. Red Team execution stays OFF. Begin with an approved **benign baseline**; do not invent Attack labels.

## 1. Capture original network configuration (read-only)

From the project root on the Windows host, create a **private** directory outside Git. Use a new filename per attempt:

```powershell
New-Item -ItemType Directory -Force 'C:/DA005-private/session-001/network'
py -3.12 --version
powershell -File scripts/collect_windows_hostonly_snapshot.ps1 -AdapterName 'VMware Network Adapter VMnet1' -OutputPath 'C:/DA005-private/session-001/network/host.json'
```

Inside the **owned Windows guest**, create its own private folder first, then run the same repository script (or copy the script to the guest and invoke its actual local path). Keep the output private and transfer the original bytes back without editing:

```powershell
New-Item -ItemType Directory -Force 'C:/DA005-private/session-001/network'
powershell -File scripts/collect_windows_guest_network_snapshot.ps1 -OutputPath 'C:/DA005-private/session-001/network/guest.json'
```

Record both SHA-256 values **independently in a dated private notebook** before invoking any verifier:

```powershell
Get-FileHash 'C:/DA005-private/session-001/network/host.json' -Algorithm SHA256
Get-FileHash 'C:/DA005-private/session-001/network/guest.json' -Algorithm SHA256
py -3.12 scripts/check_paired_network_preflight.py `
  --host-snapshot 'C:/DA005-private/session-001/network/host.json' --expected-host-sha256 '<HOST_SHA256_LOWERCASE>' --host-adapter 'VMware Network Adapter VMnet1' `
  --guest-snapshot 'C:/DA005-private/session-001/network/guest.json' --expected-guest-sha256 '<GUEST_SHA256_LOWERCASE>' --guest-adapter '<ACTUAL_GUEST_ADAPTER>' --cidr '<ACTUAL_HOST_ONLY_CIDR>'
```

A passing snapshot comparison is **not** a physical isolation certificate. Independently archive screenshots of VMware NIC assignments, host/guest routes, and Linux guest NICs.

## 2. Obtain an original, authorized benign PCAP (manual)

Only **after** the manual isolation/authorization review, capture a small, bounded, non-destructive baseline on the approved Host-only interface using a tool already installed on the Linux guest (e.g. tcpdump). For example, after checking the actual interface with `ip -br link`, a bounded passive capture is `sudo tcpdump -i <ACTUAL_HOST_ONLY_INTERFACE> -c 100 -w /home/student/da005-private/session-001/original.pcap` (stop it manually if the approved session ends first). This does not generate traffic. Record the exact interface and command in the private notebook. Do not run a network scanner or attack generator. Stop capture manually; preserve a **classic .pcap**, not PCAPNG, below 64 MiB. Zeek must be able to produce a nonempty `conn.log`. Record the PCAP SHA-256 immediately and preserve the original bytes; no packet payloads go into Git.

Inside the Linux Zeek VM, with the DA005 repository/scripts available locally and a private output directory that does **not yet exist**:

```bash
zeek --version
sha256sum /home/student/da005-private/session-001/original.pcap
python3 scripts/import_offline_pcap.py \
  --pcap /home/student/da005-private/session-001/original.pcap \
  --output-dir /home/student/da005-private/session-001/zeek-run-001 \
  --cidr '<ACTUAL_HOST_ONLY_CIDR>' --confirm-offline-only
sha256sum /home/student/da005-private/session-001/zeek-run-001/conn.log
sha256sum /home/student/da005-private/session-001/zeek-run-001/offline_import_report.json
```

Preserve `original.pcap`, `conn.log`, `offline_import_report.json`, Zeek version, timestamps and original capture notes. Copy **unchanged** originals to the Windows private directory for the next read-only gate; record their hashes again. If import fails, quarantine the partial output and use a new output directory, never overwrite originals.

## 3. Cross-check the complete evidence chain (read-only)

After the three files above are privately copied to Windows, use the **same** pinned values recorded before verification. Example paths below are placeholders for actual private files:

```powershell
py -3.12 scripts/verify_lab_evidence_chain.py `
  --host-snapshot 'C:/DA005-private/session-001/network/host.json' --expected-host-sha256 '<HOST_SHA256_LOWERCASE>' --host-adapter 'VMware Network Adapter VMnet1' `
  --guest-snapshot 'C:/DA005-private/session-001/network/guest.json' --expected-guest-sha256 '<GUEST_SHA256_LOWERCASE>' --guest-adapter '<ACTUAL_GUEST_ADAPTER>' `
  --cidr '<ACTUAL_HOST_ONLY_CIDR>' `
  --pcap 'C:/DA005-private/session-001/original.pcap' `
  --log 'C:/DA005-private/session-001/zeek-run-001/conn.log' `
  --import-report 'C:/DA005-private/session-001/zeek-run-001/offline_import_report.json' `
  --expected-import-report-sha256 '<IMPORT_REPORT_SHA256_LOWERCASE>' `
  --expected-pcap-sha256 '<PCAP_SHA256_LOWERCASE>' --expected-log-sha256 '<CONN_SHA256_LOWERCASE>' `
  --require-independent-original-pins --require-pcap-framing
```

Do **not** add `--require-guest-endpoint` when the observed traffic legitimately excludes the Windows guest (e.g. passive sensor on a third VM). A PASS only corroborates **operator-supplied bytes/configuration**, not real isolation, capture authenticity, authorization, attack truth, or AI detection.

## 4. Record acceptance, then plan a separate labeled experiment

For the **first benign session**, record: exact original hashes, version, PCAP packet count, Zeek flow count, event timestamp bounds, network screenshots, operator authorization, and the tool exit codes. Mark each item **PASS / FAIL / NOT MEASURED**, with an evidence file reference. If any required gate fails, do not claim acceptance.

Do **not** label every flow as Attack or manufacture a mixed-class dataset to make training run. Later, gather multiple **independent authorized sessions** with predeclared host-disjoint TRAIN/VALIDATION/TEST and independently reviewed 0/1 labels, following [offline experiment protocol](ZEEK_OFFLINE_EXPERIMENT.md). Keep TEST sealed until the final evaluation. Only then compare the separately trained Zeek-schema model against fixed always-Normal/always-Attack references, and separately measure real event-to-alert/SOC timing. Dataset Mode's UNSW-NB15 benchmark remains untouched.

## 5. CI contract versus real acceptance

```powershell
py -3.12 -m pytest -q tests/test_first_vmware_session_contract.py
```

This regression checks that the runbook still references existing scripts and actual CLI flags. It **does not** execute VMware, Zeek, tcpdump, traffic, labels, AI scoring, or SOC cases. CI passing is never evidence that the student ran this procedure on Windows 11.


## 6. Optional private session evidence index (operator review, not attestation)

After step 3 succeeds, save its **unmodified JSON stdout** as
C:/DA005-private/session-001/chain.json (on Windows PowerShell 5.1,
use a pipeline to Set-Content -Encoding UTF8 and immediately check
that $LASTEXITCODE equals 0; a failed command is not a valid report).
Record the chain file's SHA-256 independently in the private notebook.
This index does **not** re-run step 3; its chain check validates a
hash-pinned report's expected fields, not whether the report was authentic.

Place four **private** supporting files beside session-record.json:
a written approval/scope note (approval.txt), VMware adapter assignment
screenshots (vmware-nics.png), guest routes/NIC screenshots or saved text
(guest-routes.txt), and a dated capture-command/origin note
(capture-origin.txt). Include actual operator, time, network scope,
interface, command and original PCAP/Zeek SHA-256 in the private notes;
do not commit or publish them. Each supporting file must be nonempty,
at most 4 MiB, and SHA-256-pinned. Each PASS role must reference a
**different resolved file path**; reusing one pinned file for multiple
roles is rejected even if its SHA-256 is valid. Distinct files with
identical bytes are not automatically rejected: file identity checks
cannot establish independent human evidence or content relevance.
For multiple screenshots, combine
the review into a bounded private PDF or text summary and hash that file;
the tool checks bytes only, not what the screenshot proves.

Create session-record.json **outside Git** with real lowercase hashes,
using forward-slash relative paths. Example schema only; placeholder hashes
are not valid evidence:

~~~json
{
  "record_version": 1,
  "session_id": "session-001",
  "checks": {
    "authorization": {"status": "PASS", "path": "approval.txt", "sha256": "<ACTUAL_SHA256>"},
    "vmware_hostonly_adapters": {"status": "PASS", "path": "vmware-nics.png", "sha256": "<ACTUAL_SHA256>"},
    "guest_route_review": {"status": "PASS", "path": "guest-routes.txt", "sha256": "<ACTUAL_SHA256>"},
    "capture_origin": {"status": "PASS", "path": "capture-origin.txt", "sha256": "<ACTUAL_SHA256>"}
  }
}
~~~

Use {"status": "FAIL"} or {"status": "NOT_MEASURED"} for
incomplete checks; **never** mark PASS without a supporting file.
Record the finished JSON's SHA-256 separately, before validation.
From the project root:

~~~powershell
Get-FileHash 'C:/DA005-private/session-001/chain.json' -Algorithm SHA256
Get-FileHash 'C:/DA005-private/session-001/session-record.json' -Algorithm SHA256
py -3.12 scripts/verify_vmware_session_record.py --record 'C:/DA005-private/session-001/session-record.json' --expected-record-sha256 '<RECORD_SHA256_LOWERCASE>' --chain-report 'C:/DA005-private/session-001/chain.json' --expected-chain-sha256 '<CHAIN_SHA256_LOWERCASE>'
~~~

Exit 0 means the supplied record is complete and hash-consistent
**for subsequent human review**, not certified isolation or approval.
Exit 2 means a valid but incomplete FAIL/NOT_MEASURED checklist;
exit 1 means invalid input, untrusted report shape, hash mismatch or
unsafe path. The CLI reads only private local files, never connects to
a network, never exports private paths or IPs in stdout, and never
writes an output file. Hashes cannot prove that the operator's claims,
timestamps, approval or capture source are truthful. The signed-off
human review and original evidence remain mandatory.

Synthetic-only developer test:

~~~powershell
py -3.12 -m pytest -q tests/test_vmware_session_record.py
~~~
