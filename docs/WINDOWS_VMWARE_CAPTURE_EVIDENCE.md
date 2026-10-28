# DA005 — Private Windows/VMware Zeek capture evidence inventory

This is a **read-only, offline** evidence-recording helper for a student-owned,
authorized VMware Host-only experiment. It does not configure VMware, capture
packets, generate traffic, verify isolation, infer attack labels, fit a model,
create SOC cases or measure detection latency. Do not run active Red Team
scenarios until the isolated environment has been independently checked.

## Collect original evidence manually

Create a private folder **outside the Git repository**, for example
`C:/DA005-private/capture-001/`. Preserve these original files without
editing them after capture:

1. `conn.log`: the actual Zeek ASCII log from an authorized capture. Record
   its SHA-256 separately in your lab notebook **before** running this tool.
2. `vmware-network.png`: screenshot of VMware Virtual Network Editor showing
   the selected VMnet is Host-only, with its actual subnet and NAT/bridged
   settings visible. Verify every participating VM uses only the intended
   Host-only adapter; retain those settings as additional private evidence.
3. `host-adapter.png`: screenshot of Windows network adapters and relevant
   VMware VMnet adapter details. Verify guest routes, internet connectivity
   restrictions and the physical network boundary manually; a screenshot
   cannot prove that a second adapter or route is absent.
4. `zeek-version.txt`: saved terminal output of `zeek --version` from the
   machine where Zeek ran. If Zeek is unavailable, do not fabricate this file
   or call the capture verified.
5. `scenario-notes.txt`: a dated operator notebook entry stating who
   authorized the session, VM/host identifiers, capture start/end, local
   clock/timezone, VMnet/CIDR, normal activity, approved non-destructive
   scenario, capture command and independent label evidence references.
   Do not infer Attack labels from AI scores or port numbers.

PNG/JPEG signature checks are only file-type sanity checks, not image
authenticity checks. The helper records SHA-256 and byte length for each
supporting file without copying or embedding screenshots, IPs, UIDs, notes
or absolute private paths into its report.

## Execute on Windows Python 3.12.9

Run from the project root, after recording the original log hash:

```powershell
py -3.12 --version
Get-FileHash "C:/DA005-private/capture-001/conn.log" -Algorithm SHA256

py -3.12 scripts/record_zeek_lab_capture.py `
  --log "C:/DA005-private/capture-001/conn.log" `
  --expected-log-sha256 "<64-character lowercase SHA-256 saved separately>" `
  --cidr "192.168.56.0/24" `
  --origin lab_capture `
  --vmware-screenshot "C:/DA005-private/capture-001/vmware-network.png" `
  --host-adapter-screenshot "C:/DA005-private/capture-001/host-adapter.png" `
  --zeek-version-file "C:/DA005-private/capture-001/zeek-version.txt" `
  --scenario-notes "C:/DA005-private/capture-001/scenario-notes.txt" `
  --output "C:/DA005-private/capture-001/evidence-inventory.json"
```

Replace the example CIDR with the actual canonical RFC1918 Host-only subnet.
For a replay or synthetic fixture, explicitly use `--origin offline_replay`
or `--origin synthetic`; never label these as live capture. The helper
checks that every Zeek source/destination IP belongs to one of the
operator-declared private CIDRs (repeat `--cidr` up to four times). It
rejects malformed/empty/oversized Zeek logs, wrong independent hash,
missing/empty evidence, duplicate evidence roles, non-PNG/JPEG screenshot
signatures and preexisting/public output paths. The JSON is created only
when all checks pass; it is never overwritten.

The report includes original log and evidence SHA-256, byte lengths,
Zeek-supplied first/last event timestamps, flow count, declared origin,
and explicit `false` values for isolation, authenticity, authorization,
scenario truth and detection. A passing report is **not** an independent
audit of those claims. Retain the raw originals, operator notebook and
the report privately. Do not commit them or paste sensitive screenshots
into public CI/PRs.

After collecting genuine independent captures, use
`docs/ZEEK_OFFLINE_EXPERIMENT.md` to create and validate annotations
and host/session-disjoint TRAIN/VALIDATION/TEST partitions. Only then
evaluate Blue Team AI on the untouched test/new capture. Offline batch
runtime is not event-to-alert latency.

## Software tests (not student lab evidence)

```powershell
py -3.12 -m pytest -q tests/test_zeek_capture_evidence.py
```

CI fixtures are synthetic; they do not establish a VMware capture, network
isolation, authorization, true Attack labels, model generalization or
end-to-end SOC alerting.
