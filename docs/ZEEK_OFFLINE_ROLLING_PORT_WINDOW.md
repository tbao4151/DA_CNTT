# DA005 — offline Zeek rolling port-diversity diagnostic

This standalone, **read-only** retrospective diagnostic is **not a trained Blue
AI model**, not a prediction of attack truth, not real-time SOC detection and
not a measured packet-to-alert latency. It is deliberately outside the frozen
9-feature Zeek v1 Logistic Regression model contract, so it does not change
Dataset Mode, thresholds, research artifact schemas, SOC cases or alerts.

The basic motivation is that a port scan is a **sequence of connections**,
whereas a single Zeek `conn.log` record can only show one destination port.

## Confirm the current 16-flow student lab cohort

Use Windows PowerShell, from `E:\DA_CNTT`, **after** the operator has
independently checked the private derived log and recorded its SHA-256:

```powershell
Set-Location "E:\DA_CNTT"

& ".\.venv\Scripts\python.exe" scripts/inspect_zeek_scan_windows.py `
  --log "E:\DA005_Private\zeek-experiment\reviewed-scan-001\conn.log" `
  --expected-log-sha256 "e8bd906e908fbb832f9731ecbe4df6fa5d1f320ef652191533aa9e4a42989825" `
  --labels "E:\DA005_Private\zeek-experiment\reviewed-scan-001\labels.json" `
  --cidr "192.168.77.0/24" `
  --window-seconds 10 `
  --min-distinct-ports 5

if ($LASTEXITCODE -ne 0) { throw "DA005_SCAN_WINDOW_DIAGNOSTIC_FAILED" }
```

Expected software interpretation from the operator-provided cohort is a
maximum 12 distinct destination ports within 10 seconds and potentially
eight candidate *flow positions* (positions 5 through 12 of the burst).
The first four scan connections intentionally do not meet the threshold;
no method sees into the future. Validate the **actual** output instead of
assuming these counts or reporting classification performance.

The CLI checks the exact source bytes against an independently supplied
SHA-256, private file placement outside Git, Zeek parser validity, the
private /16-or-narrower IPv4 CIDR, optional complete 0/1 annotation with a
matching log SHA-256, and bounded window parameters. No original file is
changed. It prints only aggregate JSON (no UIDs or endpoints); raw logs,
operator labels and independent evidence stay in private storage.

`rolling_port_diversity` sorts by Zeek `ts` (connection **start** time)
and counts previous TCP connection starts from the same source IP to the
same destination IP in an inclusive 10-second window. The result for each
event includes its own start but excludes future starts, and count is
by distinct destination port. It does not use current or future scenario
labels in calculations. However, because Zeek can publish `conn.log`
long after each start, this retrospective window does **not** guarantee
information was available to an actual online service at the event time.

The 16 flows share one controlled session: four operator-supplied benign
TCP 22 probes and twelve Nmap TCP connect-scan flows. Their labels are
scenario-derived; neither checksum nor code authenticates the independent
ground truth. The sample is inadequate for model generalization claims,
Precision/Recall estimates or a model comparison. Normal probes all
target port 22, so a naive classifier can exploit port rather than
recognizing scanning behavior. The `service` field is absent in all 16
flows, but must not be fabricated. Any future v2 model needs separately
collected, host/session-disjoint TRAIN, VALIDATION and sealed TEST sets,
normal traffic to varied ports, independent attack/benign review and an
explicit migration plan preserving the v1 artifact contract.
