# DA005 — single-command bounded benign probe -> fresh guest Zeek -> SCP -> UID candidate links

This is an **opt-in** extension to `scripts/run_vmware_stepwise.py`. It uses
the existing manually installed, root-owned
`/usr/local/sbin/da005-export-zeek-snapshot` helper. It does NOT install
the helper or alter Zeek, VMware networking, SSH keys or sudoers.

Prerequisites from the private VMware acceptance:
- Windows VMnet2 Host-only address: `192.168.77.1`.
- Ubuntu Zeek guest: `da005@192.168.77.20` on `192.168.77.0/24`.
- Existing private SSH key in the operator's `~/.ssh/id_ed25519_da005`.
- Existing pinned `~/.ssh/known_hosts`, checked out-of-band.
- Zeek is running and the root-owned helper passed Bash syntax, sudoers,
  and the actual snapshot→SCP SHA-256 acceptance.
- Operator independently verifies VMnet2 isolation **before execution**.
- No preexisting private `DA005_STOP.flag` when running executable work.

Unlike the legacy `--remote-path` option (which refers to an already
exported file), `--fresh-guest-snapshot` requests the root-owned guest
helper **after** the benign probe and bounded settle interval. The helper
exports only current Zeek `conn.log`, then the existing collector retrieves
and checks the guest-exported SHA-256. A local `.candidate-links.json` file
screens probe timestamps, source/target IPs, protocol and port against Zeek
UIDs. It is **not** causal packet evidence, ground truth or attack detection.

## Offline dry run (Windows PowerShell)

```powershell
Set-Location "E:\DA_CNTT"
$python = ".\.venv\Scripts\python.exe"
& $python scripts/run_vmware_stepwise.py `
  --source-ip "192.168.77.1" --target-ip "192.168.77.20" `
  --cidr "192.168.77.0/24" --scenario connection_shift `
  --user da005 --known-hosts (Join-Path $HOME ".ssh\known_hosts") `
  --identity-file (Join-Path $HOME ".ssh\id_ed25519_da005") `
  --output-dir "E:\DA005_Private\captures" `
  --attempts 2 --settle-s 2 --fresh-guest-snapshot
if ($LASTEXITCODE -ne 0) { throw "STEPWISE_DRY_RUN_FAILED" }
```

Without both execute/confirmation flags, this calls **no** network socket,
remote helper, SCP or Blue model. No private capture is created.

## Real, operator-authorized Host-only run

```powershell
Set-Location "E:\DA_CNTT"
$python = ".\.venv\Scripts\python.exe"
& $python scripts/run_vmware_stepwise.py `
  --source-ip "192.168.77.1" --target-ip "192.168.77.20" `
  --cidr "192.168.77.0/24" --scenario connection_shift `
  --user da005 --known-hosts (Join-Path $HOME ".ssh\known_hosts") `
  --identity-file (Join-Path $HOME ".ssh\id_ed25519_da005") `
  --output-dir "E:\DA005_Private\captures" `
  --attempts 2 --settle-s 2 --fresh-guest-snapshot `
  --progress-jsonl --execute --operator-confirmed-hostonly
if ($LASTEXITCODE -ne 0) { throw "STEPWISE_FRESH_GUEST_FAILED" }
```

Expected progress stage values: preflight, red, zeek, blue (skipped), audit,
soc (skipped). The terminal result must show
`fresh_guest_snapshot_export_performed=true`, `ssh_fetch_performed=true`
and a private `candidate_links_file`; the candidate match count may be
lower than the number of attempted probes if packet visibility, clocks or
capture flush differ. Do not silently replace unmatched flows.

## Zeek conn.log may appear minutes after a short TCP probe

Zeek can defer a conn.log record until connection termination or an inactivity
timer. The original 2-second settle is not a proof that the guest has flushed
the two probe records. If a verified Host-only test produces two successful
Red socket receipts but export sees no current conn.log, use the explicit,
bounded extra grace interval:

```powershell
# Add to an authorized, executable --fresh-guest-snapshot command:
--zeek-wait-s 165
```

This adds a fixed 0..180-second **optional** delay after the normal 0..5s
settle and before requesting **exactly one** privileged snapshot. The delay
checks the private STOP marker every second. Dry-run still performs no socket
activity or waiting, and non-fresh modes reject this argument. It is a
reliability workaround, NOT low-latency detection: real-time SOC requires a
separate live Zeek event ingestion and Blue inference path. The 165-second
value is evidence-driven from a single observed lab run, not a portable
Zeek flush guarantee. Existing snapshots and receipt SHA-256 must be
preserved; never overwrite a failed JSONL session or claim that an unmatched
UID was detected.

## Fresh export acceptance requires correlation, not merely SCP

On 2026-11-22 a real operator run produced a complete 9-stage JSONL
and verified 3 Zeek flows, but both new TCP probes from 06:01:16-17Z
had **zero** UID candidates in the exported snapshot. The snapshot
contained only much earlier 00:10 and 00:22Z Zeek flow timestamps.
A 165-second wait did not fix this observation. This does **not**
demonstrate an SSH failure or imply that Zeek is functioning as a
current network capture source.

Fresh-helper sessions now fail closed if `unmatched_probe_count != 0`
after successful snapshot and UID screening. The private original
log, SCP receipt and `.candidate-links.json` are still preserved;
the JSONL includes `audit.completed` with the candidate/unmatched
counters followed by a terminal `refused` (not `completed`).
A static, redacted `DA005_ZEEK_UID_MATCH_INCOMPLETE` stderr code
distinguishes this from generic preflight failure without leaking
local paths or packet content. This screen is still only candidate
matching by tuple and timestamp, never causality proof.

If this occurs, do **not** keep increasing `--zeek-wait-s`. Check
the guest's current `conn.log` record timestamps, Zeek's live
ens33 interface and packet counters, and any capture filters/rotated
logs before running another full stepwise session. Do not mark any
failed session as a completed lab or operational AI detection.

## Safety / model boundary

The fresh-helper mode presently **refuses** `--model` or a custom
`--remote-path`; it only supports the actual `da005` SSH user and a
private pinned identity file. These checks happen BEFORE benign traffic,
even in dry-run. The original (non-fresh) Zeek SCP and optional pinned Blue
research CLI remain unchanged. A future Blue integration must reuse a
verified data-only model and exclude training flows from scoring; it must
not claim real detection just because stepwise transport and matching pass.

Actual service availability, physical isolation, guest log authenticity,
packet-to-UID causality, and operational SOC alerting remain separately
unverified. Never put private receipts, SSH keys or model artifacts into Git.
