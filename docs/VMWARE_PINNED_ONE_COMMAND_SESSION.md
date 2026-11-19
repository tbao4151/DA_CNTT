# DA005 — One-command VMware operator-assisted session

This launcher reduces the previous long command to one invocation over a SHA-256-pinned private JSON profile. It does NOT configure VMware, certify Host-only isolation, create attacks, train AI or automatically create SOC cases. Only the existing safe bounded benign Red -> Zeek SCP -> optional pinned Blue research pipeline can execute. The default is a dry-run with no sockets or SCP.

## Step 1 — Create a private profile on Windows 11

Create a folder outside the Git repository:

    New-Item -ItemType Directory -Force 'E:\DA005_Private\captures' | Out-Null

Create E:\DA005_Private\captures\operator-profile.json with this example, then replace all machine/user paths and addresses with the exact values confirmed on YOUR laptop and VMware. The IPs below are historical examples only and must NOT be assumed correct. Use forward slashes in JSON Windows paths or escape every backslash twice.

    {
      "version": 1,
      "source_ip": "192.168.77.1",
      "target_ip": "192.168.77.20",
      "cidr": "192.168.77.0/24",
      "scenario_id": "connection_shift",
      "username": "ubuntu",
      "known_hosts": "C:/Users/YOUR_WINDOWS_USER/.ssh/known_hosts",
      "output_dir": "E:/DA005_Private/captures",
      "stop_file": "E:/DA005_Private/captures/DA005_STOP.flag",
      "attempts": 2,
      "settle_s": 2,
      "model_path": null,
      "expected_model_sha256": null
    }

scenario_id can only be connection_shift (TCP connect/close without SSH authentication), baseline_web (HTTP HEAD to a pre-existing owned port 8080 service), or dns_variation (nonrecursive DNS query to fixed guest port 53 and reserved .invalid hostname). The launcher never accepts arbitrary targets, shell commands or port scanning. Attempts are limited to 1–4. The profile never contains an SSH password/private key.

Blue research is optional: model_path and expected_model_sha256 must both be set to an already existing, independently hashed, privately stored compatible Zeek research model. Leaving them null makes the Blue stage SKIPPED, not zero detections. Research candidates are not verified attacks or SOC alerts. The offline UCB1 planner is not wired into execution; operator chooses the fixed benign scenario.

**Optional UCB1 bridge:** Profile v2 retains all v1 fields but adds a strictly validated `red_policy` object. Its deterministic proposal must exactly match the operator-approved `scenario_id` before the existing fixed benign runner can proceed; a private `.red-plan.json` receipt records this non-executable planning decision. See `docs/VMWARE_PINNED_RED_POLICY.md`. Profile v1 stays unchanged. No automatic exploitation or confirmed Blue feedback is implied.

## Step 2 — Pin the profile independently

After finalizing the JSON and before invoking the launcher, record the hash separately in your private notebook:

    (Get-FileHash 'E:\DA005_Private\captures\operator-profile.json' -Algorithm SHA256).Hash.ToLowerInvariant()

Do not edit the profile after recording its SHA-256; any modification requires re-review and a newly recorded digest. A matching hash verifies file bytes against the operator-supplied pin, not permission to run or physical network isolation.

## Step 2a — Check private profile readiness without making a session

After recording the independently calculated SHA-256, a safe local-only gate verifies the profile structure and, if configured, the private Blue Zeek v1 model's hash and schema. It creates **no JSONL**, Red plan receipt or session lock; it makes **no network requests**, predictions or SOC records.

```powershell
py -3.12 scripts/run_vmware_session_profile.py --config-file 'E:\DA005_Private\captures\operator-profile.json' --expected-config-sha256 $profileSha --validate-only
```

For a two-module research demo, **require** a privately stored, already available and independently SHA-256-pinned compatible Blue Zeek v1 model:

```powershell
py -3.12 scripts/run_vmware_session_profile.py --config-file 'E:\DA005_Private\captures\operator-profile.json' --expected-config-sha256 $profileSha --validate-only --require-blue-research
```

If `model_path` or `expected_model_sha256` is null, the second command **refuses** the profile. If a supplied Blue model is missing, tampered, unreadable or has an incompatible Zeek feature schema, it also refuses. The JSON output uses `blue_model_pinned_and_schema_verified` to distinguish model readiness from a model-free profile; it always records `network_activity_performed=false`, `vmware_isolation_verified=false` and `operational_ai_detection_verified=false`. Do **not** interpret readiness as real detection or physical isolation.

For an authorized actual session after independent VMware Host-only preflight, append `--require-blue-research` to the Step 4 launcher command as well. This prevents silently running Blue=SKIPPED when a model is required and refuses invalid Blue models **before** creating the progress JSONL or Red receipt and before attempting a packet. This flag does not auto-create or train a model and does not turn benign probes into cyberattacks. The ordinary optional-Blue dry-run remains backward-compatible.

## Step 2b — Bind the exact Windows VMnet adapter to the profile (offline)

The profile source address must match the actual VMware Host-only adapter used on Windows. After confirming the selected VMnet in VMware Virtual Network Editor **manually**, save a fresh v2 read-only adapter snapshot, without network traffic. Use the **actual adapter name**, for example VMnet2 rather than the historical VMnet1 examples elsewhere in the docs. Re-check the VMnet and guest interfaces after any switch between NAT and Host-only.

~~~powershell
$adapter = 'VMware Network Adapter VMnet2'  # Replace with the confirmed adapter
$hostPath = 'E:\DA005_Private\captures\host-vmnet2-001.json'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\collect_windows_hostonly_snapshot.ps1 -AdapterName $adapter -OutputPath $hostPath
$hostSha = (Get-FileHash $hostPath -Algorithm SHA256).Hash.ToLowerInvariant()
$profileSha = (Get-FileHash 'E:\DA005_Private\captures\operator-profile.json' -Algorithm SHA256).Hash.ToLowerInvariant()
py -3.12 scripts/run_vmware_session_profile.py --config-file 'E:\DA005_Private\captures\operator-profile.json' --expected-config-sha256 $profileSha --validate-only --host-snapshot $hostPath --expected-host-sha256 $hostSha --host-adapter $adapter
~~~

**Windows legacy IPv6 DNS placeholders (VMnet2):** Windows may report exactly
`fec0:0:0:ffff::1`, `fec0:0:0:ffff::2`, and
`fec0:0:0:ffff::3` as historical site-local DNS fallback addresses.
The read-only host preflight recognizes only this exact three-address set
(not subsets, duplicates, additional DNS servers, or default IPv6 routes)
and reports `host_ipv6_legacy_dns_placeholders_observed=true`. Do not
disable IPv6 or edit adapter DNS solely to force a blank list.
A placeholder exception is **not** evidence of unreachable DNS services,
safe physical isolation, or permission to run experiments; preserve and
independently inspect the original immutable host snapshot and actual VMware
configuration. Any effective IPv6 DNS or default route continues to fail closed.

The output includes \`host_snapshot_pinned_and_profile_bound=true\` only if the **independently hashed** v2 snapshot has the exact adapter name, active and unique host IPv4, matching CIDR/prefix and source IP from the operator profile, no adapter default routes or DNS, and no unsafe IPv6. A mismatch fails before writing private progress files. For a research two-module run also include \`--require-blue-research\`.

After **separate** manual authorization and inspection of all VMware/guest NICs, routes, IPv6, firewall/forwarding, SSH host key, Zeek capture and model, repeat the same \`--host-snapshot\`, \`--expected-host-sha256\`, \`--host-adapter\` arguments on the eventual Step 4 invocation **with** \`--execute --operator-confirmed-hostonly\`. The check is offline metadata consistency, not proof that the snapshot is current, that VMware truly isolates the VM or that the network experiment is authorized.

## Step 3 — Dry-run the entire local CLI path (network OFF)

From the project root on the Windows host, set $profileSha to the 64 lowercase characters you independently recorded, then run:

    py -3.12 scripts/run_vmware_session_profile.py --config-file 'E:\DA005_Private\captures\operator-profile.json' --expected-config-sha256 $profileSha --jsonl-file 'E:\DA005_Private\captures\session-001.jsonl'

This always creates a new UTF-8 JSONL evidence file, never overwriting an existing one. The dry-run output has a preflight/dry_run event and a dry_run terminal, with network_attempts=0 and Blue/SSH false. Open http://127.0.0.1:3000/vmware-progress in the locally running Next.js frontend to import or follow the JSONL. This is not a real Zeek or AI experiment.

## Step 4 — Operator-confirmed benign lab execution (only after manual preflight)

Do not add execution flags until you have independently confirmed: written authorization, VMware Virtual Network Editor Host-only VMnet, the actual host adapter source IP, the guest NIC and all routes, no unwanted NAT/bridged/secondary NICs, IPv4/IPv6 isolation and forwarding, Zeek's exact listening interface, SSH host-key pinning, output ACLs, and presence of any optional pinned research model. Run the existing offline preflight tools and archive screenshots/versions/hashes. A software preflight PASS is not a physical isolation certificate.

Verify DA005_STOP.flag is absent while no prior session is active, choose a new output filename, then run the same command with BOTH --execute --operator-confirmed-hostonly. Omitting either flag refuses network execution. If the fixed STOP marker exists, the launcher refuses an executable session before creating JSONL.

A second Windows PowerShell can request a cooperative STOP:

    New-Item -ItemType File -Path 'E:\DA005_Private\captures\DA005_STOP.flag' -Force

The local /vmware-progress UI can also create this fixed marker after explicit directory selection and second confirmation. It is not an instantaneous OS-level kill switch: a socket/SSH transfer already in flight may finish or time out. Partial benign attempts are privately archived with BENIGN_LAB_ABORTED and are not treated as completed sessions or accepted as Zeek correlation proof.

## Exclusive session lock (same private evidence directory)

The Python profile launcher now creates `DA005_ACTIVE_SESSION.lock` exclusively inside the approved private evidence folder **before** writing the optional Red plan or invoking the stepwise runner. A second launcher using the same folder refuses to start, even when it uses a different JSONL filename. The lock contains no credentials or IP addresses and is automatically removed on normal completion or a handled runner error, only if it is still the same file.

If Windows is forcibly terminated or loses power, the lock may remain. Treat it as a **fail-closed condition**: inspect Task Manager / running Python processes and preserve the existing JSONL and receipt before manually handling the lock. Never delete this lock while a session is active, and never assume a missing lock proves network isolation or a successful run. This mechanism coordinates only cooperating profile-launcher invocations in one directory; it does not lock all tools, other evidence directories or separate host processes.

## Step 5 — Independent post-run checks

    (Get-FileHash 'E:\DA005_Private\captures\session-001.jsonl' -Algorithm SHA256).Hash.ToLowerInvariant()

Run scripts/verify_vmware_progress_jsonl.py with its --expected-sha256 value. Preserve the original private file, exit code, exact software versions, Zeek log, model hash if used, PCAP when captured, and operator evidence notes. Follow docs/FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md and the other pinned snapshot checks. Do NOT include raw private paths, IP details or credentials in the published report or commit them to Git.

## Threat model and limitations

- All execution stays local to the explicitly approved Windows host and owned Host-only VM. No HTTP API execution endpoint is added.
- A corrupt, unknown-key, duplicate-key, oversized, symlinked, unpinned, nonprivate or out-of-scope JSON profile is refused. An already used progress file is never overwritten.
- The launcher cannot independently verify physical VMware network mode, source adapter/route, true packet provenance, correct labels, an operational AI detector or SOC alerts. It does not turn synthetic replay into a real cyberattack demonstration.
- All CI tests run network-free; their completed simulated runs are fixtures, never physical VMware capture evidence.


## Optional v3 profile: explicit Windows SSH key and operator-owned Zeek copy

Windows 11 operators may have a verified ED25519 key that is not one of the
OpenSSH default names, and the Zeek `conn.log` may be inaccessible to the
unprivileged guest account because `/opt/zeek/logs` belongs to the Zeek user.
Do **not** disable SSH host-key checks, chmod 777 or expose Zeek's entire
log directory to work around this. The v3 profile extends the **v1**
operator profile with exactly two new required keys:

- `"version": 3`
- `"ssh_identity_file": "C:/Users/USER/.ssh/id_ed25519_da005"`
- `"remote_zeek_path": "/home/da005/da005-private-logs/conn-20261119T161546.log"`

The paths here are examples that must be replaced with the operator's real,
existing files; no private key content belongs in the JSON. The original
profile v1/v2 schemas remain unchanged. Write a **new** profile JSON outside
Git and independently record its SHA-256; never rewrite the original pinned
profile or snapshot. The private identity must exist outside Git and be
nonempty and at most 64 KiB. The remote path is restricted to original Zeek
`conn.log` install paths or a basename matching exactly
`/home/<SSH-username>/da005-private-logs/conn-YYYYMMDDTHHMMSS.log`.
Unknown directories, another user's home, traversal, shell metacharacters
and arbitrary remote filenames are refused *before any probe*.

Create an approved snapshot on the **Ubuntu console or operator SSH
session**, where the operator has already verified Zeek is running and the
original file's scope. Example:

```bash
D=/home/da005/da005-private-logs
sudo install -d -m 0700 -o da005 -g da005 "$D"
SNAP="$D/conn-$(date -u +%Y%m%dT%H%M%S).log"
sudo install -m 0600 -o da005 -g da005 /opt/zeek/logs/current/conn.log "$SNAP"
sha256sum "$SNAP"
```

Write the **exact** resulting snapshot path into the new v3 profile. This
operation is operator-assisted and is not performed by the Windows
automation. The snapshot will not automatically grow when new traffic is
generated afterward. A v3 run therefore **cannot claim** that a snapshot
pre-dating the benign probes contains those new probes, even if the program
successfully downloads it. Inspect the private candidate link output for
unmatched attempts, original UIDs, actual timestamps and hashes. Future
live fresh-capture acceptance requires an independently reviewed privileged
guest-side export mechanism or scoped Zeek directory access and fresh,
per-session provenance; none is implied by this enhancement.

The transport uses `scp -F none -i ... -o IdentitiesOnly=yes`, strict pinned
`known_hosts`, BatchMode, and disabled password/keyboard-interactive
authentication. The operator's private key is never copied to the guest
or uploaded to GitHub. The private receipt contains the remote file path
and exact downloaded hash; it does not verify guest snapshot authenticity.

For an *offline-only* pinned v3 readiness check, use the existing launcher:

```powershell
$profile = 'E:\DA005_Private\captures\operator-profile-v3.json'
$profileSha = (Get-FileHash $profile -Algorithm SHA256).Hash.ToLowerInvariant()
py -3.12 scripts/run_vmware_session_profile.py --config-file $profile --expected-config-sha256 $profileSha --validate-only
```

On a laptop with a project virtual environment, replace `py -3.12` with
`& .\.venv\Scripts\python.exe`. For host adapter checks, also pass
`--host-snapshot`, `--expected-host-sha256` and `--host-adapter` as
documented in Step 2b. Use the distinct new v3 profile hash, not the old v1
hash. `operator_owned_ssh_snapshot_configured=true` is a configuration check
only; `fresh_post_probe_zeek_snapshot_verified=false`, `network_activity_performed=false`
and `vmware_isolation_verified=false` remain explicit.

**Important:** A pinned Zeek research model is **still** needed to enable the
Blue research inference stage; without a real independently labeled
TRAIN/VALIDATION/TEST Zeek experiment and an exported trusted model, Blue
is SKIPPED. The pinned v3 profile does not train a model, create attack
traffic, or provide live AI detection.
