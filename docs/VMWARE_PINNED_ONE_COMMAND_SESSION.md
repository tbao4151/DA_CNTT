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

## Step 2 — Pin the profile independently

After finalizing the JSON and before invoking the launcher, record the hash separately in your private notebook:

    (Get-FileHash 'E:\DA005_Private\captures\operator-profile.json' -Algorithm SHA256).Hash.ToLowerInvariant()

Do not edit the profile after recording its SHA-256; any modification requires re-review and a newly recorded digest. A matching hash verifies file bytes against the operator-supplied pin, not permission to run or physical network isolation.

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

## Step 5 — Independent post-run checks

    (Get-FileHash 'E:\DA005_Private\captures\session-001.jsonl' -Algorithm SHA256).Hash.ToLowerInvariant()

Run scripts/verify_vmware_progress_jsonl.py with its --expected-sha256 value. Preserve the original private file, exit code, exact software versions, Zeek log, model hash if used, PCAP when captured, and operator evidence notes. Follow docs/FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md and the other pinned snapshot checks. Do NOT include raw private paths, IP details or credentials in the published report or commit them to Git.

## Threat model and limitations

- All execution stays local to the explicitly approved Windows host and owned Host-only VM. No HTTP API execution endpoint is added.
- A corrupt, unknown-key, duplicate-key, oversized, symlinked, unpinned, nonprivate or out-of-scope JSON profile is refused. An already used progress file is never overwritten.
- The launcher cannot independently verify physical VMware network mode, source adapter/route, true packet provenance, correct labels, an operational AI detector or SOC alerts. It does not turn synthetic replay into a real cyberattack demonstration.
- All CI tests run network-free; their completed simulated runs are fixtures, never physical VMware capture evidence.
