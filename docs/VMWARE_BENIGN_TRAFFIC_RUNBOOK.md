# DA005 — Benign Host-only Traffic: first live Zeek capture experiment

This is a **real but benign test traffic generator** for the student's explicitly authorized, isolated VMware lab. It does NOT exploit vulnerabilities, launch an attack, choose scenarios with AI, infer from logs, or create SOC alerts. It is an ingredient for a later end-to-end Red Team → Zeek → Blue Team experiment.

## Required operator preflight

1. Independently confirm the Windows VMnet2 Host-only adapter and Ubuntu guest are on the SAME isolated CIDR; confirm guest has no internet/default egress through unintended adapters. Keep snapshots of Windows `ipconfig /all`, `route print -4`, and Ubuntu `ip -4 addr`, `ip route`, plus VMware Network Editor.
2. Confirm Ubuntu's actual Host-only interface and Zeek capture interface. A Zeek instance monitoring another interface will not record this traffic.
3. Use the real Windows VMnet2 IPv4 for `--source-ip` and the Ubuntu Host-only IPv4 for `--target-ip` (historical example: Windows 192.168.77.1 / Ubuntu 192.168.77.20 / CIDR 192.168.77.0/24). Verify them in the actual guest rather than assuming.
4. Create `E:\DA005_Private\captures` OUTSIDE the repository for private receipts, logs and screenshots; never push these files to Git.
5. To test `baseline_web`, explicitly start a benign test HTTP server on the Ubuntu guest: `python3 -m http.server 8080 --bind 192.168.77.20`. It serves files from its current directory: use a dedicated empty temporary directory (e.g. `mkdir -p /tmp/da005-http && cd /tmp/da005-http`) to avoid exposure. Do not use this command on an Internet-exposed interface.
6. `connection_shift` only does one TCP connect-and-close on the guest's known SSH port 22, never attempts authentication. `dns_variation` sends one nonrecursive DNS question for `da005.invalid` to guest port 53; if no DNS service is running, a timeout is EXPECTED. Do not run DNS tests before confirming guest route isolation.

## Start with DRY-RUN (no network)

From repository root in Windows PowerShell:

```powershell
py -3.12 scripts/run_hostonly_benign_traffic.py --source-ip 192.168.77.1 --target-ip 192.168.77.20 --cidr 192.168.77.0/24 --scenario baseline_web
```

Dry-run prints `DRY_RUN_EXECUTION_OFF`; emits no packets and creates no receipt.

## Bounded actual test, only after preflight

```powershell
py -3.12 scripts/run_hostonly_benign_traffic.py --source-ip 192.168.77.1 --target-ip 192.168.77.20 --cidr 192.168.77.0/24 --scenario baseline_web --count 3 --delay-ms 1000 --execute --operator-confirmed-hostonly --output-dir 'E:\DA005_Private\captures'
```

The source IP must exist on the Windows Host-only adapter. The destination port is fixed by the scenario: `baseline_web` → TCP 8080, `dns_variation` → UDP 53, `connection_shift` → TCP 22. The program refuses public destinations, different subnets, counts above 4, intervals under 500 ms, timeouts above 2 s, execution without explicit consent, and evidence locations inside Git. Every probe is sequential; there is NO scanning, exploitation, brute force, concurrency, or target discovery.

## Inspect raw evidence

On Ubuntu, check that Zeek is bound to the correct Host-only NIC and view the matching connection records in its `conn.log`. Then use the read-only SHA-pinned SCP fetcher from PR #399 and, if a separately verified Zeek v1 research model exists, the offline scoring bridge from PR #401. Match timestamp, two endpoint IPs, destination port, protocol and Zeek UID. Capture output snapshots and private file hashes.

**Critical distinction:** successful socket connection != Zeek capture != AI detection != confirmed attack. A generated receipt only records that Windows attempted benign traffic. Do not report any verified attack, Precision/Recall/F1 or One-Click live capability from this receipt.

## Network-free CI gate

```powershell
py -3.12 -m pytest -q tests/test_hostonly_benign_traffic.py
```

## Next steps after local acceptance

Connect this approved execution backend to the Red Team policy controller only with a verified per-session scope contract and explicit user opt-in; route original Zeek logs to an independently pinned Zeek v1 model and SOC review. After that, add Step-by-Step and One-Click orchestration plus abort/kill-switch verification. None of these later steps is claimed completed by this script.

## One command for the first real STEPWISE acceptance (manual mode, NOT One-Click AI)

After independently verifying Host-only isolation, Zeek capture NIC, SSH key and known_hosts, the following performs a **fixed benign probe → wait for Zeek flush → SCP snapshot**:

```powershell
py -3.12 scripts/run_vmware_stepwise.py --source-ip 192.168.77.1 --target-ip 192.168.77.20 --cidr 192.168.77.0/24 --scenario connection_shift --user YOUR_UBUNTU_USER --known-hosts "$HOME\.ssh\known_hosts" --output-dir 'E:\DA005_Private\captures' --attempts 2 --settle-s 2 --execute --operator-confirmed-hostonly
```

**Dry-run first:** omit `--execute --operator-confirmed-hostonly`; no packets or SSH activity occur. This first acceptance needs NO model; returned flow count is the WHOLE copied conn.log, not necessarily only flows generated in this session.

If there is a trusted private **Zeek v1 JSON model**, add both options:

```powershell
--model 'E:\DA005_Private\models\zeek_research.json' --expected-model-sha256 YOUR_PINNED_MODEL_SHA256
```

The model is validated **before any network probe**, and the subsequent Zeek research scoring is never reported as a confirmed attack or operational SOC alert. The first end-to-end acceptance remains an operator-assisted research process. The full autonomous two-AI One-Click workflow still requires verified session correlation, a secure Red Team controller, a model suitable for the lab and SOC evidence linkage.

CI now runs `tests/test_hostonly_benign_traffic.py` and `tests/test_vmware_stepwise.py` on Windows, both using network-free mocks. Real evidence must still come from the user's VM, not CI.
