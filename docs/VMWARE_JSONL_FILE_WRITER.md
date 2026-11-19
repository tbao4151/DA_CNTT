# DA005 — Private UTF-8 JSONL writer on Windows

This optional wrapper writes the operator-assisted VMware stage sequence directly to a new UTF-8 file, avoiding UTF-16 / OEM code page differences of PowerShell pipeline redirection. It calls the existing bounded scripts/run_vmware_stepwise.py CLI and introduces no other traffic generator, attack engine, scanner, or network service.

## Dry-run without VMware traffic

From PowerShell in the repository root:

    New-Item -ItemType Directory -Force 'E:\DA005_Private\captures' | Out-Null
    py -3.12 scripts/run_vmware_progress_file.py --jsonl-file 'E:\DA005_Private\captures\phase-001.jsonl' --source-ip 192.168.77.1 --target-ip 192.168.77.20 --cidr 192.168.77.0/24 --scenario connection_shift --user YOUR_UBUNTU_USER --known-hosts "$HOME\.ssh\known_hosts" --output-dir 'E:\DA005_Private\captures'

These IPs are historic examples and must be independently checked. Dry-run emits no packets, does not run Zeek SCP, and does not score a model. The saved file can be viewed at http://127.0.0.1:3000/vmware-progress.

The wrapper requires an absolute .jsonl path in an existing evidence directory outside the repository. It creates the file exclusively, rejects symlinks and emits complete UTF-8 lines as the CLI progresses. It never stores the raw private run_sequence response: only the redacted stage/provenance JSONL from PR #405.

## Controlled operator-assisted experiment

Only after independently verifying VMware VMnet isolation, Windows adapter and route, Ubuntu NIC and Zeek capture interface, the pinned guest SSH host key and evidence permissions may the operator supply both --execute and --operator-confirmed-hostonly. Those flags are forwarded to the existing CLI and checked there. Without both, the wrapper is a dry-run. Scenarios remain bounded benign probes, not a real attacker AI, exploit, verified SOC alert or proof of Blue model performance. Blue inference requires a separately pinned private Zeek v1 research model.

Dependency: the --progress-jsonl option is in PR #405; the viewer is PR #406. The wrapper is usable only after those are integrated.

On Chrome/Edge at localhost, use the local file picker on /vmware-progress to follow the private JSONL. It polls locally without upload.

## Test (no network)

    py -3.12 -m pytest -q tests/test_vmware_progress_file.py

Unit tests verify UTF-8, file exclusivity, path/symlink rejection and safe forwarding, with the underlying CLI mocked.
