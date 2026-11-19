# DA005 — JSONL progress for operator-assisted VMware stepwise testing

This new optional output makes local execution stages observable as newline-delimited JSON. It does NOT turn the test into a full dual-AI One-Click mode or a live SOC detector. It does not alter the existing default CLI output or its safety gates.

## Offline dry-run

From repository root in Windows PowerShell:

    py -3.12 scripts/run_vmware_stepwise.py --source-ip 192.168.77.1 --target-ip 192.168.77.20 --cidr 192.168.77.0/24 --scenario connection_shift --user YOUR_UBUNTU_USER --known-hosts "$HOME\.ssh\known_hosts" --output-dir 'E:\DA005_Private\captures' --progress-jsonl

The addresses above are historic **examples**, not verified current addresses. Dry-run does not open a socket, issue SCP, score a model, or create evidence. It emits one preflight/dry_run event and a terminal dry_run summary.

## Operator-assisted live benign traffic, only after local verification

Verify VMware VMnet Host-only isolation, Windows adapter and route, Ubuntu NIC/route/Zeek capture interface, SSH host key, and a PRIVATE evidence directory outside Git. Only then add the explicit --execute --operator-confirmed-hostonly flags to the same command. Probe scope and count remain bounded by the existing orchestrator. This is not a vulnerability exploit or an attack.

Each stage event identifies its kind, monotonic sequence, UTC timestamp, stage, status, and bounded aggregate counts. Red is fixed *benign* probe generation; Zeek is SCP of the original snapshot; Blue either skips or completes separately pinned Zeek v1 offline research scoring; Audit is candidate UID screening; SOC is always skipped. Stage completion means the relevant program call completed, not that physical isolation, packet-to-flow causation, ground truth, or model validity have been independently established.

When a valid private Zeek v1 model exists, provide both --model PATH and --expected-model-sha256 SHA256. Without both, Blue is skipped. Research predictions must not be portrayed as confirmed attacks or automated alerts.

All progress events explicitly carry:
- vmware_isolation_verified: false
- attack_executed: false
- ai_attack_planning_executed: false
- operational_ai_detection_verified: false
- soc_alerts_created: false

The JSONL terminal summary exposes only bounded aggregate counts and explicit false verification flags; unlike the legacy non-JSONL CLI output, it must not expose private IPs, capture paths, receipts or model paths. Keep the legacy report local as it can contain sensitive scope information.\n\nIf the operator-assisted run fails, the CLI prints a generic terminal refusal event and returns a nonzero exit code. Do not upload raw stdout, private network addresses, model paths, original captures, or receipts to public Git.

## Test without sockets

    py -3.12 -m pytest -q tests/test_vmware_stage_progress.py tests/test_vmware_stepwise.py

The next integration step is a separately reviewed local bridge from stage JSONL to a dedicated VMware dashboard session. Synthetic replay SSE must remain isolated and must never be rebranded as captured live evidence.
