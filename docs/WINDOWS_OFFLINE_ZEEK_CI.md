# DA005 — Windows offline Zeek software acceptance (CI)

This workflow runs a **software-only** cross-platform regression on a GitHub-hosted
Windows Server 2022 runner using **Python 3.12.9**. It is independent of the
Ubuntu/real-Zeek CI and does not replace it.

## Scope and evidence

`.github/workflows/windows-offline-zeek.yml` compiles the existing Python
source and executes targeted synthetic tests for the offline PCAP import contract,
pinned PCAP/Zeek provenance gates, lab-specific inference, analyst-confirmed
SQLite SOC case creation, aggregate telemetry quality, and manifest/holdout
research evaluation. It uses the production Python modules and existing test
fixtures. It does **not** run the Zeek binary, attach a network interface,
generate traffic, operate VMware, use the official UNSW-NB15 dataset, or
authenticate any Attack/Normal labels. The PCAP importer tests mock the Zeek
subprocess; Linux CI separately exercises real Zeek on benign synthetic PCAP.

The workflow runs on relevant pull requests or manual dispatch and uses
ephemeral runner files only. It uploads no private logs, PCAPs, models, cases
or credentials. A green workflow demonstrates **Windows CI compatibility for
the tested offline Python paths only**; it does not establish that the student's
Windows 11 laptop, VMware Host-only topology, Linux Zeek installation, live
capture or attack detection is working.

## Reproduce on the student's Windows 11 laptop

From the repository root in PowerShell, with Python 3.12.9 installed:

```powershell
py -3.12 -m pip install -r requirements-app.txt
py -3.12 -m pytest -q tests/test_zeek_lab_cli.py tests/test_zeek_telemetry_quality.py tests/test_offline_pcap_import.py tests/test_offline_pcap_scoring_gate.py tests/test_offline_pcap_soc_triage_gate.py tests/test_zeek_new_log_inference.py tests/test_zeek_manual_triage.py
```

Record `py -3.12 --version`, the command, exit code and screenshots locally.
Then **separately** verify VMware Host-only adapters/routes, run the real Zeek
offline smoke in the Linux VM, capture authorized traffic and pin its hashes
outside the public repository. Only independently labeled, host/session-disjoint
captures can support Precision/Recall/FPR and event-to-SOC latency research.

No change to Dataset Mode's official UNSW-NB15 benchmark, trained models,
operational alert policy or active Red Team execution is introduced here.
