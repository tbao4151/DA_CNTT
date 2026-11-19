# DA005 — Read-only VMware Zeek Fetch (pre-acceptance utility)

This is a **setup and verification runbook**, NOT a submission-ready project report.

## Purpose

Fetch a bounded copy of Ubuntu Zeek ASCII `conn.log` from an explicitly specified
VMware Host-only guest via OpenSSH SCP. Validate declared CIDR scope and
record a SHA-256 receipt in a private Windows directory. No attacks, AI
inference, alert, automatic SOC case or proof of physical isolation occur.

## Windows setup (after local Ubuntu Host-only VM is verified)

1. Confirm Ubuntu guest's static Host-only IPv4 matches your actual VMware
   configuration (historical example: 192.168.77.20/24). Do not copy this
   address blindly if the VM differs.
2. Ensure Zeek is configured to produce Zeek ASCII `conn.log`, and the SSH
   account has read permission on its actual log path. The utility only
   allows `/opt/zeek/logs/current/conn.log` or
   `/usr/local/zeek/logs/current/conn.log`.
3. Generate/verify SSH host fingerprint **out of band** on the Ubuntu console
   using `sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
   Prepare an SSH `known_hosts` file for the guest; independently verify
   its fingerprint. Never auto-accept unverified host keys.
4. Set up SSH key authentication for an unprivileged Zeek-reading account.
   BatchMode=yes intentionally refuses interactive password prompts.
5. Create a PRIVATE folder outside your Git repository for capture evidence,
   for example `E:\DA005_Private\captures`.

Run from the cloned Git repository (replace USER and private paths):

```powershell
py -3.12 scripts/fetch_zeek_hostonly.py --host 192.168.77.20 --cidr 192.168.77.0/24 --user USER --known-hosts "$HOME\.ssh\known_hosts" --output-dir "E:\DA005_Private\captures"
```

To test the validator without VMware/network, run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_fetch_zeek_hostonly.py
```

## Outputs and scientific boundaries

- A new `zeek_conn_*.log` containing original transferred bytes.
- A new `zeek_conn_*.receipt.json` with local SHA-256, flow count and times.
- `host_only_isolation_verified=false` and `attack_detection_performed=false`
  are intentional until independent verification and actual inference.
- File-based transfer is a snapshot, **not** a real-time packet stream. It
  does not itself complete One-Click Red/Blue orchestration.
- Current Zeek logs may grow during the SCP snapshot; preserve log closing
  boundaries and independently verify authenticity for final evaluation.
- Screenshots, adapter/routing evidence and original authorized PCAP/Zeek
  evidence must still be collected on the student laptop.
- Never commit raw private logs, model JSON, keys, case databases, or receipts.

## Next integration

Use the pinned log with the project's vetted Zeek v1 research scoring
pipeline and the manual review-to-SOC gate; add a real session adapter only
after G1 isolation and model/ground-truth validations are documented.
