# DA005: optional bounded guest Zeek snapshot export

Operator must review and install the root-owned helper manually on the
authorized Ubuntu VM. Neither this guide nor the Python script automatically
changes sudoers, VMware, or Zeek configuration.

The sudoers empty-argument marker (`""`) denies every argument to the helper.
The root-owned lock resides in /run, not a potentially writable /run/lock.
The helper accepts no arguments. It reads only
/opt/zeek/logs/current/conn.log (max 15 MiB), stores a temporary copy under
root-private /run, then drops privileges to write a new file under
/home/da005/da005-private-logs. Concurrent invocation and filename collision
are rejected; 100 snapshots per directory is the cap. Guest SHA-256 and
downloaded SHA-256 are checked for agreement, not independent provenance.

Never grant NOPASSWD: ALL or chmod 777 on Zeek logs. The sudo rule must
permit precisely /usr/local/sbin/da005-export-zeek-snapshot. Installing
privileged helpers increases risk, so inspect the complete source first.

## First: install helper, once

Windows PowerShell at E:\DA_CNTT (each line is a separate command):

~~~powershell
Set-Location "E:\DA_CNTT"
$key = Join-Path $HOME ".ssh\id_ed25519_da005"
$known = Join-Path $HOME ".ssh\known_hosts"
$helper = "E:\DA_CNTT\scripts\guest\da005-export-zeek-snapshot.sh"
Get-FileHash $helper -Algorithm SHA256
scp -F none -i $key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$known" $helper da005@192.168.77.20:/home/da005/da005-export-zeek-snapshot.stage
~~~

Ubuntu da005 SSH terminal:

~~~bash
cat /home/da005/da005-export-zeek-snapshot.stage
sudo install -o root -g root -m 0755 /home/da005/da005-export-zeek-snapshot.stage /usr/local/sbin/da005-export-zeek-snapshot
sudo bash -n /usr/local/sbin/da005-export-zeek-snapshot
sudo stat -c '%U:%G %a %n' /usr/local/sbin/da005-export-zeek-snapshot
printf '%s\n' 'da005 ALL=(root) NOPASSWD: /usr/local/sbin/da005-export-zeek-snapshot ""' | sudo tee /etc/sudoers.d/da005-zeek-export >/dev/null
sudo chown root:root /etc/sudoers.d/da005-zeek-export
sudo chmod 0440 /etc/sudoers.d/da005-zeek-export
sudo visudo -cf /etc/sudoers.d/da005-zeek-export
sudo visudo -c
~~~

Proceed only when root ownership and both sudoers tests succeed. Test the
helper once; this only copies an existing Zeek log, without generating probes:

~~~bash
sudo -n /usr/local/sbin/da005-export-zeek-snapshot
~~~

Expected stdout: exactly one DA005_ZEEK_SNAPSHOT_V1 line containing the
generated filename and a lowercase 64-hex SHA-256.

## Windows: one command to export then transfer after Zeek flushes

Use the command below only after manual Host-only isolation review:

~~~powershell
Set-Location "E:\DA_CNTT"
$python = ".\.venv\Scripts\python.exe"
& $python scripts/export_and_fetch_zeek_hostonly.py --host "192.168.77.20" --cidr "192.168.77.0/24" --user "da005" --known-hosts (Join-Path $HOME ".ssh\known_hosts") --identity-file (Join-Path $HOME ".ssh\id_ed25519_da005") --output-dir "E:\DA005_Private\captures" --execute --operator-confirmed-hostonly
if ($LASTEXITCODE -ne 0) { throw "GUEST_EXPORT_OR_SCP_FAILED" }
~~~

Without both execution/confirmation switches, the Python command does NOT
connect. Check the log and receipt with verify_vmware_snapshot_bundle.py.
The helper cannot prove that newly exported Zeek flows contain all preceding
Red probes or that a Blue model detected an attack.

This command automates export plus SCP only. It has intentionally not been
wired to operator profile v3 or One-Click GUI until actual VMware acceptance.
No labeled Zeek Blue model, SOC alerts, or operational attack detection are
created by this enhancement.

## Rollback

The operator may remove only /etc/sudoers.d/da005-zeek-export and the
installed root-owned /usr/local/sbin/da005-export-zeek-snapshot after
independent review. Do not delete original Zeek captures or receipts.
