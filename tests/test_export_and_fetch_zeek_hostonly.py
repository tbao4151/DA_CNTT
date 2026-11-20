"""Network-free contract checks for bounded guest Zeek export plus SCP."""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import export_and_fetch_zeek_hostonly as module

REMOTE = "/home/da005/da005-private-logs/conn-20261119T181442.log"
SHA = "a" * 64


def files(tmp_path):
    known = tmp_path / "known_hosts"
    known.write_text("192.168.77.20 ssh-ed25519 TESTONLY\n", encoding="utf-8")
    identity = tmp_path / "id_ed25519_da005"
    identity.write_text("SYNTHETIC ONLY", encoding="utf-8")
    return dict(
        host="192.168.77.20", cidr="192.168.77.0/24",
        username="da005", known_hosts=known,
        identity_file=identity, output_dir=tmp_path,
    )


def test_defaults_to_offline_dry_run_without_ssh_or_scp(monkeypatch, tmp_path):
    monkeypatch.setattr(module.subprocess, "run",
                        lambda *_a, **_k: pytest.fail("No SSH in dry run"))
    monkeypatch.setattr(module.collector, "fetch",
                        lambda **_k: pytest.fail("No SCP in dry run"))
    result = module.export_and_fetch(**files(tmp_path))
    assert result["ssh_executed"] is False
    assert result["network_activity_performed"] is False


@pytest.mark.parametrize("change", [
    {"host": "8.8.8.8"},
    {"cidr": "0.0.0.0/0"},
    {"host": "192.168.78.20"},
    {"username": "root"},
    {"timeout": 0},
    {"identity_file": Path("/not/a/real/key")},
])
def test_unsafe_inputs_fail_before_ssh(monkeypatch, tmp_path, change):
    monkeypatch.setattr(module.subprocess, "run",
                        lambda *_a, **_k: pytest.fail("No SSH"))
    params = {**files(tmp_path), **change}
    with pytest.raises((ValueError, OSError)):
        module.export_and_fetch(
            **params, execute=True, operator_confirmed_hostonly=True
        )


def test_execution_requires_explicit_operator_confirmation(monkeypatch, tmp_path):
    monkeypatch.setattr(module.subprocess, "run",
                        lambda *_a, **_k: pytest.fail("No SSH"))
    with pytest.raises(ValueError, match="confirm"):
        module.export_and_fetch(**files(tmp_path), execute=True)


def test_fixed_privileged_helper_and_host_key_pin_are_enforced(monkeypatch, tmp_path):
    params = files(tmp_path)
    commands = []

    def ssh(argv, **kwargs):
        commands.append(("ssh", argv, kwargs))
        return subprocess.CompletedProcess(
            argv, 0, f"DA005_ZEEK_SNAPSHOT_V1 {REMOTE} {SHA}\n", ""
        )

    def fetch(**kwargs):
        commands.append(("scp", kwargs))
        return {
            "log_sha256": SHA,
            "local_log_filename": "zeek_conn_20261119T181447Z_84e9786e815b.log",
            "flow_count": 2,
        }

    monkeypatch.setattr(module.subprocess, "run", ssh)
    monkeypatch.setattr(module.collector, "fetch", fetch)
    result = module.export_and_fetch(
        **params, execute=True, operator_confirmed_hostonly=True,
    )
    assert [c[0] for c in commands] == ["ssh", "scp"]
    argv = commands[0][1]
    assert argv[-1] == "sudo -n /usr/local/sbin/da005-export-zeek-snapshot"
    assert argv[-2] == "da005@192.168.77.20"
    assert argv[argv.index("-i") + 1] == str(params["identity_file"])
    assert "IdentitiesOnly=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert f"UserKnownHostsFile={params['known_hosts']}" in argv
    assert "PasswordAuthentication=no" in argv
    assert "ForwardAgent=no" in argv
    assert commands[1][1]["remote_path"] == REMOTE
    assert commands[1][1]["identity_file"] == params["identity_file"]
    assert result["guest_export_and_scp_sha256_consistent"] is True
    assert result["fresh_relative_to_probe_utc_independently_verified"] is False
    assert result["attack_detection_verified"] is False
    assert result["blue_ai_executed"] is False


@pytest.mark.parametrize("stdout", [
    "INVALID\n",
    "",
    f"DA005_ZEEK_SNAPSHOT_V1 /etc/shadow {SHA}\n",
    f"DA005_ZEEK_SNAPSHOT_V1 {REMOTE} {'X'*64}\n",
    f"DA005_ZEEK_SNAPSHOT_V1 {REMOTE} {SHA}\nextra\n",
    f"DA005_ZEEK_SNAPSHOT_V1 {REMOTE};touch /tmp/x {SHA}\n",
    f"DA005_ZEEK_SNAPSHOT_V1 {REMOTE} {SHA}\n" + "A"*600,
])
def test_invalid_helper_receipt_prevents_scp(monkeypatch, tmp_path, stdout):
    monkeypatch.setattr(
        module.subprocess, "run",
        lambda argv, **_kw: subprocess.CompletedProcess(argv, 0, stdout, ""),
    )
    monkeypatch.setattr(module.collector, "fetch",
                        lambda **_k: pytest.fail("No SCP after invalid receipt"))
    with pytest.raises((ValueError, RuntimeError)):
        module.export_and_fetch(
            **files(tmp_path), execute=True, operator_confirmed_hostonly=True
        )


def test_guest_export_failure_does_not_fetch(monkeypatch, tmp_path):
    monkeypatch.setattr(
        module.subprocess, "run",
        lambda argv, **_kw: subprocess.CompletedProcess(argv, 1, "", "sudo failed"),
    )
    monkeypatch.setattr(module.collector, "fetch",
                        lambda **_k: pytest.fail("No SCP when sudo failed"))
    with pytest.raises(RuntimeError, match="refused"):
        module.export_and_fetch(
            **files(tmp_path), execute=True, operator_confirmed_hostonly=True
        )


def test_mismatched_guest_and_scp_hash_fails_without_success(monkeypatch, tmp_path):
    monkeypatch.setattr(
        module.subprocess, "run",
        lambda argv, **_kw: subprocess.CompletedProcess(
            argv, 0, f"DA005_ZEEK_SNAPSHOT_V1 {REMOTE} {SHA}\n", ""
        ),
    )
    monkeypatch.setattr(
        module.collector, "fetch",
        lambda **_kw: {"log_sha256": "b"*64, "flow_count": 2},
    )
    with pytest.raises(RuntimeError, match="differs"):
        module.export_and_fetch(
            **files(tmp_path), execute=True, operator_confirmed_hostonly=True,
        )


def test_guest_helper_root_lock_is_not_in_world_writable_lock_dir():
    helper = (ROOT / "scripts" / "guest" / "da005-export-zeek-snapshot.sh").read_text(encoding="utf-8")
    assert "LOCK=/run/da005-zeek-export.lock" in helper
    assert "LOCK=/run/lock/" not in helper
    assert "exec 9>" in helper
    assert "flock -n 9" in helper


def test_guest_helper_is_checked_out_with_lf_even_on_windows():
    helper = ROOT / "scripts" / "guest" / "da005-export-zeek-snapshot.sh"
    raw = helper.read_bytes()
    assert raw.startswith(b"#!/usr/bin/env bash\n")
    assert b"\r" not in raw, "Git must checkout guest helpers with LF, not CRLF"
    attr = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "scripts/guest/*.sh text eol=lf" in attr


def test_guest_helper_has_valid_bash_syntax_when_bash_available():
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash unavailable on this runner")
    helper = ROOT / "scripts" / "guest" / "da005-export-zeek-snapshot.sh"
    assert subprocess.run(
        [bash, "-n", str(helper)], check=False,
        capture_output=True, timeout=5,
    ).returncode == 0
