"""Network-free regression checks for read-only VMware Zeek log fetch."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_zeek_hostonly as mod


def sample_log(ip: str = "192.168.77.30") -> bytes:
    return (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\n"
        f"1730000100.125000\tCtest001\t{ip}\t51234\t192.168.77.20\t80\ttcp\thttp\t0.142\t412\t1890\tSF\t6\t5\n"
    ).encode("utf-8")


@pytest.mark.parametrize("host,cidr", [
    ("8.8.8.8", "192.168.77.0/24"),
    ("192.168.78.20", "192.168.77.0/24"),
    ("192.168.77.20", "0.0.0.0/0"),
    ("192.168.77.20", "192.168.77.0/16"),
    ("192.168.77.0", "192.168.77.0/24"),
    ("192.168.77.20", "192.168.77.1/24"),
])
def test_reject_unauthorized_guest_scope(host, cidr):
    with pytest.raises(ValueError):
        mod.validate_guest(host, cidr)


def test_fetch_mock_writes_pinned_private_original_bytes(monkeypatch, tmp_path):
    known = tmp_path / "known_hosts"
    known.write_text("192.168.77.20 ssh-ed25519 TEST_ONLY_KEY\n", encoding="utf-8")
    output = tmp_path / "evidence"
    output.mkdir()
    raw = sample_log()
    args_seen = []

    def fake_run(argv, **kwargs):
        args_seen.extend(argv)
        assert kwargs["check"] is True
        assert kwargs["timeout"] == 45
        assert "StrictHostKeyChecking=yes" in argv
        assert "BatchMode=yes" in argv
        assert "-F" in argv
        Path(argv[-1]).write_bytes(raw)

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    receipt = mod.fetch(
        host="192.168.77.20",
        cidr="192.168.77.0/24",
        username="ubuntu",
        known_hosts=known,
        output_dir=output,
    )
    assert receipt["log_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["flow_count"] == 1
    assert receipt["host_only_isolation_verified"] is False
    assert receipt["attack_detection_performed"] is False
    assert receipt["capture_authenticity_verified"] is False
    logs = list(output.glob("zeek_conn_*.log"))
    reports = list(output.glob("zeek_conn_*.receipt.json"))
    assert len(logs) == len(reports) == 1
    assert logs[0].read_bytes() == raw
    assert json.loads(reports[0].read_text(encoding="utf-8"))["log_sha256"] == receipt["log_sha256"]
    assert not list(output.glob(".da005-fetch-*"))
    assert str(known) in " ".join(args_seen)


def test_refuse_out_of_scope_zeek_before_publish(monkeypatch, tmp_path):
    known = tmp_path / "known_hosts"
    known.write_text("host-key-test\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda argv, **kwargs: Path(argv[-1]).write_bytes(sample_log("10.1.1.3")),
    )
    with pytest.raises(ValueError, match="outside the declared lab scope"):
        mod.fetch(host="192.168.77.20", cidr="192.168.77.0/24",
                  username="ubuntu", known_hosts=known, output_dir=out)
    assert not list(out.glob("*.log"))
    assert not list(out.glob("*.receipt.json"))


def test_reject_unknown_remote_path_without_running_scp(monkeypatch, tmp_path):
    known = tmp_path / "known_hosts"
    known.write_text("host-key-test\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    def no_run(*_args, **_kwargs):
        raise AssertionError("SCP must not run")
    monkeypatch.setattr(mod.subprocess, "run", no_run)
    with pytest.raises(ValueError, match="not allowlisted"):
        mod.fetch(host="192.168.77.20", cidr="192.168.77.0/24",
                  username="ubuntu", known_hosts=known, output_dir=out,
                  remote_path="/etc/shadow")


@pytest.mark.parametrize("host,cidr", [
    ("127.0.0.2", "127.0.0.0/24"),
    ("169.254.10.5", "169.254.10.0/24"),
    ("100.64.1.3", "100.64.1.0/24"),
    ("192.0.2.10", "192.0.2.0/24"),
])
def test_reject_non_rfc1918_special_ranges(host, cidr):
    with pytest.raises(ValueError):
        mod.validate_guest(host, cidr)


def test_failed_receipt_write_rolls_back_published_log(monkeypatch, tmp_path):
    known = tmp_path / "known_hosts"
    known.write_text("192.168.77.20 ssh-ed25519 TEST_ONLY_KEY\\n", encoding="utf-8")
    out = tmp_path / "evidence"
    out.mkdir()
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda argv, **kwargs: Path(argv[-1]).write_bytes(sample_log()),
    )
    original_dump = mod.json.dump

    def fail_dump(*args, **kwargs):
        args[1].write('{"incomplete":')
        raise OSError("simulated disk failure")

    monkeypatch.setattr(mod.json, "dump", fail_dump)
    with pytest.raises(OSError, match="simulated disk failure"):
        mod.fetch(host="192.168.77.20", cidr="192.168.77.0/24",
                  username="ubuntu", known_hosts=known, output_dir=out)
    assert not list(out.glob("zeek_conn_*"))
    assert not list(out.glob(".da005-fetch-*"))


def test_operator_owned_private_snapshot_with_explicit_ssh_key(monkeypatch, tmp_path):
    known = tmp_path / "known_hosts"
    known.write_text("192.168.77.20 ssh-ed25519 TEST_ONLY_KEY\\n", encoding="utf-8")
    private_key = tmp_path / "id_ed25519_da005"
    private_key.write_text("TEST-ONLY-NOT-A-REAL-PRIVATE-KEY\\n", encoding="utf-8")
    output = tmp_path / "captures"
    output.mkdir()
    seen = []
    snapshot_path = "/home/da005/da005-private-logs/conn-20261119T161546.log"

    def fake_scp(argv, **kwargs):
        seen.extend(argv)
        Path(argv[-1]).write_bytes(sample_log())

    monkeypatch.setattr(mod.subprocess, "run", fake_scp)
    receipt = mod.fetch(
        host="192.168.77.20", cidr="192.168.77.0/24",
        username="da005", known_hosts=known, output_dir=output,
        remote_path=snapshot_path, identity_file=private_key,
    )
    assert receipt["remote_path"] == snapshot_path
    assert receipt["flow_count"] == 1
    assert receipt["attack_detection_performed"] is False
    assert seen[seen.index("-i") + 1] == str(private_key)
    assert "IdentitiesOnly=yes" in seen
    assert "PasswordAuthentication=no" in seen
    assert "KbdInteractiveAuthentication=no" in seen
    assert seen[-2] == f"da005@192.168.77.20:{snapshot_path}"


@pytest.mark.parametrize("remote_path", [
    "/home/other/da005-private-logs/conn-20261119T161546.log",
    "/home/da005/da005-private-logs/conn-20261119T161546.log;touch /tmp/x",
    "/home/da005/da005-private-logs/../conn-20261119T161546.log",
    "/home/da005/da005-private-logs/conn-20261119T161546.log/../secret",
    "/home/da005/da005-private-logs/conn-20261119T161546.log ",
    "/home/da005/da005-private-logs/conn-20261119T161546.txt",
    "/home/da005/da005-private-logs/conn-20261119T161546.log\\n",
    "/home/da005/da005-private-logs/conn-20261119-161546.log",
    "/etc/shadow",
])
def test_private_snapshot_remote_path_must_match_exact_owner_and_name(remote_path):
    with pytest.raises(ValueError, match="not allowlisted"):
        mod.validate_remote_path(remote_path, "da005")


def test_identity_must_be_existing_private_file_before_scp(monkeypatch, tmp_path):
    known = tmp_path / "known_hosts"
    known.write_text("test-key", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr(mod.subprocess, "run",
                        lambda *_a, **_kw: pytest.fail("No SCP for invalid key"))
    with pytest.raises(OSError):
        mod.fetch(
            host="192.168.77.20", cidr="192.168.77.0/24",
            username="da005", known_hosts=known, output_dir=output,
            identity_file=tmp_path / "missing-key",
        )
    assert not list(output.iterdir())


def test_snapshot_user_name_is_not_interchangeable():
    assert mod.validate_remote_path(
        "/home/da005/da005-private-logs/conn-20261119T161546.log", "da005",
    ).endswith(".log")
    assert mod.validate_remote_path(
        "/opt/zeek/logs/current/conn.log", "da005",
    ) == "/opt/zeek/logs/current/conn.log"
