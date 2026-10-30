"""Synthetic two-pass Zeek orchestration tests; Zeek binary is never launched."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import replay_zeek_twice_offline as runner
from test_zeek_reprocessing_compare import _log, _row, _tcp_pcap


def _setup(tmp_path):
    pcap = tmp_path / "owned.pcap"
    pcap.write_bytes(_tcp_pcap())
    args = [
        "--pcap", str(pcap),
        "--expected-pcap-sha256", hashlib.sha256(pcap.read_bytes()).hexdigest(),
        "--first-output-dir", str(tmp_path / "zeek-1"),
        "--second-output-dir", str(tmp_path / "zeek-2"),
        "--cidr", "10.1.1.0/24",
        "--confirm-offline-only",
    ]
    return pcap, args


def _fake_import(monkeypatch, *, second_port=80, fail_second=False, wrong_log_pin=False,
                 mutate_pcap=False):
    calls = []
    def fake(source, output, *, lab_cidrs, operator_confirmed_offline,
             timeout_seconds, zeek_executable=None):
        calls.append((source, output, tuple(lab_cidrs), operator_confirmed_offline,
                      timeout_seconds, zeek_executable))
        output.mkdir()
        index = len(calls)
        data = _log(_row(uid="FIRST" if index == 1 else "SECOND",
                         dport=str(second_port if index == 2 else 80)))
        (output / "conn.log").write_bytes(data)
        if fail_second and index == 2:
            raise ValueError("simulated Zeek failure")
        if mutate_pcap:
            source.write_bytes(source.read_bytes() + b"changed")
        return {
            "pcap_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "zeek_conn_sha256": ("0" * 64 if wrong_log_pin else
                                hashlib.sha256(data).hexdigest()),
        }
    monkeypatch.setattr(runner, "import_offline_pcap", fake)
    return calls


def test_two_distinct_offline_passes_strict_and_tuple_checks(tmp_path, monkeypatch, capsys):
    source, args = _setup(tmp_path)
    calls = _fake_import(monkeypatch)
    assert runner.main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(calls) == 2
    assert calls[0][0] == calls[1][0] == source
    assert calls[0][1] != calls[1][1]
    assert all(call[3] is True and call[4] == 120 and call[5] is None for call in calls)
    assert report["two_zeek_subprocesses_completed"] is True
    assert report["strict_all_non_uid_fields_equivalent"] is True
    assert report["pcap_tuple_presence_for_both_logs"] is True
    assert report["pcap_packet_count"] == report["zeek_flow_count"] == 1
    assert report["attack_detection_verified"] is False
    assert report["pcap_to_log_derivation_proven"] is False
    assert "10.1.1." not in json.dumps(report)
    assert (tmp_path / "zeek-1" / "conn.log").is_file()
    assert (tmp_path / "zeek-2" / "conn.log").is_file()


@pytest.mark.parametrize("failure", [
    "no_consent", "wrong_pin", "bad_pcap", "same_directory",
    "nested_directory", "existing_second_directory", "relative_directory",
    "invalid_cidr", "bad_timeout",
])
def test_preflight_refuses_before_first_zeek_pass(tmp_path, monkeypatch, capsys, failure):
    source, args = _setup(tmp_path)
    calls = _fake_import(monkeypatch)
    if failure == "no_consent":
        args.remove("--confirm-offline-only")
    elif failure == "wrong_pin":
        args[args.index("--expected-pcap-sha256") + 1] = "0" * 64
    elif failure == "bad_pcap":
        source.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 20)
        args[args.index("--expected-pcap-sha256") + 1] = hashlib.sha256(source.read_bytes()).hexdigest()
    elif failure == "same_directory":
        args[args.index("--second-output-dir") + 1] = str(tmp_path / "zeek-1")
    elif failure == "nested_directory":
        args[args.index("--second-output-dir") + 1] = str(tmp_path / "zeek-1" / "child")
    elif failure == "existing_second_directory":
        (tmp_path / "zeek-2").mkdir()
    elif failure == "relative_directory":
        args[args.index("--first-output-dir") + 1] = "relative"
    elif failure == "invalid_cidr":
        args[args.index("--cidr") + 1] = "8.8.8.0/24"
    elif failure == "bad_timeout":
        args += ["--timeout-seconds", "0"]
    assert runner.main(args) == 2
    assert calls == []
    assert capsys.readouterr().out == ""
    assert not (tmp_path / "zeek-1").exists()


def test_second_import_failure_preserves_both_private_directories(tmp_path, monkeypatch, capsys):
    _source, args = _setup(tmp_path)
    calls = _fake_import(monkeypatch, fail_second=True)
    assert runner.main(args) == 2
    assert len(calls) == 2
    assert (tmp_path / "zeek-1" / "conn.log").is_file()
    assert (tmp_path / "zeek-2" / "conn.log").is_file()
    assert capsys.readouterr().out == ""


def test_different_second_zeek_flow_refuses_without_success(tmp_path, monkeypatch, capsys):
    _source, args = _setup(tmp_path)
    _fake_import(monkeypatch, second_port=81)
    assert runner.main(args) == 2
    assert capsys.readouterr().out == ""
    assert (tmp_path / "zeek-1" / "conn.log").is_file()


def test_post_import_log_hash_mismatch_refused(tmp_path, monkeypatch, capsys):
    _source, args = _setup(tmp_path)
    _fake_import(monkeypatch, wrong_log_pin=True)
    assert runner.main(args) == 2
    assert capsys.readouterr().out == ""


def test_pcap_modified_during_first_pass_refused(tmp_path, monkeypatch, capsys):
    _source, args = _setup(tmp_path)
    calls = _fake_import(monkeypatch, mutate_pcap=True)
    assert runner.main(args) == 2
    assert len(calls) == 1
    assert capsys.readouterr().out == ""


def _pin_mock_zeek_binary(tmp_path, monkeypatch):
    """Mock PATH resolution; the Zeek executable is never launched."""
    executable = tmp_path / "mock-zeek-executable"
    executable.write_bytes(b"synthetic-zeek-binary-v1")
    monkeypatch.setattr(runner.shutil, "which", lambda name: str(executable))
    return executable, hashlib.sha256(executable.read_bytes()).hexdigest()


def test_optional_pinned_zeek_binary_success_does_not_claim_version(tmp_path, monkeypatch, capsys):
    _source, args = _setup(tmp_path)
    executable, digest = _pin_mock_zeek_binary(tmp_path, monkeypatch)
    calls = _fake_import(monkeypatch)
    args += ["--expected-zeek-binary-sha256", digest]
    assert runner.main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(calls) == 2
    assert all(call[5] == executable.resolve() for call in calls)
    assert report["zeek_binary_sha256_pinned"] is True
    assert report["zeek_binary_sha256"] == digest
    assert report["zeek_binary_version_verified"] is False
    assert str(executable) not in json.dumps(report)


@pytest.mark.parametrize("failure", ["bad_hash", "uppercase_hash", "missing_binary"])
def test_zeek_binary_pin_refuses_before_any_import(tmp_path, monkeypatch, capsys, failure):
    _source, args = _setup(tmp_path)
    _executable, digest = _pin_mock_zeek_binary(tmp_path, monkeypatch)
    calls = _fake_import(monkeypatch)
    if failure == "missing_binary":
        monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    elif failure == "bad_hash":
        digest = "0" * 64
    else:
        digest = digest.upper()
    args += ["--expected-zeek-binary-sha256", digest]
    assert runner.main(args) == 2
    assert calls == []
    assert capsys.readouterr().out == ""
    assert not (tmp_path / "zeek-1").exists()


def test_zeek_binary_change_after_first_pass_refuses_without_success(tmp_path, monkeypatch, capsys):
    _source, args = _setup(tmp_path)
    executable, digest = _pin_mock_zeek_binary(tmp_path, monkeypatch)
    calls = _fake_import(monkeypatch)
    fake_import = runner.import_offline_pcap

    def changed_binary(*a, **kw):
        report = fake_import(*a, **kw)
        executable.write_bytes(b"synthetic-zeek-binary-v2")
        return report

    monkeypatch.setattr(runner, "import_offline_pcap", changed_binary)
    args += ["--expected-zeek-binary-sha256", digest]
    assert runner.main(args) == 2
    assert len(calls) == 1
    assert (tmp_path / "zeek-1" / "conn.log").exists()
    assert not (tmp_path / "zeek-2").exists()
    assert capsys.readouterr().out == ""


def test_legacy_two_pass_has_no_binary_fingerprint_claim(tmp_path, monkeypatch, capsys):
    _source, args = _setup(tmp_path)
    _fake_import(monkeypatch)
    assert runner.main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["zeek_binary_sha256_pinned"] is False
    assert "zeek_binary_sha256" not in report
    assert report["zeek_binary_version_verified"] is False
