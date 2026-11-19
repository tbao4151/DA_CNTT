"""No-network verification of exclusive private UTF-8 stage writer."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_vmware_progress_file as writer


def test_utf8_line_flush_and_cli_option_forwarded(monkeypatch, tmp_path):
    def fake_main(args):
        assert "--progress-jsonl" in args
        assert "--execute" not in args
        print(json.dumps({
            "kind": "da005_vmware_stepwise_progress_v1",
            "stage": "preflight", "status": "dry_run", "note": "Kiểm thử",
        }, ensure_ascii=False), flush=True)
        return 0
    monkeypatch.setattr(writer.stepwise, "main", fake_main)
    file = tmp_path / "phase.jsonl"
    assert writer.run_to_file(jsonl_file=file, cli_args=["--scenario", "connection_shift"]) == 0
    raw = file.read_bytes()
    assert raw.endswith(b"\n")
    assert "Kiểm thử" in raw.decode("utf-8")
    assert json.loads(raw)["status"] == "dry_run"
    if os.name != "nt":
        assert file.stat().st_mode & 0o077 == 0


def test_never_overwrite_even_if_existing_jsonl_is_valid(monkeypatch, tmp_path):
    file = tmp_path / "evidence.jsonl"
    file.write_text('{"existing":true}\n', encoding="utf-8")
    monkeypatch.setattr(writer.stepwise, "main", lambda _a: pytest.fail("Must not run CLI"))
    with pytest.raises(ValueError, match="already exist"):
        writer.run_to_file(jsonl_file=file, cli_args=[])
    assert file.read_text(encoding="utf-8") == '{"existing":true}\n'


def test_relative_and_repo_paths_are_rejected_before_cli(monkeypatch, tmp_path):
    monkeypatch.setattr(writer.stepwise, "main", lambda _a: pytest.fail("No CLI"))
    with pytest.raises(ValueError, match="absolute"):
        writer.run_to_file(jsonl_file=Path("relative.jsonl"), cli_args=[])
    with pytest.raises(ValueError, match="private"):
        writer.run_to_file(jsonl_file=ROOT / "secret.jsonl", cli_args=[])
    with pytest.raises(ValueError, match="extension"):
        writer.run_to_file(jsonl_file=tmp_path / "log.txt", cli_args=[])


def test_symlink_or_missing_evidence_directory_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(writer.stepwise, "main", lambda _a: pytest.fail("No CLI"))
    with pytest.raises(FileNotFoundError):
        writer.run_to_file(jsonl_file=tmp_path / "missing" / "foo.jsonl", cli_args=[])
    path = tmp_path / "link.jsonl"
    try:
        path.symlink_to(tmp_path / "somewhere")
    except (OSError, NotImplementedError):
        pytest.skip("Filesystem does not support unprivileged symlinks")
    with pytest.raises(ValueError, match="symlink"):
        writer.run_to_file(jsonl_file=path, cli_args=[])


def test_failure_or_refused_cli_is_preserved_in_private_file(monkeypatch, tmp_path):
    monkeypatch.setattr(writer.stepwise, "main",
                        lambda _args: (print('{"kind":"da005_vmware_stepwise_terminal_v1","status":"refused"}', flush=True) or 1))
    file = tmp_path / "refused.jsonl"
    assert writer.run_to_file(jsonl_file=file, cli_args=["--execute"]) == 1
    assert json.loads(file.read_text(encoding="utf-8"))["status"] == "refused"


def test_wrapper_main_prints_only_generic_success(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(writer.stepwise, "main", lambda _args: (print('{"kind":"test"}') or 0))
    dest = tmp_path / "phase.jsonl"
    assert writer.main(["--jsonl-file", str(dest), "--source-ip", "192.168.77.1"]) == 0
    captured = capsys.readouterr()
    assert "DA005 JSONL completed" in captured.out
    assert '{"kind":"test"}' not in captured.out
    assert dest.read_text(encoding="utf-8") == '{"kind":"test"}\n'
