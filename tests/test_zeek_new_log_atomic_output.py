"""Synthetic filesystem regressions for atomic private Zeek prediction reports.

These do not test VMware, model accuracy, or operational attack detection.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from score_zeek_new_log import _write_new_report_atomically


def _temporary_reports(directory: Path) -> list[Path]:
    return list(directory.glob(".da005-new-log-*.tmp"))


def test_atomic_report_publishes_complete_utf8_and_cleans_staging(tmp_path):
    output = tmp_path / "predictions.json"
    payload = '{"origin":"offline_zeek_log","note":"thử nghiệm"}\n'
    _write_new_report_atomically(output, payload)
    assert output.read_bytes() == payload.encode("utf-8")
    assert _temporary_reports(tmp_path) == []


def test_atomic_report_does_not_overwrite_existing_evidence(tmp_path):
    output = tmp_path / "predictions.json"
    output.write_bytes(b"original evidence")
    with pytest.raises(FileExistsError):
        _write_new_report_atomically(output, '{"new":true}\n')
    assert output.read_bytes() == b"original evidence"
    assert _temporary_reports(tmp_path) == []


def test_atomic_report_fails_closed_when_publication_is_unsupported(tmp_path, monkeypatch):
    output = tmp_path / "predictions.json"

    def refuse_link(_source, _target):
        raise OSError("hard links unsupported")

    monkeypatch.setattr(os, "link", refuse_link)
    with pytest.raises(OSError, match="unsupported"):
        _write_new_report_atomically(output, '{"ok":true}\n')
    assert not output.exists()
    assert _temporary_reports(tmp_path) == []


def test_atomic_report_fails_closed_on_incomplete_staging_write(tmp_path, monkeypatch):
    output = tmp_path / "predictions.json"

    def refuse_fsync(_fd):
        raise OSError("simulated storage failure")

    monkeypatch.setattr(os, "fsync", refuse_fsync)
    with pytest.raises(OSError, match="storage failure"):
        _write_new_report_atomically(output, '{"ok":true}\n')
    assert not output.exists()
    assert _temporary_reports(tmp_path) == []


def test_atomic_report_rejects_concurrent_destination_creation(tmp_path, monkeypatch):
    output = tmp_path / "predictions.json"
    real_link = os.link

    def race_link(source, target):
        Path(target).write_bytes(b"other analyst evidence")
        return real_link(source, target)

    monkeypatch.setattr(os, "link", race_link)
    with pytest.raises(FileExistsError):
        _write_new_report_atomically(output, '{"ok":true}\n')
    assert output.read_bytes() == b"other analyst evidence"
    assert _temporary_reports(tmp_path) == []
