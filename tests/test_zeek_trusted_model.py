"""Synthetic-only pinned JSON loader tests, not VMware detection evidence."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.model_artifact import build_zeek_research_artifact
from blue_team_ai.trusted_model import MAX_MODEL_BYTES, load_pinned_zeek_research_model
from test_zeek_offline_baseline import _dataset


@pytest.fixture(scope="module")
def model_bytes():
    artifact = build_zeek_research_artifact(_dataset(), input_manifest_sha256="a" * 64)
    return json.dumps(artifact, allow_nan=False).encode("utf-8")


def _store(tmp_path, payload):
    path = tmp_path / "model.json"
    path.write_bytes(payload)
    return path, hashlib.sha256(payload).hexdigest()


def test_pinned_loader_accepts_exact_exported_bytes(tmp_path, model_bytes):
    path, digest = _store(tmp_path, model_bytes)
    artifact = load_pinned_zeek_research_model(path, expected_sha256=digest)
    assert artifact["test_scored"] is False
    assert artifact["automated_alerts"] is False
    assert artifact["feature_schema_version"] == 1


@pytest.mark.parametrize("invalid_digest", ["", "A" * 64, "x" * 64, "a" * 63, " a" * 64])
def test_loader_requires_canonical_external_digest(tmp_path, model_bytes, invalid_digest):
    path, _ = _store(tmp_path, model_bytes)
    with pytest.raises(ValueError):
        load_pinned_zeek_research_model(path, expected_sha256=invalid_digest)


def test_changed_bytes_rejected_before_json_parsing(tmp_path, model_bytes):
    path, digest = _store(tmp_path, model_bytes)
    path.write_bytes(model_bytes + b" ")
    with pytest.raises(ValueError, match="SHA-256"):
        load_pinned_zeek_research_model(path, expected_sha256=digest)


@pytest.mark.parametrize("payload", [
    b'{"x":1,"x":2}', b'{"x":{"nested":1,"nested":2}}',
    b'{"intercept":NaN}', b'{"intercept":Infinity}', b"\xff",
    b"[]", b"{}", b"",
])
def test_invalid_json_or_contract_is_refused(tmp_path, payload):
    path, digest = _store(tmp_path, payload)
    with pytest.raises(ValueError):
        load_pinned_zeek_research_model(path, expected_sha256=digest)


def test_oversized_file_rejected(tmp_path):
    payload = b"x" * (MAX_MODEL_BYTES + 1)
    path, digest = _store(tmp_path, payload)
    with pytest.raises(ValueError, match="size limit"):
        load_pinned_zeek_research_model(path, expected_sha256=digest)


def test_symlink_and_directory_refused(tmp_path, model_bytes):
    path, digest = _store(tmp_path, model_bytes)
    with pytest.raises(ValueError):
        load_pinned_zeek_research_model(tmp_path, expected_sha256=digest)
    link = tmp_path / "alias.json"
    try:
        link.symlink_to(path)
    except (OSError, NotImplementedError):
        pytest.skip("Platform does not permit creating symlinks")
    with pytest.raises(ValueError):
        load_pinned_zeek_research_model(link, expected_sha256=digest)


def test_read_only_cli_and_no_implicit_digest(tmp_path, model_bytes):
    path, digest = _store(tmp_path, model_bytes)
    cmd = [sys.executable, str(ROOT / "scripts" / "verify_zeek_model.py"),
           "--model", str(path), "--expected-sha256", digest]
    passed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert passed.returncode == 0, passed.stderr
    assert "No traffic was scored" in passed.stdout
    assert path.read_bytes() == model_bytes
    assert subprocess.run(cmd[:-1], capture_output=True).returncode != 0
    assert subprocess.run(cmd[:-1] + ["0" * 64], capture_output=True).returncode == 1


def test_cli_refuses_model_inside_repository(model_bytes):
    # Existing checked-in source is intentionally NOT a model, and must not be
    # parsed or accepted as a private artifact regardless of its pinned digest.
    path = ROOT / "README.md"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    cmd = [sys.executable, str(ROOT / "scripts" / "verify_zeek_model.py"),
           "--model", str(path), "--expected-sha256", digest]
    assert subprocess.run(cmd, capture_output=True).returncode == 1
