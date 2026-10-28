"""Synthetic-only normalized Zeek flow identity screening; not lab evidence."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.new_log_inference import score_new_zeek_log
from blue_team_ai.partition_guard import verify_declared_partition_exclusion
from evaluate_zeek_lab import load_experiment_manifest
from test_zeek_new_log_partition_triage import _setup
from test_zeek_partition_guard import _inputs


def _reencoded_reserved_test(manifest: Path) -> bytes:
    original = (manifest.parent / "host-2.log").read_bytes()
    # Different SHA-256, identical parsed UID/time/5-tuple identities.
    changed = original.replace(b"#fields\\t", b"# harmless encoding comment\\n#fields\\t", 1)
    assert changed != original
    return changed


def _verify(manifest, dataset, model, raw, captures=None):
    return verify_declared_partition_exclusion(
        model, dataset,
        manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        new_capture_sha256=hashlib.sha256(raw).hexdigest(),
        declared_captures=captures, new_source_data=raw if captures is not None else None,
    )


def test_reencoded_reserved_test_rejected_beyond_exact_file_digest(tmp_path):
    manifest, dataset, model, new = _inputs(tmp_path)
    captures, _ = load_experiment_manifest(manifest, lab_cidrs=["192.168.56.0/24"])
    raw = _reencoded_reserved_test(manifest)
    assert hashlib.sha256(raw).hexdigest() != hashlib.sha256(
        (manifest.parent / "host-2.log").read_bytes()
    ).hexdigest()
    # Historical exact-byte-only contract cannot detect this overlap.
    assert _verify(manifest, dataset, model, raw)["declared_flow_identity_nonreuse_checked"] is False
    with pytest.raises(ValueError, match="flow identity overlap"):
        _verify(manifest, dataset, model, raw, captures)


def test_new_unique_flow_passes_with_explicit_scientific_limitations(tmp_path):
    manifest, dataset, model, new = _inputs(tmp_path)
    captures, _ = load_experiment_manifest(manifest, lab_cidrs=["192.168.56.0/24"])
    result = _verify(manifest, dataset, model, new.read_bytes(), captures)
    assert result["declared_flow_identity_nonreuse_checked"] is True
    assert result["semantic_flow_nonreuse_verified"] is False
    assert result["host_only_isolation_verified"] is False
    assert "192.168.56" not in json.dumps(result)
    assert "NEW1" not in json.dumps(result)


def test_missing_original_capture_or_mismatched_new_bytes_fails_closed(tmp_path):
    manifest, dataset, model, new = _inputs(tmp_path)
    captures, _ = load_experiment_manifest(manifest, lab_cidrs=["192.168.56.0/24"])
    with pytest.raises(ValueError, match="provided together"):
        verify_declared_partition_exclusion(
            model, dataset,
            manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
            new_capture_sha256=hashlib.sha256(new.read_bytes()).hexdigest(),
            declared_captures=captures,
        )
    with pytest.raises(ValueError, match="do not cover"):
        _verify(manifest, dataset, model, new.read_bytes(), captures[:2])
    with pytest.raises(ValueError, match="Invalid pinned flow identity"):
        verify_declared_partition_exclusion(
            model, dataset,
            manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
            new_capture_sha256=hashlib.sha256(new.read_bytes()).hexdigest(),
            declared_captures=captures, new_source_data=b"changed",
        )


def test_preflight_cli_rejects_reencoded_reserved_test(tmp_path):
    manifest, dataset, model, new = _inputs(tmp_path)
    raw = _reencoded_reserved_test(manifest)
    new.write_bytes(raw)
    model_path = manifest.parent / "model.json"
    model_path.write_text(json.dumps(model), encoding="utf-8")
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "check_zeek_partition_exclusion.py"),
        "--model", str(model_path),
        "--expected-model-sha256", hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "--manifest", str(manifest),
        "--expected-manifest-sha256", hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "--log", str(new),
        "--expected-log-sha256", hashlib.sha256(raw).hexdigest(),
        "--cidr", "192.168.56.0/24",
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert "192.168.56" not in proc.stderr
    assert str(new) not in proc.stderr


def test_manual_triage_reencoded_test_refused_before_sqlite(tmp_path):
    manifest, _, model, new_log, _, index, base, pinned = _setup(tmp_path)
    raw = _reencoded_reserved_test(manifest)
    new_log.write_bytes(raw)
    log_digest = hashlib.sha256(raw).hexdigest()
    model_digest = base[base.index("--expected-model-sha256") + 1]
    report = score_new_zeek_log(
        raw, model, expected_log_sha256=log_digest,
        lab_cidrs=["192.168.56.0/24"], model_sha256=model_digest,
    )
    (manifest.parent / "new-predictions.json").write_text(
        json.dumps(report, allow_nan=False), encoding="utf-8",
    )
    changed = base.copy()
    changed[changed.index("--expected-log-sha256") + 1] = log_digest
    db = manifest.parent / "cases.sqlite3"
    for action in (
        ["--list-candidates"],
        ["--record-index", str(index), "--db", str(db),
         "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture"],
    ):
        proc = subprocess.run(
            changed + pinned + action, capture_output=True, text=True, check=False,
        )
        assert proc.returncode == 1
        assert not db.exists()
        assert "192.168.56" not in proc.stderr
