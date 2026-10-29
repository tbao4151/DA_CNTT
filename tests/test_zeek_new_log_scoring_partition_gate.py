"""Synthetic-only CLI regressions for pinned partition checks during NEW-log scoring.

Not evidence of real VMware isolation, independent labels, or attack detection.
"""
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

from test_zeek_partition_guard import _inputs


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _setup(tmp_path: Path):
    manifest, _dataset, model, new = _inputs(tmp_path)
    # Strict scoring requires separately pinned labels for every declared
    # partition, not just a pinned manifest with mutable annotation files.
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    for capture in spec["captures"]:
        label_file = manifest.parent / capture["labels_path"]
        capture["labels_sha256"] = _sha(label_file.read_bytes())
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    model["input_manifest_sha256"] = _sha(manifest.read_bytes())
    model_file = manifest.parent / "model.json"
    model_file.write_text(json.dumps(model, allow_nan=False), encoding="utf-8")
    output = manifest.parent / "new-predictions.json"
    return manifest, model_file, new, output


def _command(manifest, model_file, new, output):
    return [
        sys.executable, str(ROOT / "scripts" / "score_zeek_new_log.py"),
        "--model", str(model_file),
        "--expected-model-sha256", _sha(model_file.read_bytes()),
        "--log", str(new),
        "--expected-log-sha256", _sha(new.read_bytes()),
        "--cidr", "192.168.56.0/24",
        "--manifest", str(manifest),
        "--expected-manifest-sha256", _sha(manifest.read_bytes()),
        "--output", str(output),
    ]


def _run(command):
    return subprocess.run(command, capture_output=True, text=True, check=False)


def test_strict_scoring_screens_declared_splits_and_keeps_report_compatible(tmp_path):
    manifest, model_file, new, output = _setup(tmp_path)
    command = _command(manifest, model_file, new, output)
    before = {p.name: p.read_bytes() for p in manifest.parent.iterdir() if p.is_file()}
    result = _run(command)
    assert result.returncode == 0, result.stderr
    assert "flow identity non-reuse screened" in result.stdout
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["mode"] == "offline_new_zeek_research_inference_only"
    assert report["test_partition_exclusion_verified"] is False
    assert report["automated_alerts"] is False
    assert report["soc_cases_created"] is False
    assert report["flow_count"] == 2
    assert before == {p.name: p.read_bytes() for p in manifest.parent.iterdir()
                      if p.is_file() and p != output}
    assert _run(command).returncode == 1  # No overwrite.


def test_reserved_test_capture_is_rejected_with_a_correct_new_log_pin(tmp_path):
    manifest, model_file, new, output = _setup(tmp_path)
    new.write_bytes((manifest.parent / "host-2.log").read_bytes())
    result = _run(_command(manifest, model_file, new, output))
    assert result.returncode == 1
    assert not output.exists()


def test_changed_bytes_with_reused_uid_time_and_five_tuple_are_rejected(tmp_path):
    manifest, model_file, new, output = _setup(tmp_path)
    # First flow otherwise matches the declared TRAIN flow. The source SHA
    # changes, but the normalized identity check must still refuse it.
    new.write_bytes(new.read_bytes().replace(b"NEW1", b"N0"))
    result = _run(_command(manifest, model_file, new, output))
    assert result.returncode == 1
    assert not output.exists()


@pytest.mark.parametrize("change", ["manifest", "labels", "missing_label_pin", "model_manifest", "missing_flag"])
def test_tampering_or_partial_pins_fail_before_output(tmp_path, change):
    manifest, model_file, new, output = _setup(tmp_path)
    command = _command(manifest, model_file, new, output)
    if change == "manifest":
        manifest.write_bytes(manifest.read_bytes() + b"\n")
    elif change == "labels":
        label_file = manifest.parent / "host-0-labels.json"
        label_file.write_bytes(label_file.read_bytes() + b"\n")
    elif change == "missing_label_pin":
        spec = json.loads(manifest.read_text(encoding="utf-8"))
        del spec["captures"][0]["labels_sha256"]
        manifest.write_text(json.dumps(spec), encoding="utf-8")
        model = json.loads(model_file.read_text(encoding="utf-8"))
        model["input_manifest_sha256"] = _sha(manifest.read_bytes())
        model_file.write_text(json.dumps(model), encoding="utf-8")
        command[command.index("--expected-manifest-sha256") + 1] = _sha(manifest.read_bytes())
        command[command.index("--expected-model-sha256") + 1] = _sha(model_file.read_bytes())
    elif change == "model_manifest":
        model = json.loads(model_file.read_text(encoding="utf-8"))
        model["input_manifest_sha256"] = "f" * 64
        model_file.write_text(json.dumps(model), encoding="utf-8")
        command[command.index("--expected-model-sha256") + 1] = _sha(model_file.read_bytes())
    else:
        idx = command.index("--expected-manifest-sha256")
        del command[idx:idx + 2]
    result = _run(command)
    assert result.returncode == 1
    assert not output.exists()
    assert str(manifest) not in result.stderr
    assert "192.168.56" not in result.stderr


def test_legacy_unpinned_scoring_remains_explicitly_unverified(tmp_path):
    manifest, model_file, new, output = _setup(tmp_path)
    command = _command(manifest, model_file, new, output)
    idx = command.index("--manifest")
    del command[idx:idx + 4]
    result = _run(command)
    assert result.returncode == 0, result.stderr
    assert "flow identity non-reuse screened" not in result.stdout
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["test_partition_exclusion_verified"] is False
