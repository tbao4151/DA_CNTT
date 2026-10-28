"""Synthetic-only software tests; timing values are NOT lab measurements."""
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

from blue_team_ai.runtime_benchmark import benchmark_offline_new_log_scoring
from evaluate_zeek_lab import load_experiment_manifest
from test_zeek_partition_guard import _inputs

CIDR = ["192.168.56.0/24"]


def _fixture(tmp_path):
    manifest, dataset, model, new_log = _inputs(tmp_path)
    model_path = manifest.parent / "runtime-model.json"
    model_path.write_text(json.dumps(model, allow_nan=False), encoding="utf-8")
    captures, manifest_sha = load_experiment_manifest(manifest, lab_cidrs=CIDR)
    raw = new_log.read_bytes()
    args = dict(
        expected_log_sha256=hashlib.sha256(raw).hexdigest(),
        model_sha256=hashlib.sha256(model_path.read_bytes()).hexdigest(),
        lab_cidrs=CIDR,
        declared_dataset=dataset,
        declared_manifest_sha256=manifest_sha,
        declared_captures=captures,
        repetitions=3,
        warmup=0,
    )
    return manifest, model_path, new_log, model, raw, args


def test_batch_timing_has_honest_semantics_and_no_sensitive_rows(tmp_path):
    _, _, _, model, raw, args = _fixture(tmp_path)
    report = benchmark_offline_new_log_scoring(raw, model, **args)
    assert report["mode"] == "offline_new_zeek_scoring_batch_runtime_only"
    assert report["flow_count"] == 2
    assert report["repetitions"] == 3
    assert len(report["per_batch_duration_ms"]) == 3
    assert all(t > 0 for t in report["per_batch_duration_ms"])
    assert report["median_batch_ms"] > 0
    assert report["p95_nearest_rank_batch_ms"] >= report["median_batch_ms"]
    assert report["detection_latency_measured"] is False
    assert report["automated_alerts"] is False
    assert report["soc_cases_created"] is False
    assert "192.168.56" not in json.dumps(report)
    assert "NEW1" not in json.dumps(report)
    assert not list(tmp_path.rglob("*.sqlite3"))


@pytest.mark.parametrize("change", [
    {"repetitions": 0},
    {"repetitions": 21},
    {"repetitions": True},
    {"warmup": -1},
    {"warmup": 4},
    {"warmup": False},
    {"declared_captures": None},
    {"declared_manifest_sha256": "0" * 64},
    {"expected_log_sha256": "0" * 64},
    {"lab_cidrs": ["10.1.0.0/16"]},
])
def test_invalid_bounds_or_pins_refuse_before_metrics(tmp_path, change):
    _, _, _, model, raw, args = _fixture(tmp_path)
    args.update(change)
    with pytest.raises(ValueError):
        benchmark_offline_new_log_scoring(raw, model, **args)
    assert not list(tmp_path.rglob("*.sqlite3"))


def test_reencoded_reserved_test_flow_refused(tmp_path):
    manifest, _, _, model, _, args = _fixture(tmp_path)
    original = (manifest.parent / "host-2.log").read_bytes()
    reused = original.replace(b"#fields\t", b"# harmless comment\n#fields\t", 1)
    args["expected_log_sha256"] = hashlib.sha256(reused).hexdigest()
    with pytest.raises(ValueError, match="flow identity overlap"):
        benchmark_offline_new_log_scoring(reused, model, **args)


def test_cli_read_only_and_refuses_modified_hash(tmp_path):
    manifest, model_path, new_log, _, _, args = _fixture(tmp_path)
    command = [
        sys.executable, str(ROOT / "scripts" / "benchmark_zeek_new_log_runtime.py"),
        "--model", str(model_path),
        "--expected-model-sha256", args["model_sha256"],
        "--manifest", str(manifest),
        "--expected-manifest-sha256", args["declared_manifest_sha256"],
        "--log", str(new_log),
        "--expected-log-sha256", args["expected_log_sha256"],
        "--cidr", CIDR[0], "--repetitions", "2", "--warmup", "0",
    ]
    before = {p.name: p.read_bytes() for p in manifest.parent.iterdir() if p.is_file()}
    completed = subprocess.run(command, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["repetitions"] == 2
    assert report["detection_latency_measured"] is False
    assert "192.168.56" not in completed.stdout
    for flag, value in (
        ("--expected-model-sha256", "0" * 64),
        ("--expected-manifest-sha256", "0" * 64),
        ("--expected-log-sha256", "0" * 64),
        ("--cidr", "10.0.0.0/8"),
        ("--repetitions", "21"),
    ):
        altered = command.copy()
        altered[altered.index(flag) + 1] = value
        refused = subprocess.run(altered, capture_output=True, text=True)
        assert refused.returncode == 1
        assert not refused.stdout
        assert str(manifest) not in refused.stderr
    assert before == {p.name: p.read_bytes() for p in manifest.parent.iterdir() if p.is_file()}
