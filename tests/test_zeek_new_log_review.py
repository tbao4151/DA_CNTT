"""Synthetic regression tests for read-only new-log report verification.

No VMware capture, independent labels or genuine attack-detection evidence.
"""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.model_artifact import build_zeek_research_artifact
from blue_team_ai.new_log_inference import score_new_zeek_log
from blue_team_ai.new_log_review import (
    MAX_NEW_LOG_REPORT_BYTES, review_pinned_new_log_report,
)
from test_zeek_new_log_inference import _log
from test_zeek_offline_baseline import _dataset


@pytest.fixture
def inputs():
    model = build_zeek_research_artifact(_dataset(), input_manifest_sha256="a" * 64)
    raw = _log()
    digest = hashlib.sha256(raw).hexdigest()
    model_bytes = json.dumps(model, allow_nan=False).encode("utf-8")
    model_sha = hashlib.sha256(model_bytes).hexdigest()
    report = score_new_zeek_log(
        raw, model, expected_log_sha256=digest,
        lab_cidrs=["192.168.56.0/24"], model_sha256=model_sha,
    )
    return raw, model, model_bytes, report, digest, model_sha


def _review(inputs, report=None, *, report_bytes=None, raw=None, model=None, digest=None):
    original, trained, _, prediction, source_sha, model_sha = inputs
    payload = report_bytes if report_bytes is not None else json.dumps(
        prediction if report is None else report, allow_nan=False,
    ).encode("utf-8")
    return review_pinned_new_log_report(
        original if raw is None else raw,
        trained if model is None else model,
        payload,
        expected_log_sha256=source_sha if digest is None else digest,
        lab_cidrs=["192.168.56.0/24"], model_sha256=model_sha,
    )


def test_exact_recomputed_report_passes_without_operational_claims(inputs):
    result = _review(inputs)
    assert result["report_matches_recomputed_predictions"] is True
    assert result["flow_count"] == 2
    assert result["source_sha256"] == inputs[4]
    assert result["research_candidate_count"] == inputs[3]["research_candidate_count"]
    for field in (
        "test_partition_exclusion_verified", "host_only_isolation_verified",
        "capture_authenticity_verified", "model_authorship_verified",
        "operational_attack_detection_verified", "automated_alerts",
        "soc_cases_created", "live_capture",
    ):
        assert result[field] is False
    assert "predictions" not in result


@pytest.mark.parametrize("change", [
    "probability", "candidate", "endpoint", "timestamp", "source",
    "model", "count", "flag", "extra", "reorder", "bool_as_int",
])
def test_modified_report_fails_closed(inputs, change):
    report = copy.deepcopy(inputs[3])
    if change == "probability":
        report["predictions"][0]["attack_probability"] = 0.123456789
    elif change == "candidate":
        report["predictions"][0]["research_candidate"] = not report["predictions"][0]["research_candidate"]
    elif change == "endpoint":
        report["predictions"][0]["dst_ip"] = "192.168.56.99"
    elif change == "timestamp":
        report["predictions"][0]["event_time_utc"] = "2026-10-28T00:00:00+00:00"
    elif change == "source":
        report["source_sha256"] = "0" * 64
    elif change == "model":
        report["model_sha256"] = "0" * 64
    elif change == "count":
        report["flow_count"] += 1
    elif change == "flag":
        report["live_capture"] = True
    elif change == "extra":
        report["verified_attack"] = True
    elif change == "reorder":
        report["predictions"].reverse()
    elif change == "bool_as_int":
        report["predictions"][0]["research_candidate"] = int(report["predictions"][0]["research_candidate"])
    with pytest.raises(ValueError, match="differs"):
        _review(inputs, report)


@pytest.mark.parametrize("payload", [
    b'{"mode":"x","mode":"y"}',
    b'{"score":NaN}',
    b'{"score":Infinity}',
    b'not json',
    b'\xff',
    b'',
    b' ' * (MAX_NEW_LOG_REPORT_BYTES + 1),
    b'[]',
])
def test_malformed_private_json_rejected(inputs, payload):
    with pytest.raises(ValueError):
        _review(inputs, report_bytes=payload)


def test_modified_original_or_pinned_reference_refused(inputs):
    with pytest.raises(ValueError, match="pinned bytes"):
        _review(inputs, raw=inputs[0] + b" ")
    with pytest.raises(ValueError):
        _review(inputs, digest="0" * 64)


def test_cli_is_read_only_and_rejects_tampered_report(tmp_path, inputs):
    raw, _, model_bytes, report, digest, model_sha = inputs
    private = tmp_path / "private"
    private.mkdir()
    log_path = private / "conn.log"
    model_path = private / "model.json"
    report_path = private / "new-predictions.json"
    log_path.write_bytes(raw)
    model_path.write_bytes(model_bytes)
    report_path.write_text(json.dumps(report, allow_nan=False), encoding="utf-8")
    command = [
        sys.executable, str(ROOT / "scripts" / "verify_zeek_new_log_report.py"),
        "--model", str(model_path),
        "--expected-model-sha256", model_sha,
        "--log", str(log_path),
        "--expected-log-sha256", digest,
        "--report", str(report_path),
        "--cidr", "192.168.56.0/24",
    ]
    before = [p.read_bytes() for p in (log_path, model_path, report_path)]
    success = subprocess.run(command, capture_output=True, text=True, check=False)
    assert success.returncode == 0, success.stderr
    assert "matches recomputed pinned inference" in success.stdout
    assert "NOT verified" in success.stdout
    assert [p.read_bytes() for p in (log_path, model_path, report_path)] == before

    tampered = copy.deepcopy(report)
    tampered["predictions"][0]["attack_probability"] = -1
    report_path.write_text(json.dumps(tampered), encoding="utf-8")
    failed = subprocess.run(command, capture_output=True, text=True, check=False)
    assert failed.returncode == 1
    assert "refused" in failed.stderr
    assert "192.168.56" not in failed.stderr
    assert not (private / "soc_cases.sqlite3").exists()

    report_path.write_bytes(before[2])
    changed = command.copy()
    changed[changed.index("--expected-model-sha256") + 1] = "0" * 64
    assert subprocess.run(changed, capture_output=True).returncode == 1

    outside = tmp_path / "other.json"
    outside.write_bytes(before[2])
    changed = command.copy()
    changed[changed.index("--report") + 1] = str(outside)
    assert subprocess.run(changed, capture_output=True).returncode == 1
