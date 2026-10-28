"""Offline PCAP provenance recheck at independent Zeek report review.

The Zeek importer is mocked; real model scoring and report review run in
subprocesses. No live traffic, VMware capture or operational SOC alerts.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from test_offline_pcap_verify import imported
from test_zeek_offline_baseline import _dataset

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.model_artifact import build_zeek_research_artifact


def run(command):
    return subprocess.run(command, capture_output=True, text=True, check=False)


def test_review_rechecks_original_pcap_after_scoring(imported):
    model = build_zeek_research_artifact(_dataset(), input_manifest_sha256="a" * 64)
    model_path = imported["pcap"].parent / "zeek-research-model.json"
    model_bytes = (json.dumps(model, allow_nan=False) + "\n").encode("utf-8")
    model_path.write_bytes(model_bytes)
    model_sha = hashlib.sha256(model_bytes).hexdigest()
    log_sha = hashlib.sha256(imported["log"].read_bytes()).hexdigest()
    prediction_path = imported["log"].parent / "new-predictions.json"

    common = [
        "--model", str(model_path),
        "--expected-model-sha256", model_sha,
        "--log", str(imported["log"]),
        "--expected-log-sha256", log_sha,
        "--cidr", "192.168.56.0/24",
    ]
    provenance = [
        "--offline-import-report", str(imported["report"]),
        "--expected-offline-import-report-sha256", imported["pin"],
        "--offline-import-pcap", str(imported["pcap"]),
    ]
    scorer = [
        sys.executable, str(ROOT / "scripts" / "score_zeek_new_log.py"),
        *common, *provenance, "--output", str(prediction_path),
    ]
    scored = run(scorer)
    assert scored.returncode == 0, scored.stderr
    original_report = prediction_path.read_bytes()
    original_pcap = imported["pcap"].read_bytes()

    review = [
        sys.executable, str(ROOT / "scripts" / "verify_zeek_new_log_report.py"),
        *common, "--report", str(prediction_path), *provenance,
    ]
    before = {
        key: imported[key].read_bytes()
        for key in ("pcap", "log", "report")
    }
    ok = run(review)
    assert ok.returncode == 0, ok.stderr
    assert "offline_pcap_provenance_reverified=true" in ok.stdout
    assert "NOT verified" in ok.stdout
    assert all(imported[key].read_bytes() == value for key, value in before.items())
    assert prediction_path.read_bytes() == original_report

    # A missing optional flag cannot silently downgrade to legacy review.
    for flag in (
        "--offline-import-report",
        "--expected-offline-import-report-sha256",
        "--offline-import-pcap",
    ):
        partial = review.copy()
        index = partial.index(flag)
        del partial[index:index + 2]
        assert run(partial).returncode == 1

    for flag, replacement in (
        ("--expected-offline-import-report-sha256", "0" * 64),
        ("--offline-import-pcap", str(imported["report"])),
        ("--cidr", "192.168.57.0/24"),
        ("--expected-log-sha256", "0" * 64),
    ):
        changed = review.copy()
        changed[changed.index(flag) + 1] = replacement
        refused = run(changed)
        assert refused.returncode == 1
        assert str(imported["pcap"]) not in refused.stderr

    # Legacy invocation remains supported, but cannot attest PCAP provenance.
    legacy = review.copy()
    for flag in (
        "--offline-import-report",
        "--expected-offline-import-report-sha256",
        "--offline-import-pcap",
    ):
        index = legacy.index(flag)
        del legacy[index:index + 2]
    old = run(legacy)
    assert old.returncode == 0, old.stderr
    assert "offline_pcap_provenance_reverified" not in old.stdout

    # Original PCAP changed AFTER successful scoring: report/model/log still
    # match, but the independent provenance recheck must refuse.
    imported["pcap"].write_bytes(original_pcap + b"changed-after-scoring")
    assert run(legacy).returncode == 0
    rejected = run(review)
    assert rejected.returncode == 1
    assert "refused" in rejected.stderr
    assert prediction_path.read_bytes() == original_report
    assert not (prediction_path.parent / "soc_cases.sqlite3").exists()
