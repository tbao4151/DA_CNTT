"""Synthetic PCAP -> Zeek import provenance gate -> research scoring integration.

Zeek itself is mocked by the imported fixture. No real network or VMware run.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from blue_team_ai.model_artifact import build_zeek_research_artifact
from test_offline_pcap_verify import imported  # pytest fixture: mocked Zeek import
from test_zeek_offline_baseline import _dataset

ROOT = Path(__file__).resolve().parents[1]


def _command(item, model_path, model_digest, output):
    return [
        sys.executable, str(ROOT / "scripts" / "score_zeek_new_log.py"),
        "--model", str(model_path),
        "--expected-model-sha256", model_digest,
        "--log", str(item["log"]),
        "--expected-log-sha256", hashlib.sha256(item["log"].read_bytes()).hexdigest(),
        "--cidr", "192.168.56.0/24",
        "--offline-import-report", str(item["report"]),
        "--expected-offline-import-report-sha256", item["pin"],
        "--offline-import-pcap", str(item["pcap"]),
        "--output", str(output),
    ]


def _run(command):
    return subprocess.run(command, capture_output=True, text=True, check=False)


def test_pinned_pcap_import_gates_real_research_scorer_cli(imported):
    model = build_zeek_research_artifact(_dataset(), input_manifest_sha256="a" * 64)
    model_path = imported["pcap"].parent / "research-model.json"
    model_bytes = (json.dumps(model, allow_nan=False) + "\n").encode("utf-8")
    model_path.write_bytes(model_bytes)
    output = imported["log"].parent / "pcap-research-scores.json"
    command = _command(
        imported, model_path, hashlib.sha256(model_bytes).hexdigest(), output,
    )
    originals = {key: imported[key].read_bytes() for key in ("pcap", "log", "report")}

    ok = _run(command)
    assert ok.returncode == 0, ok.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["mode"] == "offline_new_zeek_research_inference_only"
    assert report["source_sha256"] == hashlib.sha256(originals["log"]).hexdigest()
    assert report["flow_count"] == 1
    assert report["automated_alerts"] is False
    assert report["soc_cases_created"] is False
    assert report["test_partition_exclusion_verified"] is False
    assert report["host_only_isolation_verified"] is False
    assert all(imported[key].read_bytes() == data for key, data in originals.items())

    # Refuse overwriting the existing prediction report.
    assert _run(command).returncode == 1
    output.unlink()

    # A partial provenance declaration is never silently ignored.
    incomplete = command.copy()
    del incomplete[incomplete.index("--offline-import-pcap"):
                   incomplete.index("--offline-import-pcap") + 2]
    assert _run(incomplete).returncode == 1
    assert not output.exists()

    # A re-pinned Zeek log alone must not bypass the independent PCAP report pin.
    for flag, replacement in (
        ("--expected-offline-import-report-sha256", "0" * 64),
        ("--offline-import-pcap", str(imported["report"])),
        ("--cidr", "192.168.57.0/24"),
        ("--expected-log-sha256", "0" * 64),
    ):
        invalid = command.copy()
        invalid[invalid.index(flag) + 1] = replacement
        result = _run(invalid)
        assert result.returncode == 1
        assert not output.exists()
        assert str(imported["pcap"]) not in result.stderr

    # Legacy CLI without the three optional flags remains functional.
    legacy = command.copy()
    for flag in (
        "--offline-import-report",
        "--expected-offline-import-report-sha256",
        "--offline-import-pcap",
    ):
        index = legacy.index(flag)
        del legacy[index:index + 2]
    assert _run(legacy).returncode == 0
    output.unlink()

    # Altered original PCAP must fail before any prediction report is written.
    imported["pcap"].write_bytes(originals["pcap"] + b"changed")
    assert _run(command).returncode == 1
    assert not output.exists()
    assert imported["log"].read_bytes() == originals["log"]
    assert imported["report"].read_bytes() == originals["report"]
