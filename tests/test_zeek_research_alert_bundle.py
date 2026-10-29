"""Synthetic-only regression of verified research alert export; no VMware."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from test_zeek_new_log_scoring_partition_gate import _setup, _command, _sha

ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path):
    manifest, model_file, new, report = _setup(tmp_path)
    # Force a candidate solely to exercise the export contract in synthetic CI.
    # This threshold is NOT an experimentally selected operating point.
    model = json.loads(model_file.read_text(encoding="utf-8"))
    model["selected_threshold"] = 0.000001
    model_file.write_text(json.dumps(model, allow_nan=False), encoding="utf-8")
    scored = subprocess.run(_command(manifest, model_file, new, report),
                            capture_output=True, text=True)
    assert scored.returncode == 0, scored.stderr
    output = new.parent / "research-alerts.json"
    command = [
        sys.executable, str(ROOT / "scripts/export_zeek_research_alerts.py"),
        "--model", str(model_file),
        "--expected-model-sha256", _sha(model_file.read_bytes()),
        "--log", str(new),
        "--expected-log-sha256", _sha(new.read_bytes()),
        "--report", str(report),
        "--expected-report-sha256", _sha(report.read_bytes()),
        "--manifest", str(manifest),
        "--expected-manifest-sha256", _sha(manifest.read_bytes()),
        "--cidr", "192.168.56.0/24",
        "--output", str(output),
    ]
    return command, output, manifest, new, report


def _run(command):
    return subprocess.run(command, capture_output=True, text=True, check=False)


def test_export_creates_private_deterministic_research_queue_without_soc(tmp_path):
    command, output, manifest, new, report = _fixture(tmp_path)
    before = {p.name: p.read_bytes() for p in new.parent.iterdir() if p.is_file()}
    result = _run(command)
    assert result.returncode == 0, result.stderr
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["mode"] == "offline_zeek_research_alert_candidates_only"
    assert data["declared_partition_and_flow_identity_nonreuse_checked"] is True
    assert data["research_alert_candidates_exported"] >= 1
    assert data["research_alert_candidates_exported"] <= 500
    assert data["research_candidate_count_total"] >= data["research_alert_candidates_exported"]
    assert all(data[k] is False for k in (
        "independent_partition_history_verified", "independent_ground_truth_verified",
        "vmware_isolation_verified", "capture_authenticity_verified",
        "operational_alerts_created", "soc_cases_created", "live_capture",
    ))
    assert all(row["confirmed_attack"] is False and row["soc_case_id"] is None
               and row["record_index"] < 500 for row in data["research_alerts"])
    assert all(row["status"] == "pending_manual_research_review"
               for row in data["research_alerts"])
    assert [r["attack_probability"] for r in data["research_alerts"]] == sorted(
        [r["attack_probability"] for r in data["research_alerts"]], reverse=True)
    assert before == {p.name: p.read_bytes() for p in new.parent.iterdir()
                      if p.is_file() and p != output}
    assert not any(p.suffix == ".sqlite3" for p in new.parent.iterdir())
    assert _run(command).returncode == 1  # Atomic no-overwrite.
    second = new.parent / "research-alerts-2.json"
    second_command = command.copy()
    second_command[-1] = str(second)
    assert _run(second_command).returncode == 0
    assert output.read_bytes() == second.read_bytes()


@pytest.mark.parametrize("change", [
    "wrong_report_pin", "tampered_report", "tampered_labels",
    "reserved_test_capture", "missing_manifest_pin", "public_output",
])
def test_export_refuses_changed_or_unpinned_inputs_before_publication(tmp_path, change):
    command, output, manifest, new, report = _fixture(tmp_path)
    if change == "wrong_report_pin":
        command[command.index("--expected-report-sha256") + 1] = "0" * 64
    elif change == "tampered_report":
        prediction = json.loads(report.read_text(encoding="utf-8"))
        prediction["predictions"][0]["attack_probability"] = 0.123
        report.write_text(json.dumps(prediction), encoding="utf-8")
        command[command.index("--expected-report-sha256") + 1] = _sha(report.read_bytes())
    elif change == "tampered_labels":
        label_file = manifest.parent / "host-0-labels.json"
        label_file.write_bytes(label_file.read_bytes() + b" ")
    elif change == "reserved_test_capture":
        new.write_bytes((manifest.parent / "host-2.log").read_bytes())
        command[command.index("--expected-log-sha256") + 1] = _sha(new.read_bytes())
    elif change == "missing_manifest_pin":
        index = command.index("--expected-manifest-sha256")
        del command[index:index + 2]
    else:
        command[-1] = str(ROOT / "research-alerts.json")
    result = _run(command)
    assert result.returncode != 0
    assert not output.exists()
    assert "refused" in result.stderr or "required" in result.stderr
    assert "192.168.56" not in result.stderr
    assert str(tmp_path) not in result.stderr
