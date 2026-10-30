"""Synthetic-only regression of verified research alert export; no VMware."""
from __future__ import annotations

import hashlib
import json
import re
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


def _pinned_manual_handoff(tmp_path):
    command, output, manifest, log, report = _fixture(tmp_path)
    exported = _run(command)
    assert exported.returncode == 0, exported.stderr
    bundle = json.loads(output.read_text(encoding="utf-8"))
    selected = bundle["research_alerts"][0]
    model_path = Path(command[command.index("--model") + 1])
    db = log.parent / "research-cases.sqlite3"
    triage = [
        sys.executable, str(ROOT / "scripts/triage_zeek_new_log.py"),
        "--model", str(model_path),
        "--expected-model-sha256", _sha(model_path.read_bytes()),
        "--log", str(log),
        "--expected-log-sha256", _sha(log.read_bytes()),
        "--report", str(report),
        "--manifest", str(manifest),
        "--expected-manifest-sha256", _sha(manifest.read_bytes()),
        "--cidr", "192.168.56.0/24",
        "--record-index", str(selected["record_index"]),
        "--db", str(db),
        "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture",
        "--research-alert-bundle", str(output),
        "--expected-research-alert-bundle-sha256", _sha(output.read_bytes()),
        "--research-alert-ref", selected["research_alert_ref"],
    ]
    return triage, output, db, selected


def test_pinned_queue_manual_handoff_creates_one_unclassified_case(tmp_path):
    command, output, db, selected = _pinned_manual_handoff(tmp_path)
    first = _run(command)
    assert first.returncode == 0, first.stderr
    assert "pinned_research_bundle_selection_reverified=true" in first.stdout
    sys.path.insert(0, str(ROOT / "src"))
    from siem_ai.core import case_history, list_cases
    cases = list_cases(db)
    assert len(cases) == 1
    row = cases.iloc[0]
    assert row["verdict"] == "Unclassified"
    assert row["state"] == "New"
    assert "NEW-log OFFLINE research candidate" in row["analyst_note"]
    assert "source_sha256=" in row["analyst_note"]
    # Preserve the existing canonical creation-audit contract.
    assert "research_bundle_sha256=" not in row["analyst_note"]
    second = _run(command)
    assert second.returncode == 0, second.stderr
    assert len(list_cases(db)) == 1
    assert len(case_history(db, row["case_id"])) == 1


@pytest.mark.parametrize("change", [
    "wrong_pin", "wrong_ref", "wrong_index", "missing_pin",
    "missing_manifest", "tampered_repin", "duplicate_key_repin",
    "noncanonical_type_repin",
])
def test_pinned_queue_handoff_refuses_unverified_selection_without_soc_write(
    tmp_path, change,
):
    command, output, db, selected = _pinned_manual_handoff(tmp_path)
    if change == "wrong_pin":
        command[command.index("--expected-research-alert-bundle-sha256") + 1] = "0" * 64
    elif change == "wrong_ref":
        command[command.index("--research-alert-ref") + 1] = "0" * 64
    elif change == "wrong_index":
        command[command.index("--record-index") + 1] = "499"
    elif change == "missing_pin":
        index = command.index("--expected-research-alert-bundle-sha256")
        del command[index:index + 2]
    elif change == "missing_manifest":
        index = command.index("--manifest")
        del command[index:index + 4]
    elif change == "tampered_repin":
        payload = json.loads(output.read_text(encoding="utf-8"))
        payload["research_alerts"][0]["soc_case_id"] = 99
        output.write_text(json.dumps(payload), encoding="utf-8")
    elif change == "duplicate_key_repin":
        raw = output.read_text(encoding="utf-8")
        output.write_text(raw.replace('"bundle_version": 1,',
                                           '"bundle_version": 1, "bundle_version": 1,', 1),
                          encoding="utf-8")
    else:
        payload = json.loads(output.read_text(encoding="utf-8"))
        # Python True == 1, but the validator must reject JSON type changes.
        payload["bundle_version"] = True
        output.write_text(json.dumps(payload), encoding="utf-8")
    if change in ("tampered_repin", "duplicate_key_repin", "noncanonical_type_repin"):
        command[command.index("--expected-research-alert-bundle-sha256") + 1] = _sha(
            output.read_bytes()
        )
    result = _run(command)
    assert result.returncode == 1
    assert not db.exists()
    assert "refused" in result.stderr
    assert "192.168.56" not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_opt_in_manual_soc_runtime_is_scoped_and_not_detection_latency(tmp_path):
    command, output, db, selected = _pinned_manual_handoff(tmp_path)
    first = _run(command)
    assert first.returncode == 0, first.stderr
    assert "offline_manual_soc_handoff_duration_ms=" not in first.stdout

    # Reusing an existing source+UID case is a different operation from
    # first-time creation. The timer must not pretend to measure analyst wait.
    timed = _run(command + ["--measure-manual-soc-runtime"])
    assert timed.returncode == 0, timed.stderr
    match = re.search(r"^offline_manual_soc_handoff_duration_ms=(\d+\.\d{6})$",
                      timed.stdout, re.MULTILINE)
    assert match is not None
    assert float(match.group(1)) >= 0
    assert "offline_manual_soc_handoff_boundary=verified_recompute_plus_sqlite_create_or_reuse" in timed.stdout
    assert "detection_latency_measured=false; analyst_wait_excluded=true" in timed.stdout
    assert "192.168.56." not in timed.stdout
    sys.path.insert(0, str(ROOT / "src"))
    from siem_ai.core import list_cases
    assert len(list_cases(db)) == 1


def test_opt_in_manual_soc_runtime_refuses_bad_pin_without_timing_or_write(tmp_path):
    command, output, db, selected = _pinned_manual_handoff(tmp_path)
    command[command.index("--expected-research-alert-bundle-sha256") + 1] = "0" * 64
    failed = _run(command + ["--measure-manual-soc-runtime"])
    assert failed.returncode == 1
    assert "offline_manual_soc_handoff_duration_ms=" not in failed.stdout
    assert not db.exists()
    assert "refused" in failed.stderr


def test_opt_in_research_queue_export_runtime_scoped_and_json_deterministic(tmp_path):
    command, output, manifest, log, report = _fixture(tmp_path)
    timed = _run(command + ["--measure-research-export-runtime"])
    assert timed.returncode == 0, timed.stderr
    match = re.search(r"^offline_research_queue_export_duration_ms=(\d+\.\d{6})$",
                      timed.stdout, re.MULTILINE)
    assert match is not None
    assert float(match.group(1)) >= 0
    assert "offline_research_queue_export_boundary=verified_recompute_json_publish" in timed.stdout
    assert "detection_latency_measured=false; capture_zeek_analyst_wait_excluded=true" in timed.stdout
    assert "192.168.56." not in timed.stdout
    assert str(tmp_path) not in timed.stdout
    first_bytes = output.read_bytes()
    second = log.parent / "research-alerts-untimed.json"
    untimed_command = command.copy()
    untimed_command[untimed_command.index("--output") + 1] = str(second)
    untimed = _run(untimed_command)
    assert untimed.returncode == 0, untimed.stderr
    assert "offline_research_queue_export_duration_ms=" not in untimed.stdout
    assert first_bytes == second.read_bytes()  # Timing is never embedded in evidence.


def test_opt_in_research_queue_export_runtime_refuses_bad_pin_without_timing(tmp_path):
    command, output, manifest, log, report = _fixture(tmp_path)
    command[command.index("--expected-report-sha256") + 1] = "0" * 64
    failed = _run(command + ["--measure-research-export-runtime"])
    assert failed.returncode == 1
    assert not output.exists()
    assert "offline_research_queue_export_duration_ms=" not in failed.stdout
    assert "refused" in failed.stderr
    assert "192.168.56." not in failed.stderr
    assert str(tmp_path) not in failed.stderr
