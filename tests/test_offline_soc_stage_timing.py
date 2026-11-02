"""Synthetic-only stage timing contract; not a real VMware measurement."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.offline_stage_timing import review_offline_soc_stage_timing


def _record():
    return {
        "record_version": 1,
        "clock_basis": "single_operator_host_utc",
        "timestamps_utc": {
            "capture_completed": "2026-11-02T12:00:00Z",
            "zeek_log_ready": "2026-11-02T12:00:01Z",
            "inference_started": "2026-11-02T12:00:03Z",
            "inference_finished": "2026-11-02T12:00:03.500Z",
            "research_queue_ready": "2026-11-02T12:00:04Z",
            "soc_case_created": "2026-11-02T12:00:09Z",
        },
        "declared_evidence_sha256": {
            key: str(index) * 64 for index, key in enumerate(
                ("pcap", "zeek_conn", "model", "research_report", "soc_case_export"), 1
            )
        },
    }


def _check(record):
    raw = json.dumps(record).encode()
    return review_offline_soc_stage_timing(
        raw, expected_record_sha256=hashlib.sha256(raw).hexdigest(),
    )


def test_stage_durations_are_aggregate_and_not_live_latency():
    report = _check(_record())
    assert report["stage_duration_ms"] == {
        "capture_complete_to_zeek_ready": 1000,
        "zeek_ready_to_inference_start": 2000,
        "inference_processing": 500,
        "inference_end_to_queue_ready": 500,
        "queue_ready_to_manual_soc_case": 5000,
    }
    assert report["capture_complete_to_manual_soc_case_ms"] == 9000
    assert report["packet_event_to_detection_latency_measured"] is False
    assert report["operational_alert_latency_measured"] is False
    assert report["evidence_file_bytes_verified"] is False
    assert "192.168." not in json.dumps(report)
    assert "timestamps_utc" not in report


@pytest.mark.parametrize("change", [
    "missing_stage", "extra_stage", "reverse", "non_utc", "naive",
    "bad_clock", "missing_pin", "bad_pin", "bool_version", "too_long",
])
def test_invalid_or_misleading_timing_refused(change):
    record = _record()
    times = record["timestamps_utc"]
    if change == "missing_stage":
        del times["inference_started"]
    elif change == "extra_stage":
        times["packet_detected"] = times["capture_completed"]
    elif change == "reverse":
        times["zeek_log_ready"] = "2026-11-02T11:59:59Z"
    elif change == "non_utc":
        times["soc_case_created"] = "2026-11-02T19:00:09+07:00"
    elif change == "naive":
        times["soc_case_created"] = "2026-11-02T12:00:09"
    elif change == "bad_clock":
        record["clock_basis"] = "unsynchronized_vm_clocks"
    elif change == "missing_pin":
        del record["declared_evidence_sha256"]["pcap"]
    elif change == "bad_pin":
        record["declared_evidence_sha256"]["pcap"] = "G" * 64
    elif change == "bool_version":
        record["record_version"] = True
    elif change == "too_long":
        times["soc_case_created"] = "2026-11-10T12:00:09Z"
    with pytest.raises(ValueError):
        _check(record)


def test_stale_digest_and_duplicate_keys_refused():
    record = _record()
    raw = json.dumps(record).encode()
    with pytest.raises(ValueError):
        review_offline_soc_stage_timing(raw, expected_record_sha256="0" * 64)
    duplicate = raw.replace(b'"record_version": 1,', b'"record_version": 1, "record_version": 1,')
    # The public review API deliberately hides parser internals while refusing bad JSON.
    # Assert the fail-closed contract, not the private object_pairs_hook message.
    nested_duplicate = raw.replace(
        b'"pcap": "' + b"1" * 64 + b'",',
        b'"pcap": "' + b"1" * 64 + b'", "pcap": "' + b"1" * 64 + b'",',
        1,
    )
    assert nested_duplicate != raw
    for invalid in (duplicate, nested_duplicate):
        with pytest.raises(ValueError, match="Malformed timing record"):
            review_offline_soc_stage_timing(
                invalid, expected_record_sha256=hashlib.sha256(invalid).hexdigest(),
            )


def test_cli_private_input_and_no_case_write(tmp_path):
    record = tmp_path / "timing.json"
    raw = json.dumps(_record()).encode()
    record.write_bytes(raw)
    command = [
        sys.executable, str(ROOT / "scripts" / "review_offline_soc_stage_timing.py"),
        "--record", str(record),
        "--expected-record-sha256", hashlib.sha256(raw).hexdigest(),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["capture_complete_to_manual_soc_case_ms"] == 9000
    assert not list(tmp_path.rglob("*.sqlite3"))
    assert "2026-11-02T12:00:09Z" not in result.stdout
    failed = command.copy()
    failed[-1] = "0" * 64
    refused = subprocess.run(failed, capture_output=True, text=True)
    assert refused.returncode == 1 and not refused.stdout
    assert str(tmp_path) not in refused.stderr
