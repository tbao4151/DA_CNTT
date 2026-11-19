"""Synthetic, network-free candidate-only Zeek correlation contract tests."""
from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from shared.zeek_stimulus_match import screen_candidate_zeek_matches


def _log(entries: list[tuple[datetime, str, str, int]]) -> bytes:
    lines = [
        r"#separator \x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto",
    ]
    for when, uid, src, port in entries:
        lines.append(
            f"{when.timestamp():.3f}\t{uid}\t{src}\t54321\t192.168.77.20\t{port}\ttcp"
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _receipt(when: datetime) -> dict:
    return {
        "kind": "da005_benign_vmware_hostonly_network_stimulus",
        "mode": "BENIGN_LAB_EXECUTION",
        "scenario_id": "connection_shift",
        "scope": {
            "source_ip": "192.168.77.1",
            "target_ip": "192.168.77.20",
            "cidr": "192.168.77.0/24",
        },
        "planned_attempts": 2,
        "network_attempts": 2,
        "events": [
            {"attempted_at_utc": when.isoformat(), "scenario_id": "connection_shift",
             "protocol": "tcp", "port": 22},
            {"attempted_at_utc": (when + timedelta(seconds=3)).isoformat(),
             "scenario_id": "connection_shift", "protocol": "tcp", "port": 22},
        ],
    }


def test_candidate_matches_two_distinct_flow_uids_without_detection_claim():
    start = datetime(2026, 11, 19, 6, tzinfo=timezone.utc)
    raw = _log([
        (start + timedelta(milliseconds=100), "C1", "192.168.77.1", 22),
        (start + timedelta(seconds=3, milliseconds=100), "C2", "192.168.77.1", 22),
        (start, "Other", "192.168.77.33", 22),
    ])
    result = screen_candidate_zeek_matches(
        _receipt(start), raw, expected_log_sha256=hashlib.sha256(raw).hexdigest(),
    )
    assert result["candidate_match_count"] == 2
    assert result["unmatched_probe_count"] == 0
    assert {x["zeek_uid"] for x in result["candidates"]} == {"C1", "C2"}
    assert result["causal_packet_to_zeek_uid_proof"] is False
    assert result["clock_sync_independently_verified"] is False
    assert result["attack_detection_verified"] is False
    assert result["ground_truth_verified"] is False


def test_bad_timing_and_different_endpoint_do_not_match():
    start = datetime(2026, 11, 19, 6, tzinfo=timezone.utc)
    raw = _log([
        (start + timedelta(minutes=2), "Late", "192.168.77.1", 22),
        (start, "WrongSrc", "192.168.77.2", 22),
        (start, "WrongPort", "192.168.77.1", 443),
    ])
    out = screen_candidate_zeek_matches(
        _receipt(start), raw, expected_log_sha256=hashlib.sha256(raw).hexdigest(),
    )
    assert out["candidate_match_count"] == 0
    assert out["unmatched_probe_count"] == 2


def test_one_log_uid_cannot_satisfy_two_probes():
    start = datetime(2026, 11, 19, 6, tzinfo=timezone.utc)
    raw = _log([(start, "Only", "192.168.77.1", 22)])
    result = screen_candidate_zeek_matches(
        _receipt(start), raw, expected_log_sha256=hashlib.sha256(raw).hexdigest(),
    )
    assert result["candidate_match_count"] == 1


@pytest.mark.parametrize("mutation", [
    {"mode": "DRY_RUN_EXECUTION_OFF"},
    {"planned_attempts": 5},
    {"network_attempts": 0},
    {"events": []},
    {"scenario_id": "port_scan"},
    {"scope": {"source_ip": "8.8.8.8", "target_ip": "192.168.77.20",
               "cidr": "192.168.77.0/24"}},
])
def test_forged_or_unsafe_receipt_fails_closed(mutation):
    start = datetime(2026, 11, 19, 6, tzinfo=timezone.utc)
    raw = _log([(start, "C1", "192.168.77.1", 22)])
    receipt = _receipt(start)
    receipt.update(mutation)
    with pytest.raises(ValueError):
        screen_candidate_zeek_matches(
            receipt, raw, expected_log_sha256=hashlib.sha256(raw).hexdigest(),
        )


def test_malformed_timestamp_or_wrong_pinned_source_fails_closed():
    start = datetime(2026, 11, 19, 6, tzinfo=timezone.utc)
    raw = _log([(start, "C1", "192.168.77.1", 22)])
    receipt = _receipt(start)
    with pytest.raises(ValueError):
        screen_candidate_zeek_matches(receipt, raw, expected_log_sha256="0"*64)
    receipt["events"][0]["attempted_at_utc"] = "2026-11-19T06:00:00"
    with pytest.raises(ValueError):
        screen_candidate_zeek_matches(
            receipt, raw, expected_log_sha256=hashlib.sha256(raw).hexdigest(),
        )
