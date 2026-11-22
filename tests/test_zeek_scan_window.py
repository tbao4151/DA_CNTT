"""Network-free Zeek rolling port-diversity diagnostics (not an AI model)."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.scan_window import rolling_port_diversity
from blue_team_ai.zeek import parse_zeek_conn_log
import inspect_zeek_scan_windows as cli


def fixture_bytes():
    fields = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
    )
    rows = []
    base = 1795339000.0
    # Four benign probes separated by more than a 10-second window.
    for index, delta in enumerate((0, 20, 40, 60)):
        rows.append(
            f"{base + delta:.3f}\tN{index}\t192.168.77.10\t50000\t"
            "192.168.77.20\t22\ttcp\n"
        )
    ports = (21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 8080, 8443)
    for index, port in enumerate(ports):
        rows.append(
            f"{base + 100 + index * 0.25:.3f}\tS{index}\t192.168.77.10\t"
            f"{51000 + index}\t192.168.77.20\t{port}\ttcp\n"
        )
    return (fields + "".join(rows)).encode("utf-8")


def test_offline_window_is_past_only_and_pair_scoped():
    events = parse_zeek_conn_log(fixture_bytes())
    original = [dict(e) for e in events]
    result = rolling_port_diversity(events, window_seconds=10, min_distinct_ports=5)
    assert len(result) == 16
    assert [row["uid"] for row in result] == [e["uid"] for e in events]
    assert [row["port_diversity_heuristic_candidate"] for row in result[:4]] == [False] * 4
    assert [row["distinct_destination_ports_in_window"] for row in result[4:]] == list(range(1, 13))
    assert sum(row["port_diversity_heuristic_candidate"] for row in result) == 8
    assert result[-1]["connections_in_window"] == 12
    assert events == original  # No modifications to source events or labels.


def test_reordered_log_keeps_attribution_without_seeing_future_start_times():
    events = parse_zeek_conn_log(fixture_bytes())
    permuted = list(reversed(events))
    scored = rolling_port_diversity(permuted)
    by_uid = {row["uid"]: row for row in scored}
    assert scored[0]["uid"] == "S11"
    assert by_uid["S0"]["distinct_destination_ports_in_window"] == 1
    assert by_uid["S4"]["distinct_destination_ports_in_window"] == 5
    assert by_uid["S11"]["distinct_destination_ports_in_window"] == 12


def test_pair_and_protocol_separation():
    events = parse_zeek_conn_log(fixture_bytes())
    shifted = [dict(e) for e in events]
    shifted[10]["src_ip"] = "192.168.77.11"
    shifted[11]["dst_ip"] = "192.168.77.21"
    shifted[12]["proto"] = "udp"
    scored = rolling_port_diversity(shifted)
    assert scored[12]["connections_in_window"] == 0
    assert scored[12]["port_diversity_heuristic_candidate"] is False
    assert scored[-1]["distinct_destination_ports_in_window"] == 9


@pytest.mark.parametrize("option", [
    {"window_seconds": 0}, {"window_seconds": True},
    {"window_seconds": 61}, {"min_distinct_ports": 1},
    {"min_distinct_ports": False}, {"min_distinct_ports": 101},
])
def test_invalid_window_configuration_is_rejected(option):
    with pytest.raises(ValueError):
        rolling_port_diversity(parse_zeek_conn_log(fixture_bytes()), **option)


def test_uid_reuse_and_extra_schema_are_rejected():
    events = parse_zeek_conn_log(fixture_bytes())
    with pytest.raises(ValueError, match="repeated"):
        rolling_port_diversity([events[0], events[0]])
    forged = [dict(events[0])]
    forged[0]["scenario_label"] = 1
    with pytest.raises(ValueError, match="exact Zeek"):
        rolling_port_diversity(forged)


def test_pinned_cli_aggregates_operator_labels_without_training(tmp_path):
    raw = fixture_bytes()
    log = tmp_path / "conn.log"
    log.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    entries = parse_zeek_conn_log(raw)
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({
        "source_sha256": digest,
        "labels_by_uid": {
            event["uid"]: 1 if event["uid"].startswith("S") else 0 for event in entries
        },
    }), encoding="utf-8")
    report = cli.run(
        log=log, expected_log_sha256=digest, labels=labels,
        cidr="192.168.77.0/24",
    )
    assert report["flow_count"] == 16
    assert report["candidate_flow_count"] == 8
    assert report["maximum_distinct_ports_in_window"] == 12
    assert report["operator_label_0_count"] == 4
    assert report["operator_label_1_count"] == 12
    assert report["label_0_candidate_count"] == 0
    assert report["label_1_candidate_count"] == 8
    assert report["ai_inference_performed"] is False
    assert report["operational_alerts_created"] is False
    assert "uid" not in report and "src_ip" not in report


def test_cli_rejects_bad_pins_scope_and_unlabeled_input(tmp_path):
    raw = fixture_bytes()
    log = tmp_path / "conn.log"
    log.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="SHA-256"):
        cli.run(log=log, expected_log_sha256="a" * 64,
                cidr="192.168.77.0/24")
    with pytest.raises(ValueError, match="Out-of-scope"):
        cli.run(log=log, expected_log_sha256=digest,
                cidr="192.168.88.0/24")
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({
        "source_sha256": digest,
        "labels_by_uid": {event["uid"]: None for event in parse_zeek_conn_log(raw)},
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="Labels do not cover"):
        cli.run(log=log, expected_log_sha256=digest,
                cidr="192.168.77.0/24", labels=labels)


def test_cli_rejects_in_repo_and_symlink(tmp_path):
    raw = fixture_bytes()
    log = tmp_path / "conn.log"
    log.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError):
        cli.run(log=ROOT / "README.md", expected_log_sha256=digest,
                cidr="192.168.77.0/24")
    linked = tmp_path / "alias.log"
    try:
        linked.symlink_to(log)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not permitted by this platform")
    with pytest.raises(ValueError, match="Symlink"):
        cli.run(log=linked, expected_log_sha256=digest,
                cidr="192.168.77.0/24")
