"""Synthetic-only production CLI regression for opt-in PCAP/Zeek timestamp gating.

The import fixture mocks Zeek. These tests do not capture packets, run VMware,
prove Zeek derivation or establish independent attack labels.
"""
from __future__ import annotations

import hashlib
import json

from blue_team_ai.model_artifact import build_zeek_research_artifact
from blue_team_ai.zeek_smoke import build_benign_udp_pcap
from test_offline_pcap_verify import imported
from test_offline_pcap_scoring_gate import _command, _run
from test_pcap_zeek_tuple import zeek_log
from test_zeek_offline_baseline import _dataset


def _prepare(imported, *, timestamp: str):
    """Re-pin a coherent synthetic PCAP/log/import report; never claim provenance."""
    raw_pcap = build_benign_udp_pcap()
    raw_log = zeek_log(
        src="192.168.56.10", dst="192.168.56.20",
        sport=51000, dport=53000, proto="udp", ts=timestamp,
    )
    imported["pcap"].write_bytes(raw_pcap)
    imported["log"].write_bytes(raw_log)
    report = json.loads(imported["report"].read_text(encoding="utf-8"))
    report["pcap_sha256"] = hashlib.sha256(raw_pcap).hexdigest()
    report["pcap_size_bytes"] = len(raw_pcap)
    report["zeek_conn_sha256"] = hashlib.sha256(raw_log).hexdigest()
    report["zeek_conn_size_bytes"] = len(raw_log)
    imported["report"].write_text(json.dumps(report), encoding="utf-8")
    imported["pin"] = hashlib.sha256(imported["report"].read_bytes()).hexdigest()

    model = build_zeek_research_artifact(_dataset(), input_manifest_sha256="a" * 64)
    model_path = imported["pcap"].parent / "timestamp-test-research-model.json"
    model_bytes = (json.dumps(model, allow_nan=False) + "\n").encode("utf-8")
    model_path.write_bytes(model_bytes)
    output = imported["log"].parent / "timestamp-gated-research-scores.json"
    cmd = _command(
        imported, model_path, hashlib.sha256(model_bytes).hexdigest(), output,
    )
    return cmd, output, raw_pcap, raw_log


def test_opt_in_timestamp_gate_accepts_coherent_synthetic_pcap_and_log(imported):
    cmd, output, pcap, log = _prepare(imported, timestamp="1700000000.0")
    completed = _run([*cmd, "--require-pcap-zeek-timestamp-corroboration"])
    assert completed.returncode == 0, completed.stderr
    assert "timestamp presence checked" in completed.stdout
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["flow_count"] == 1
    assert saved["operational_attack_detection_verified"] is False
    assert saved["automated_alerts"] is False
    assert saved["soc_cases_created"] is False
    assert imported["pcap"].read_bytes() == pcap
    assert imported["log"].read_bytes() == log


def test_opt_in_timestamp_gate_rejects_stale_flow_before_prediction(imported):
    cmd, output, _, _ = _prepare(imported, timestamp="1700000120.0")
    strict = _run([*cmd, "--require-pcap-zeek-timestamp-corroboration"])
    assert strict.returncode == 1
    assert not output.exists()
    assert "refused" in strict.stderr
    # Backward compatibility: the old import-report pin checks bytes/scope,
    # not temporal correspondence, and still permits the same synthetic log.
    legacy = _run(cmd)
    assert legacy.returncode == 0, legacy.stderr
    assert output.exists()


def test_opt_in_timestamp_gate_requires_complete_pinned_import_evidence(imported):
    cmd, output, _, _ = _prepare(imported, timestamp="1700000000.0")
    for flag in (
        "--offline-import-report",
        "--expected-offline-import-report-sha256",
        "--offline-import-pcap",
    ):
        incomplete = cmd.copy()
        pos = incomplete.index(flag)
        del incomplete[pos:pos + 2]
        result = _run([*incomplete, "--require-pcap-zeek-timestamp-corroboration"])
        assert result.returncode == 1
        assert not output.exists()
        assert str(imported["pcap"]) not in result.stderr


def test_opt_in_timestamp_gate_refuses_tuple_mismatch_even_with_valid_hashes(imported):
    cmd, output, _, _ = _prepare(imported, timestamp="1700000000.0")
    # The import report and all independent digests match; the packet tuple
    # does not. The timestamp gate must refuse before scoring/publication.
    raw_log = zeek_log(
        src="192.168.56.10", dst="192.168.56.20",
        sport=51000, dport=53001, proto="udp", ts="1700000000.0",
    )
    imported["log"].write_bytes(raw_log)
    report = json.loads(imported["report"].read_text(encoding="utf-8"))
    report["zeek_conn_sha256"] = hashlib.sha256(raw_log).hexdigest()
    report["zeek_conn_size_bytes"] = len(raw_log)
    imported["report"].write_text(json.dumps(report), encoding="utf-8")
    cmd[cmd.index("--expected-log-sha256") + 1] = hashlib.sha256(raw_log).hexdigest()
    cmd[cmd.index("--expected-offline-import-report-sha256") + 1] = (
        hashlib.sha256(imported["report"].read_bytes()).hexdigest()
    )
    assert _run([*cmd, "--require-pcap-zeek-timestamp-corroboration"]).returncode == 1
    assert not output.exists()
