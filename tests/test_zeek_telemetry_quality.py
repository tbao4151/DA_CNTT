"""Synthetic-only tests for bounded, private offline Zeek telemetry quality."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.telemetry_quality import inspect_zeek_telemetry_quality

CIDR = ["192.168.56.0/24"]


def _log(*, duplicate=False, outside=False, backwards=False):
    rows = [
        "1630000001.25\tTEST1\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp\t-\t1.25\t100\t-\t2\t-",
        f"1630000000.25\t{'TEST1' if duplicate else 'TEST2'}\t192.168.56.10\t52345\t{'8.8.8.8' if outside else '192.168.56.20'}\t53\tudp\tdns\t0.25\t40\t20\t1\t1",
    ]
    if not backwards:
        rows.reverse()
    return (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
        "\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
        + "\n".join(rows) + "\n"
    ).encode()


def _check(raw, *, sha=None):
    return inspect_zeek_telemetry_quality(
        raw, expected_sha256=sha or hashlib.sha256(raw).hexdigest(), lab_cidrs=CIDR,
    )


def test_aggregate_missingness_and_no_raw_identifiers():
    report = _check(_log())
    assert report["flow_count"] == 2
    assert report["missing_optional_feature_counts"] == {
        "service": 1, "duration_s": 0, "orig_bytes": 0,
        "resp_bytes": 1, "orig_pkts": 0, "resp_pkts": 1,
    }
    assert report["protocol_bucket_counts"] == {"tcp": 1, "udp": 1, "icmp": 0, "other": 0}
    assert report["out_of_order_timestamp_pairs"] == 0
    assert "optional_feature_measurements_missing" in report["warnings"]
    assert report["attack_detection_performed"] is False
    assert report["host_only_isolation_verified"] is False
    serialized = json.dumps(report)
    for forbidden in ("TEST1", "TEST2", "192.168.56.", "52344", "8.8.8.8"):
        assert forbidden not in serialized


def test_timestamp_order_warning_is_not_a_fake_latency():
    report = _check(_log(backwards=True))
    assert report["out_of_order_timestamp_pairs"] == 1
    assert "events_not_in_timestamp_order" in report["warnings"]
    assert "latency" not in json.dumps(report)


@pytest.mark.parametrize("raw,sha", [
    (_log(), "0" * 64),
    (_log(duplicate=True), None),
    (_log(outside=True), None),
    (b"not zeek", None),
])
def test_bad_sources_fail_closed(raw, sha):
    with pytest.raises((ValueError, UnicodeError)):
        _check(raw, sha=sha)


def test_cli_private_output_and_no_overwrite(tmp_path):
    raw = _log()
    source = tmp_path / "conn.log"
    source.write_bytes(raw)
    target = tmp_path / "quality.json"
    cmd = [
        sys.executable, str(ROOT / "scripts" / "inspect_zeek_telemetry_quality.py"),
        "--log", str(source), "--expected-log-sha256", hashlib.sha256(raw).hexdigest(),
        "--cidr", CIDR[0], "--output", str(target),
    ]
    first = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert first.returncode == 0, first.stderr
    assert json.loads(target.read_text())["flow_count"] == 2
    second = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert second.returncode == 1
    assert json.loads(target.read_text())["flow_count"] == 2


def test_cli_wrong_digest_no_output(tmp_path):
    source = tmp_path / "conn.log"
    source.write_bytes(_log())
    output = tmp_path / "quality.json"
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "inspect_zeek_telemetry_quality.py"),
        "--log", str(source), "--expected-log-sha256", "f" * 64,
        "--cidr", CIDR[0], "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert not output.exists()
