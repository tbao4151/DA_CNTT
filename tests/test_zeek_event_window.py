"""Synthetic-only UTC event-start window contract; no capture or latency measurement."""
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
START = "2021-08-26T17:46:40Z"
END = "2021-08-26T17:46:42Z"


def _log() -> bytes:
    return (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "1630000000.0\tSYN1\t192.168.56.10\t12345\t192.168.56.20\t443\ttcp\n"
        "1630000001.25\tSYN2\t192.168.56.20\t23456\t192.168.56.10\t53\tudp\n"
    ).encode("utf-8")


def _quality(*, start=None, end=None, raw=None):
    raw = _log() if raw is None else raw
    return inspect_zeek_telemetry_quality(
        raw, expected_sha256=hashlib.sha256(raw).hexdigest(), lab_cidrs=CIDR,
        event_window_start_utc=start, event_window_end_utc=end,
    )


def test_declared_utc_window_inclusive_and_no_latency_claim():
    report = _quality(start=START, end=END)
    assert report["flow_count"] == 2
    assert report["operator_event_window_checked"] is True
    assert report["event_window_capture_authenticity_verified"] is False
    assert report["attack_detection_performed"] is False
    assert _quality()["operator_event_window_checked"] is False
    encoded = json.dumps(report)
    for private in ("SYN1", "SYN2", "192.168.56.10", "12345"):
        assert private not in encoded
    assert "latency" not in encoded


@pytest.mark.parametrize("start,end", [
    (START, None),
    (None, END),
    ("2021-08-26T17:46:41Z", END),
    (START, "2021-08-26T17:46:41Z"),
    (END, START),
    ("2021-08-26T17:46:40+00:00", END),
    ("2021-08-26T17:46:40", END),
    ("2021-02-30T17:46:40Z", END),
    ("2021-08-26T17:46:40.000Z", END),
    (123, END),
])
def test_invalid_or_partial_window_refused(start, end):
    with pytest.raises(ValueError):
        _quality(start=start, end=end)


def test_window_is_checked_on_original_bytes_not_generated_timestamps():
    raw = _log().replace(b"1630000001.25", b"1630000101.25")
    with pytest.raises(ValueError, match="outside declared UTC window"):
        _quality(start=START, end=END, raw=raw)


def test_cli_refuses_out_of_window_without_creating_report(tmp_path):
    source = tmp_path / "conn.log"
    source.write_bytes(_log())
    target = tmp_path / "quality.json"
    cmd = [
        sys.executable, str(ROOT / "scripts" / "inspect_zeek_telemetry_quality.py"),
        "--log", str(source), "--expected-log-sha256",
        hashlib.sha256(source.read_bytes()).hexdigest(),
        "--cidr", CIDR[0], "--event-start-utc", START,
        "--event-end-utc", END, "--output", str(target),
    ]
    ok = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(target.read_text(encoding="utf-8"))["operator_event_window_checked"]
    assert source.read_bytes() == _log()

    blocked = tmp_path / "blocked.json"
    cmd[cmd.index("--event-end-utc") + 1] = "2021-08-26T17:46:41Z"
    cmd[cmd.index("--output") + 1] = str(blocked)
    refused = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert refused.returncode == 1
    assert not blocked.exists()
    assert "SYN2" not in refused.stderr
    assert "192.168.56." not in refused.stderr
