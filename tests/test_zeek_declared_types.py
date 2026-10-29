"""Synthetic-only Zeek declared-type contract tests; no capture or detection."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.telemetry_quality import (
    inspect_zeek_declared_types, inspect_zeek_telemetry_quality,
)

CIDR = ["192.168.56.0/24"]
FIELDS = (
    b"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
    b"\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts"
)
TYPES = (
    b"#types\ttime\tstring\taddr\tport\taddr\tport\tenum"
    b"\tstring\tinterval\tcount\tcount\tcount\tcount"
)
ROWS = (
    b"1630000000.25\tTEST1\t192.168.56.10\t52344\t192.168.56.20"
    b"\t443\ttcp\t-\t1.25\t100\t-\t2\t-\n"
)


def _log(*, typed=True):
    return b"#separator \\x09\n" + FIELDS + b"\n" + (TYPES + b"\n" if typed else b"") + ROWS


def _quality(raw, *, strict=True):
    return inspect_zeek_telemetry_quality(
        raw, expected_sha256=hashlib.sha256(raw).hexdigest(),
        lab_cidrs=CIDR, require_zeek_types=strict,
    )


def test_correct_declared_types_pass_and_do_not_leak_raw_identifiers():
    report = _quality(_log())
    assert report["zeek_declared_types"] == {
        "declared_types_checked": True,
        "required_type_fields_checked": 7,
        "optional_type_fields_checked": 6,
        "capture_authenticity_verified": False,
        "host_only_isolation_verified": False,
    }
    assert report["flow_count"] == 1
    assert "zeek_declared_types" not in _quality(_log(typed=False), strict=False)
    for sensitive in ("TEST1", "192.168.56.10", "52344"):
        assert sensitive not in json.dumps(report)


@pytest.mark.parametrize("mutation", [
    lambda raw: _log(typed=False),
    lambda raw: raw.replace(b"#types\ttime", b"#types\tstring", 1),
    lambda raw: raw.replace(b"\tport\taddr\tport\tenum", b"\tport\taddr\tport\tstring", 1),
    lambda raw: raw.replace(b"\tinterval\tcount", b"\tstring\tcount", 1),
    lambda raw: raw.replace(b"\tcount\tcount\tcount\tcount\n", b"\tcount\tcount\tcount\n", 1),
    lambda raw: raw.replace(TYPES + b"\n", TYPES + b"\n" + TYPES + b"\n", 1),
    lambda raw: raw.replace(TYPES + b"\n", b"", 1) + TYPES + b"\n",
])
def test_missing_wrong_duplicate_or_late_types_fail_closed(mutation):
    raw = mutation(_log())
    with pytest.raises(ValueError):
        _quality(raw)


def test_extension_columns_are_allowed_but_required_types_are_not_optional():
    extended = _log().replace(
        FIELDS + b"\n", FIELDS + b"\tlocal_orig\n", 1,
    ).replace(
        TYPES + b"\n", TYPES + b"\tbool\n", 1,
    ).replace(
        ROWS, ROWS[:-1] + b"\tF\n", 1,
    )
    result = inspect_zeek_declared_types(extended)
    assert result["required_type_fields_checked"] == 7
    assert result["optional_type_fields_checked"] == 6


def test_private_cli_types_gate_accepts_valid_and_rejects_bad_without_output(tmp_path):
    source = tmp_path / "conn.log"
    source.write_bytes(_log())
    output = tmp_path / "quality.json"
    args = [
        sys.executable, str(ROOT / "scripts" / "inspect_zeek_telemetry_quality.py"),
        "--log", str(source),
        "--expected-log-sha256", hashlib.sha256(source.read_bytes()).hexdigest(),
        "--cidr", CIDR[0], "--require-zeek-types", "--output", str(output),
    ]
    ok = subprocess.run(args, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(output.read_text())["zeek_declared_types"]["declared_types_checked"]
    bad = _log(typed=False)
    source.write_bytes(bad)
    blocked = tmp_path / "blocked.json"
    args[args.index("--expected-log-sha256") + 1] = hashlib.sha256(bad).hexdigest()
    args[args.index("--output") + 1] = str(blocked)
    refused = subprocess.run(args, capture_output=True, text=True)
    assert refused.returncode == 1
    assert not blocked.exists()
