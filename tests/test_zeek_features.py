"""Synthetic regression tests for Zeek-only, versioned lab feature projection."""
import copy
import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from blue_team_ai.features import (
    LAB_FEATURE_COLUMNS, LAB_FEATURE_SCHEMA_VERSION,
    extract_zeek_feature_rows, extract_zeek_features,
)
from blue_team_ai.zeek import parse_zeek_conn_log


def sample_events():
    data = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
        "\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
        "1630000000.25\tC123\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp"
        "\t-\t1.25\t100\t-\t2\t-\n"
        "1630000001.0\tC124\t192.168.56.11\t52345\t192.168.56.21\t53\tudp"
        "\tdns\t-\t0\t25\t-\t1\n"
    ).encode("utf-8")
    return parse_zeek_conn_log(data)


def test_feature_projection_exact_order_and_types_without_leakage():
    events = sample_events()
    original = copy.deepcopy(events)
    rows = extract_zeek_feature_rows(events)
    assert LAB_FEATURE_SCHEMA_VERSION == 1
    assert list(rows[0]) == list(LAB_FEATURE_COLUMNS)
    assert len(rows) == 2
    assert rows[0] == {
        "proto": "tcp", "service": None, "src_port": 52344, "dst_port": 443,
        "duration_s": 1.25, "orig_bytes": 100, "resp_bytes": None,
        "orig_pkts": 2, "resp_pkts": None,
    }
    assert rows[1]["duration_s"] is None
    assert rows[1]["orig_bytes"] == 0  # Zero is not missing.
    assert rows[1]["service"] == "dns"
    assert events == original  # No mutation.
    for key in ("origin", "source_sha256", "event_time_utc", "uid",
                "src_ip", "dst_ip", "label", "attack_cat", "AI_verdict"):
        assert key not in rows[0]


@pytest.mark.parametrize("extra", ["label", "attack_cat", "AI_verdict", "AI_attack_probability", "flow_ref"])
def test_unexpected_or_leaky_event_fields_fail_closed(extra):
    event = sample_events()[0]
    event[extra] = 1
    with pytest.raises(ValueError, match="exact Zeek"):
        extract_zeek_features(event)


@pytest.mark.parametrize("field,value", [
    ("src_port", True), ("dst_port", 65536), ("orig_bytes", -1),
    ("resp_pkts", 1.5), ("orig_pkts", False),
    ("duration_s", float("nan")), ("duration_s", math.inf),
    ("duration_s", -0.01), ("proto", ""), ("service", 12),
    ("src_ip", "not-an-ip"), ("event_time_utc", "not-a-date"),
    ("event_time_utc", "2021-08-26T00:00:00+07:00"),
    ("source_sha256", "fake"), ("origin", "live"),
])
def test_malformed_zeek_event_rejected(field, value):
    event = sample_events()[0]
    event[field] = value
    with pytest.raises(ValueError):
        extract_zeek_features(event)


def test_batch_rejects_empty_mixed_source_and_invalid_input():
    events = sample_events()
    with pytest.raises(ValueError, match="nonempty"):
        extract_zeek_feature_rows([])
    with pytest.raises(ValueError, match="nonempty"):
        extract_zeek_feature_rows("not an event sequence")
    mixed = copy.deepcopy(events)
    mixed[1]["source_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="Mixed"):
        extract_zeek_feature_rows(mixed)


def test_batch_rejects_missing_field_and_does_not_drop_rows():
    events = sample_events()
    del events[1]["resp_bytes"]
    with pytest.raises(ValueError, match="exact Zeek"):
        extract_zeek_feature_rows(events)


def test_single_row_matches_batch_and_is_detached():
    events = sample_events()
    projected = extract_zeek_features(events[0])
    assert projected == extract_zeek_feature_rows(events)[0]
    projected["orig_bytes"] = 999
    assert events[0]["orig_bytes"] == 100
