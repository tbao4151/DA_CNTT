"""Synthetic-only tests of pinned, NEW Zeek log research scoring.

These tests do not establish VMware isolation or real-world detection accuracy.
"""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.features import extract_zeek_feature_rows
from blue_team_ai.model_artifact import (
    build_zeek_research_artifact, score_zeek_research_rows,
)
from blue_team_ai.new_log_inference import score_new_zeek_log
from blue_team_ai.zeek import parse_zeek_conn_log
from test_zeek_offline_baseline import _dataset


def _log(uid2="NEW2", dst="192.168.56.20"):
    return (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
        "\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
        "1630000000.25\tNEW1\t192.168.56.10\t52344\t192.168.56.20\t443"
        "\ttcp\tssl\t1.25\t100\t200\t2\t3\n"
        f"1630000001.0\t{uid2}\t192.168.56.11\t52345\t{dst}\t53"
        "\tudp\tdns\t-\t0\t25\t-\t1\n"
    ).encode("utf-8")


@pytest.fixture
def model():
    return build_zeek_research_artifact(_dataset(), input_manifest_sha256="a" * 64)


def _score(raw, model, *, digest=None, cidr="192.168.56.0/24"):
    return score_new_zeek_log(
        raw, model, expected_log_sha256=digest or hashlib.sha256(raw).hexdigest(),
        lab_cidrs=[cidr], model_sha256="b" * 64,
    )


def test_new_log_scoring_matches_internal_json_scorer_and_preserves_real_fields(model):
    raw = _log()
    report = _score(raw, model)
    events = parse_zeek_conn_log(raw)
    expected = score_zeek_research_rows(model, extract_zeek_feature_rows(events))
    assert report["mode"] == "offline_new_zeek_research_inference_only"
    assert report["flow_count"] == 2
    assert report["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["research_candidate_count"] == sum(x["predicted_attack"] for x in expected)
    for actual, reference, event in zip(report["predictions"], expected, events, strict=True):
        assert actual["uid"] == event["uid"]
        assert actual["event_time_utc"] == event["event_time_utc"]
        assert actual["src_ip"] == event["src_ip"]
        assert actual["attack_probability"] == pytest.approx(reference["attack_probability"])
        assert actual["research_candidate"] == reference["predicted_attack"]
        assert "label" not in actual and "attack_cat" not in actual
    assert report["automated_alerts"] is False
    assert report["soc_cases_created"] is False
    assert report["test_partition_exclusion_verified"] is False
    assert report["host_only_isolation_verified"] is False


def test_modified_capture_out_of_scope_duplicate_uid_and_training_reuse_rejected(model):
    raw = _log()
    with pytest.raises(ValueError, match="pinned bytes"):
        _score(raw + b" ", model, digest=hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError, match="outside"):
        _score(_log(dst="8.8.8.8"), model)
    with pytest.raises(ValueError, match="Duplicate Zeek UIDs"):
        _score(_log(uid2="NEW1"), model)
    overlap = copy.deepcopy(model)
    overlap["train_source_sha256"] = sorted([hashlib.sha256(raw).hexdigest()])
    with pytest.raises(ValueError, match="training or validation"):
        _score(raw, overlap)
    with pytest.raises(ValueError, match="lowercase"):
        score_new_zeek_log(raw, model, expected_log_sha256="A" * 64,
                           lab_cidrs=["192.168.56.0/24"], model_sha256="b" * 64)


def test_cli_private_output_and_fail_closed_digest_scope_and_overwrite(tmp_path, model):
    private = tmp_path / "private"
    private.mkdir()
    raw = _log()
    log_path = private / "conn.log"
    log_path.write_bytes(raw)
    model_path = private / "model.json"
    model_bytes = json.dumps(model, allow_nan=False).encode("utf-8")
    model_path.write_bytes(model_bytes)
    output = private / "new-predictions.json"
    command = [
        sys.executable, str(ROOT / "scripts" / "score_zeek_new_log.py"),
        "--model", str(model_path),
        "--expected-model-sha256", hashlib.sha256(model_bytes).hexdigest(),
        "--log", str(log_path),
        "--expected-log-sha256", hashlib.sha256(raw).hexdigest(),
        "--cidr", "192.168.56.0/24",
        "--output", str(output),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["flow_count"] == 2
    assert report["automated_alerts"] is False
    assert "research_candidate_count=" in result.stdout
    assert subprocess.run(command, capture_output=True).returncode == 1
    before = output.read_bytes()
    assert before == output.read_bytes()
    output.unlink()

    for flag, wrong in (
        ("--expected-model-sha256", "0" * 64),
        ("--expected-log-sha256", "0" * 64),
        ("--cidr", "10.42.0.0/16"),
    ):
        changed = command.copy()
        changed[changed.index(flag) + 1] = wrong
        assert subprocess.run(changed, capture_output=True).returncode == 1
        assert not output.exists()

    outside = tmp_path / "outside.json"
    changed = command.copy()
    changed[changed.index("--output") + 1] = str(outside)
    assert subprocess.run(changed, capture_output=True).returncode == 1
    assert not outside.exists()
    assert model_path.read_bytes() == model_bytes
    assert log_path.read_bytes() == raw
