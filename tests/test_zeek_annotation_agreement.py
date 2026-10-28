"""Synthetic-only regression: agreement is not verified attack ground truth."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from blue_team_ai.annotation_agreement import review_zeek_annotator_agreement


def _fixture():
    rows = [
        f"163000000{i}.0\tU{i}\t192.168.56.10\t5234{i}\t192.168.56.20\t443\ttcp"
        for i in range(4)
    ]
    raw = ("#separator \\x09\n"
           "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
           + "\n".join(rows) + "\n").encode()
    source = hashlib.sha256(raw).hexdigest()
    a = json.dumps({"source_sha256": source, "labels_by_uid":
                    {"U0": 0, "U1": 0, "U2": 1, "U3": 1}}).encode()
    b = json.dumps({"source_sha256": source, "labels_by_uid":
                    {"U0": 0, "U1": 0, "U2": 0, "U3": 1}}).encode()
    return raw, a, b


def _review(raw, a, b, **overrides):
    params = dict(
        expected_log_sha256=hashlib.sha256(raw).hexdigest(),
        expected_a_sha256=hashlib.sha256(a).hexdigest(),
        expected_b_sha256=hashlib.sha256(b).hexdigest(),
    )
    params.update(overrides)
    return review_zeek_annotator_agreement(raw, a, b, **params)


def test_agreement_counts_kappa_and_no_uid_leak():
    raw, a, b = _fixture()
    report = _review(raw, a, b)
    assert report["counts"] == {"a0_b0": 2, "a0_b1": 0, "a1_b0": 1, "a1_b1": 1}
    assert report["flow_count"] == 4
    assert report["agreement_count"] == 3
    assert report["disagreement_count"] == 1
    assert report["observed_agreement"] == .75
    assert report["cohen_kappa"] == .5
    assert report["ground_truth_verified"] is False
    assert report["consensus_labels_generated"] is False
    assert "U0" not in json.dumps(report)
    assert "192.168" not in json.dumps(report)


def test_perfect_agreement_and_undefined_single_class_kappa():
    raw, a, _ = _fixture()
    assert _review(raw, a, a)["cohen_kappa"] == 1
    source = hashlib.sha256(raw).hexdigest()
    one = json.dumps({"source_sha256": source,
                      "labels_by_uid": {f"U{i}": 0 for i in range(4)}}).encode()
    report = _review(raw, one, one)
    assert report["observed_agreement"] == 1
    assert report["chance_agreement"] == 1
    assert report["cohen_kappa"] is None


@pytest.mark.parametrize("field", ["expected_log_sha256", "expected_a_sha256", "expected_b_sha256"])
def test_stale_or_unpinned_digest_refused(field):
    raw, a, b = _fixture()
    with pytest.raises(ValueError, match="SHA-256"):
        _review(raw, a, b, **{field: "0" * 64})
    with pytest.raises(ValueError, match="SHA-256"):
        _review(raw, a, b, **{field: "A" * 64})


@pytest.mark.parametrize("bad_labels", [
    {"U0": 0, "U1": 0, "U2": 1},
    {"U0": 0, "U1": 0, "U2": 1, "U3": True},
    {"U0": 0, "U1": 0, "U2": 1, "U3": None},
    {"U0": 0, "U1": 0, "U2": 1, "U3": "1"},
    {"U0": 0, "U1": 0, "U2": 1, "U3": 2},
])
def test_bad_annotation_coverage_and_values_refused(bad_labels):
    raw, a, _ = _fixture()
    b = json.dumps({"source_sha256": hashlib.sha256(raw).hexdigest(),
                    "labels_by_uid": bad_labels}).encode()
    with pytest.raises(ValueError):
        _review(raw, a, b)


def test_duplicate_json_keys_and_wrong_source_refused():
    raw, a, _ = _fixture()
    source = hashlib.sha256(raw).hexdigest()
    duplicate = ('{"source_sha256":"' + source
                 + '","labels_by_uid":{"U0":0,"U0":1,"U1":0,"U2":1,"U3":1}}').encode()
    with pytest.raises(ValueError, match="Duplicate"):
        _review(raw, a, duplicate)
    changed = json.dumps({"source_sha256": "0" * 64,
                          "labels_by_uid": {f"U{i}": 0 for i in range(4)}}).encode()
    with pytest.raises(ValueError, match="source SHA"):
        _review(raw, a, changed)


def test_cli_writes_private_aggregate_exclusively(tmp_path):
    raw, a, b = _fixture()
    for name, payload in (("conn.log", raw), ("a.json", a), ("b.json", b)):
        (tmp_path / name).write_bytes(payload)
    output = tmp_path / "agreement.json"
    cmd = [
        sys.executable, str(ROOT / "scripts" / "review_zeek_annotation_agreement.py"),
        "--log", str(tmp_path / "conn.log"),
        "--annotation-a", str(tmp_path / "a.json"),
        "--annotation-b", str(tmp_path / "b.json"),
        "--expected-log-sha256", hashlib.sha256(raw).hexdigest(),
        "--expected-a-sha256", hashlib.sha256(a).hexdigest(),
        "--expected-b-sha256", hashlib.sha256(b).hexdigest(),
        "--output", str(output),
    ]
    first = subprocess.run(cmd, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    assert json.loads(output.read_text())["cohen_kappa"] == .5
    assert "U0" not in output.read_text()
    assert "192.168" not in output.read_text()
    assert subprocess.run(cmd, capture_output=True).returncode == 1
    assert "U0" not in first.stdout


def test_cli_refuses_tampered_label_without_output(tmp_path):
    raw, a, b = _fixture()
    for name, payload in (("conn.log", raw), ("a.json", a), ("b.json", b)):
        (tmp_path / name).write_bytes(payload)
    output = tmp_path / "agreement.json"
    cmd = [
        sys.executable, str(ROOT / "scripts" / "review_zeek_annotation_agreement.py"),
        "--log", str(tmp_path / "conn.log"),
        "--annotation-a", str(tmp_path / "a.json"),
        "--annotation-b", str(tmp_path / "b.json"),
        "--expected-log-sha256", hashlib.sha256(raw).hexdigest(),
        "--expected-a-sha256", hashlib.sha256(a).hexdigest(),
        "--expected-b-sha256", "0" * 64,
        "--output", str(output),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 1
    assert not output.exists()
