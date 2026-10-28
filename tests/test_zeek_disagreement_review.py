"""Synthetic-only tests: private disagreement review is not attack ground truth."""
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
from blue_team_ai.disagreement_review import build_private_disagreement_template


def _inputs():
    rows = [
        f"163000000{i}.0\tU{i}\t192.168.56.10\t5234{i}\t192.168.56.20\t443\ttcp"
        for i in range(4)
    ]
    log = ("#separator \\x09\n"
           "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
           + "\n".join(rows) + "\n").encode("utf-8")
    digest = hashlib.sha256(log).hexdigest()
    a = json.dumps({"source_sha256": digest, "labels_by_uid":
                    {"U0": 0, "U1": 1, "U2": 0, "U3": 1}}).encode()
    b = json.dumps({"source_sha256": digest, "labels_by_uid":
                    {"U0": 0, "U1": 0, "U2": 1, "U3": 1}}).encode()
    return log, a, b


def _kwargs(log, a, b):
    return {
        "expected_log_sha256": hashlib.sha256(log).hexdigest(),
        "expected_a_sha256": hashlib.sha256(a).hexdigest(),
        "expected_b_sha256": hashlib.sha256(b).hexdigest(),
    }


def _command(tmp_path, log, a, b, *, acknowledge=True):
    for name, raw in (("conn.log", log), ("reviewer-a.json", a), ("reviewer-b.json", b)):
        (tmp_path / name).write_bytes(raw)
    cmd = [
        sys.executable, str(ROOT / "scripts" / "prepare_zeek_disagreements.py"),
        "--log", str(tmp_path / "conn.log"),
        "--annotation-a", str(tmp_path / "reviewer-a.json"),
        "--annotation-b", str(tmp_path / "reviewer-b.json"),
        "--expected-log-sha256", hashlib.sha256(log).hexdigest(),
        "--expected-a-sha256", hashlib.sha256(a).hexdigest(),
        "--expected-b-sha256", hashlib.sha256(b).hexdigest(),
        "--output", str(tmp_path / "disagreements.json"),
    ]
    if acknowledge:
        cmd.append("--acknowledge-private-uids")
    return cmd


def test_only_disagreements_exported_with_null_adjudication():
    log, a, b = _inputs()
    report = build_private_disagreement_template(log, a, b, **_kwargs(log, a, b))
    assert report["disagreement_count"] == 2
    assert set(report["disagreements_by_uid"]) == {"U1", "U2"}
    assert report["disagreements_by_uid"]["U1"] == {
        "reviewer_a_label": 1, "reviewer_b_label": 0,
        "adjudicated_label": None, "evidence_reference": None,
    }
    assert report["disagreements_by_uid"]["U2"]["adjudicated_label"] is None
    assert report["consensus_labels_generated"] is False
    assert report["ground_truth_verified"] is False
    assert "192.168.56." not in json.dumps(report)
    aggregate = review_zeek_annotator_agreement(log, a, b, **_kwargs(log, a, b))
    assert aggregate["disagreement_count"] == 2
    assert "U1" not in json.dumps(aggregate)
    assert "disagreements_by_uid" not in aggregate


def test_zero_disagreements_does_not_infer_ground_truth():
    log, a, _ = _inputs()
    report = build_private_disagreement_template(log, a, a, **_kwargs(log, a, a))
    assert report["disagreements_by_uid"] == {}
    assert report["ground_truth_verified"] is False


@pytest.mark.parametrize("which", ["expected_log_sha256", "expected_a_sha256", "expected_b_sha256"])
def test_wrong_pinned_hash_fails_closed(which):
    log, a, b = _inputs()
    kw = _kwargs(log, a, b)
    kw[which] = "0" * 64
    with pytest.raises(ValueError, match="SHA-256"):
        build_private_disagreement_template(log, a, b, **kw)


def test_wrong_uid_coverage_and_duplicate_json_keys_refused():
    log, a, b = _inputs()
    digest = hashlib.sha256(log).hexdigest()
    incomplete = json.dumps({"source_sha256": digest, "labels_by_uid": {"U0": 0}}).encode()
    with pytest.raises(ValueError, match="coverage"):
        build_private_disagreement_template(log, a, incomplete, **_kwargs(log, a, incomplete))
    duplicate = ('{"source_sha256":"' + digest
                 + '","labels_by_uid":{"U0":0,"U0":1,"U1":0,"U2":1,"U3":1}}').encode()
    with pytest.raises(ValueError, match="Duplicate"):
        build_private_disagreement_template(log, a, duplicate, **_kwargs(log, a, duplicate))


def test_cli_requires_explicit_ack_and_exclusive_private_output(tmp_path):
    log, a, b = _inputs()
    cmd = _command(tmp_path, log, a, b, acknowledge=False)
    output = tmp_path / "disagreements.json"
    first = subprocess.run(cmd, capture_output=True, text=True)
    assert first.returncode == 1
    assert not output.exists()
    cmd.append("--acknowledge-private-uids")
    good = subprocess.run(cmd, capture_output=True, text=True)
    assert good.returncode == 0, good.stderr
    assert "U1" not in good.stdout
    assert "192.168." not in good.stdout
    data = json.loads(output.read_text(encoding="utf-8"))
    assert set(data["disagreements_by_uid"]) == {"U1", "U2"}
    assert data["disagreements_by_uid"]["U2"]["evidence_reference"] is None
    assert subprocess.run(cmd, capture_output=True).returncode == 1
    assert data == json.loads(output.read_text(encoding="utf-8"))


def test_cli_refuses_modified_inputs_and_repo_output(tmp_path):
    log, a, b = _inputs()
    cmd = _command(tmp_path, log, a, b)
    (tmp_path / "reviewer-b.json").write_bytes(b + b"\n")
    failed = subprocess.run(cmd, capture_output=True, text=True)
    assert failed.returncode == 1
    assert not (tmp_path / "disagreements.json").exists()
    (tmp_path / "reviewer-b.json").write_bytes(b)
    cmd[cmd.index("--output") + 1] = str(ROOT / "scripts" / "disagreements-should-not-exist.json")
    failed = subprocess.run(cmd, capture_output=True, text=True)
    assert failed.returncode == 1
    assert not (ROOT / "scripts" / "disagreements-should-not-exist.json").exists()


def test_cli_refuses_symlink_input(tmp_path):
    log, a, b = _inputs()
    cmd = _command(tmp_path, log, a, b)
    alias = tmp_path / "alias.json"
    try:
        alias.symlink_to(tmp_path / "reviewer-b.json")
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable")
    cmd[cmd.index("--annotation-b") + 1] = str(alias)
    assert subprocess.run(cmd, capture_output=True).returncode == 1
    assert not (tmp_path / "disagreements.json").exists()
