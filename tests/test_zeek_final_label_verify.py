"""Synthetic-only tests for read-only final annotation chain verification."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.adjudicated_labels import finalize_private_adjudication
from blue_team_ai.disagreement_review import build_private_disagreement_template
from blue_team_ai.final_label_verify import verify_finalized_annotation_chain


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fixture():
    rows = [
        f"163000000{i}.0\tU{i}\t192.168.56.10\t5234{i}\t192.168.56.20\t443\ttcp"
        for i in range(4)
    ]
    log = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        + "\n".join(rows) + "\n"
    ).encode()
    a = json.dumps({"source_sha256": sha(log), "labels_by_uid": {
        "U0": 0, "U1": 1, "U2": 0, "U3": 1,
    }}).encode()
    b = json.dumps({"source_sha256": sha(log), "labels_by_uid": {
        "U0": 0, "U1": 0, "U2": 1, "U3": 1,
    }}).encode()
    worksheet = build_private_disagreement_template(
        log, a, b, expected_log_sha256=sha(log),
        expected_a_sha256=sha(a), expected_b_sha256=sha(b),
    )
    for uid, label in (("U1", 1), ("U2", 0)):
        worksheet["disagreements_by_uid"][uid]["adjudicated_label"] = label
        worksheet["disagreements_by_uid"][uid]["evidence_reference"] = "private-lab-notebook/1"
    ws = json.dumps(worksheet).encode()
    final = finalize_private_adjudication(
        log, a, b, ws, expected_log_sha256=sha(log),
        expected_a_sha256=sha(a), expected_b_sha256=sha(b),
        expected_worksheet_sha256=sha(ws),
    )
    return log, a, b, ws, json.dumps(final).encode()


def verify(files, **overrides):
    log, a, b, ws, final = files
    args = {
        "expected_log_sha256": sha(log), "expected_a_sha256": sha(a),
        "expected_b_sha256": sha(b), "expected_worksheet_sha256": sha(ws),
        "expected_final_sha256": sha(final),
    }
    args.update(overrides)
    return verify_finalized_annotation_chain(*files, **args)


def test_valid_chain_is_aggregate_only():
    result = verify(fixture())
    assert result["chain_consistency_verified"] is True
    assert result["flow_count"] == 4
    assert result["normal_count"] == 2
    assert result["attack_count"] == 2
    assert result["ground_truth_verified"] is False
    assert result["annotator_independence_verified"] is False
    assert "U1" not in json.dumps(result)
    assert "192.168" not in json.dumps(result)


@pytest.mark.parametrize("index", range(5))
def test_each_original_requires_independently_pinned_sha(index):
    files = list(fixture())
    files[index] += b" "
    original = fixture()
    pinned = ["expected_log_sha256", "expected_a_sha256",
              "expected_b_sha256", "expected_worksheet_sha256",
              "expected_final_sha256"]
    with pytest.raises(ValueError, match="SHA-256"):
        verify(tuple(files), **{pinned[index]: sha(original[index])})


@pytest.mark.parametrize("uid, value", [("U1", 0), ("U0", 1), ("U2", True)])
def test_re_pinned_but_changed_final_label_rejected(uid, value):
    files = list(fixture())
    final = json.loads(files[4])
    final["labels_by_uid"][uid] = value
    files[4] = json.dumps(final).encode()
    with pytest.raises(ValueError, match="differs|binary"):
        verify(tuple(files))


def test_re_pinned_but_incomplete_final_rejected():
    files = list(fixture())
    final = json.loads(files[4])
    del final["labels_by_uid"]["U2"]
    files[4] = json.dumps(final).encode()
    with pytest.raises(ValueError, match="coverage"):
        verify(tuple(files))


def test_re_pinned_duplicate_json_key_rejected():
    files = list(fixture())
    final = json.loads(files[4])
    files[4] = ('{"source_sha256":"bad","source_sha256":'
                + json.dumps(final["source_sha256"])
                + ',"labels_by_uid":'
                + json.dumps(final["labels_by_uid"]) + '}').encode()
    with pytest.raises(ValueError, match="Duplicate"):
        verify(tuple(files))


def test_unresolved_worksheet_rejected_even_if_hash_re_pinned():
    files = list(fixture())
    ws = json.loads(files[3])
    ws["disagreements_by_uid"]["U1"]["adjudicated_label"] = None
    files[3] = json.dumps(ws).encode()
    with pytest.raises(ValueError, match="manual binary"):
        verify(tuple(files))


def test_cli_read_only_and_no_uid_in_stdout(tmp_path):
    files = fixture()
    names = ("conn.log", "a.json", "b.json", "worksheet.json", "final.json")
    paths = []
    for name, raw in zip(names, files):
        path = tmp_path / name
        path.write_bytes(raw)
        paths.append(path)
    cmd = [sys.executable, str(ROOT / "scripts" / "verify_zeek_final_labels.py")]
    for flag, path in zip(
        ("--log", "--annotation-a", "--annotation-b",
         "--worksheet", "--final-annotation"), paths
    ):
        cmd.extend([flag, str(path)])
    for flag, raw in zip(
        ("--expected-log-sha256", "--expected-a-sha256",
         "--expected-b-sha256", "--expected-worksheet-sha256",
         "--expected-final-sha256"), files
    ):
        cmd.extend([flag, sha(raw)])
    success = subprocess.run(cmd, capture_output=True, text=True)
    assert success.returncode == 0, success.stderr
    result = json.loads(success.stdout)
    assert result["flow_count"] == 4
    assert "U1" not in success.stdout and "192.168" not in success.stdout
    assert [path.read_bytes() for path in paths] == list(files)
    paths[-1].write_bytes(files[-1] + b"\n")
    refused = subprocess.run(cmd, capture_output=True, text=True)
    assert refused.returncode == 1
    assert "U1" not in refused.stderr
    assert "192.168" not in refused.stderr


def test_cli_rejects_repo_input_and_aliases(tmp_path):
    files = fixture()
    names = ("conn.log", "a.json", "b.json", "ws.json", "final.json")
    paths = []
    for name, raw in zip(names, files):
        path = tmp_path / name
        path.write_bytes(raw)
        paths.append(path)
    base = [sys.executable, str(ROOT / "scripts" / "verify_zeek_final_labels.py")]
    for flag, path in zip(
        ("--log", "--annotation-a", "--annotation-b",
         "--worksheet", "--final-annotation"), paths
    ):
        base.extend([flag, str(path)])
    for flag, raw in zip(
        ("--expected-log-sha256", "--expected-a-sha256",
         "--expected-b-sha256", "--expected-worksheet-sha256",
         "--expected-final-sha256"), files
    ):
        base.extend([flag, sha(raw)])
    alias = base.copy()
    alias[alias.index("--final-annotation") + 1] = str(paths[1])
    assert subprocess.run(alias, capture_output=True).returncode == 1
    inside_repo = base.copy()
    inside_repo[inside_repo.index("--final-annotation") + 1] = str(
        ROOT / "docs" / "ZEEK_PRIVATE_ADJUDICATION_FINALIZATION.md"
    )
    assert subprocess.run(inside_repo, capture_output=True).returncode == 1
