"""Synthetic-only adjudication regression; no genuine lab attack labels."""
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


def _fixture():
    rows = [
        f"163000000{i}.0\tU{i}\t192.168.56.10\t5234{i}\t192.168.56.20\t443\ttcp"
        for i in range(4)
    ]
    log = ("#separator \\x09\n"
           "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
           + "\n".join(rows) + "\n").encode()
    sha = hashlib.sha256(log).hexdigest()
    a = json.dumps({"source_sha256": sha, "labels_by_uid":
                    {"U0": 0, "U1": 1, "U2": 0, "U3": 1}}).encode()
    b = json.dumps({"source_sha256": sha, "labels_by_uid":
                    {"U0": 0, "U1": 0, "U2": 1, "U3": 1}}).encode()
    return log, a, b


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _worksheet(log, a, b, *, completed=True):
    template = build_private_disagreement_template(
        log, a, b,
        expected_log_sha256=_hash(log),
        expected_a_sha256=_hash(a),
        expected_b_sha256=_hash(b),
    )
    if completed:
        for uid, label in (("U1", 1), ("U2", 0)):
            template["disagreements_by_uid"][uid]["adjudicated_label"] = label
            template["disagreements_by_uid"][uid]["evidence_reference"] = "private-notebook/session-1"
    return template


def _finalize(log, a, b, worksheet, **overrides):
    raw = json.dumps(worksheet, ensure_ascii=False).encode() if isinstance(worksheet, dict) else worksheet
    kw = {
        "expected_log_sha256": _hash(log),
        "expected_a_sha256": _hash(a),
        "expected_b_sha256": _hash(b),
        "expected_worksheet_sha256": _hash(raw),
    }
    kw.update(overrides)
    return finalize_private_adjudication(log, a, b, raw, **kw)


def test_complete_manual_decisions_emit_only_annotation_v1():
    log, a, b = _fixture()
    result = _finalize(log, a, b, _worksheet(log, a, b))
    assert result == {
        "source_sha256": _hash(log),
        "labels_by_uid": {"U0": 0, "U1": 1, "U2": 0, "U3": 1},
    }
    assert "evidence_reference" not in json.dumps(result)
    assert "ground_truth_verified" not in result


@pytest.mark.parametrize("bad", [None, True, "1", 2])
def test_unresolved_or_nonbinary_decision_refused(bad):
    log, a, b = _fixture()
    worksheet = _worksheet(log, a, b)
    worksheet["disagreements_by_uid"]["U1"]["adjudicated_label"] = bad
    with pytest.raises(ValueError, match="manual binary"):
        _finalize(log, a, b, worksheet)


@pytest.mark.parametrize("bad", [None, "", " ", "notebook\nother", "x" * 513])
def test_missing_or_invalid_evidence_ref_refused(bad):
    log, a, b = _fixture()
    worksheet = _worksheet(log, a, b)
    worksheet["disagreements_by_uid"]["U2"]["evidence_reference"] = bad
    with pytest.raises(ValueError, match="evidence reference"):
        _finalize(log, a, b, worksheet)


@pytest.mark.parametrize("tamper", ["reviewer", "uid", "mode", "safety", "extra"])
def test_tampered_template_or_reviewer_label_refused(tamper):
    log, a, b = _fixture()
    worksheet = _worksheet(log, a, b)
    if tamper == "reviewer":
        worksheet["disagreements_by_uid"]["U1"]["reviewer_a_label"] = 0
    elif tamper == "uid":
        worksheet["disagreements_by_uid"]["invented"] = worksheet["disagreements_by_uid"].pop("U1")
    elif tamper == "mode":
        worksheet["mode"] = "trusted_ground_truth"
    elif tamper == "safety":
        worksheet["ground_truth_verified"] = True
    else:
        worksheet["new_key"] = "unexpected"
    with pytest.raises(ValueError):
        _finalize(log, a, b, worksheet)


def test_stale_hash_and_duplicate_keys_fail_closed():
    log, a, b = _fixture()
    worksheet = _worksheet(log, a, b)
    with pytest.raises(ValueError, match="SHA-256"):
        _finalize(log, a, b, worksheet, expected_worksheet_sha256="0" * 64)
    raw = json.dumps(worksheet)
    duplicate = ('{"report_version":1,' + raw[1:]).encode()
    with pytest.raises(ValueError, match="Duplicate"):
        _finalize(log, a, b, duplicate)


def test_unresolved_worksheet_does_not_create_labels():
    log, a, b = _fixture()
    with pytest.raises(ValueError, match="manual binary"):
        _finalize(log, a, b, _worksheet(log, a, b, completed=False))


def test_cli_private_exclusive_output_and_no_uid_stdout(tmp_path):
    log, a, b = _fixture()
    ws = json.dumps(_worksheet(log, a, b)).encode()
    paths = {}
    for name, raw in (("conn.log", log), ("reviewer-a.json", a),
                      ("reviewer-b.json", b), ("worksheet.json", ws)):
        path = tmp_path / name
        path.write_bytes(raw)
        paths[name] = path
    out = tmp_path / "adjudicated-v2.json"
    cmd = [
        sys.executable, str(ROOT / "scripts" / "finalize_zeek_adjudication.py"),
        "--log", str(paths["conn.log"]),
        "--annotation-a", str(paths["reviewer-a.json"]),
        "--annotation-b", str(paths["reviewer-b.json"]),
        "--worksheet", str(paths["worksheet.json"]),
        "--expected-log-sha256", _hash(log),
        "--expected-a-sha256", _hash(a),
        "--expected-b-sha256", _hash(b),
        "--expected-worksheet-sha256", _hash(ws),
        "--output", str(out),
    ]
    refused = subprocess.run(cmd, capture_output=True, text=True)
    assert refused.returncode == 1 and not out.exists()
    cmd.append("--confirm-manual-evidence-review")
    good = subprocess.run(cmd, capture_output=True, text=True)
    assert good.returncode == 0, good.stderr
    assert json.loads(out.read_text())["labels_by_uid"]["U1"] == 1
    assert "U1" not in good.stdout and "192.168." not in good.stdout
    assert subprocess.run(cmd, capture_output=True).returncode == 1
    assert paths["reviewer-a.json"].read_bytes() == a


def test_cli_rejects_modified_worksheet_and_repo_output(tmp_path):
    log, a, b = _fixture()
    ws = json.dumps(_worksheet(log, a, b)).encode()
    files = []
    for name, raw in (("conn.log", log), ("a.json", a), ("b.json", b), ("ws.json", ws)):
        p = tmp_path / name
        p.write_bytes(raw)
        files.append(p)
    out = tmp_path / "labels-v2.json"
    cmd = [
        sys.executable, str(ROOT / "scripts" / "finalize_zeek_adjudication.py"),
        "--log", str(files[0]), "--annotation-a", str(files[1]),
        "--annotation-b", str(files[2]), "--worksheet", str(files[3]),
        "--expected-log-sha256", _hash(log),
        "--expected-a-sha256", _hash(a), "--expected-b-sha256", _hash(b),
        "--expected-worksheet-sha256", _hash(ws),
        "--output", str(out), "--confirm-manual-evidence-review",
    ]
    files[3].write_bytes(ws + b"\n")
    assert subprocess.run(cmd, capture_output=True).returncode == 1
    assert not out.exists()
    files[3].write_bytes(ws)
    cmd[cmd.index("--output") + 1] = str(ROOT / "scripts" / "private-should-not-exist.json")
    assert subprocess.run(cmd, capture_output=True).returncode == 1
    assert not (ROOT / "scripts" / "private-should-not-exist.json").exists()
