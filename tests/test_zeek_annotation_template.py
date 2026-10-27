"""Synthetic-only annotation helper tests, not measured attack detection."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from prepare_zeek_annotations import prepare_template, verify_annotations


def _log(tmp_path, *, duplicate=False):
    rows = [
        "1630000000.25\tC-normal\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp",
        "1630000001.0\tC-normal" if duplicate else "1630000001.0\tC-scenario",
    ]
    rows[1] += "\t192.168.56.11\t52345\t192.168.56.21\t53\tudp"
    raw = ("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
           + "\n".join(rows) + "\n").encode("utf-8")
    path = tmp_path / "conn.log"
    path.write_bytes(raw)
    return path, raw


def test_template_never_invents_labels_and_matches_exact_source(tmp_path):
    log, raw = _log(tmp_path)
    target = tmp_path / "labels.json"
    assert prepare_template(log, target) == 2
    result = json.loads(target.read_text(encoding="utf-8"))
    assert result == {
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "labels_by_uid": {"C-normal": None, "C-scenario": None},
    }
    assert "192.168.56." not in target.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="binary"):
        verify_annotations(log, target)
    result["labels_by_uid"] = {"C-normal": 0, "C-scenario": 1}
    target.write_text(json.dumps(result), encoding="utf-8")
    assert verify_annotations(log, target) == 2
    with pytest.raises(FileExistsError):
        prepare_template(log, target)


def test_verification_rejects_changed_log_or_omitted_uid(tmp_path):
    log, _ = _log(tmp_path)
    labels = tmp_path / "labels.json"
    prepare_template(log, labels)
    spec = json.loads(labels.read_text())
    spec["labels_by_uid"] = {"C-normal": 0}
    labels.write_text(json.dumps(spec))
    with pytest.raises(ValueError, match="exactly"):
        verify_annotations(log, labels)
    spec["labels_by_uid"]["C-scenario"] = 1
    spec["source_sha256"] = "0" * 64
    labels.write_text(json.dumps(spec))
    with pytest.raises(ValueError, match="does not match"):
        verify_annotations(log, labels)


@pytest.mark.parametrize("value", [None, True, "1", 2, -1, 1.0])
def test_verification_refuses_unverified_or_nonbinary_labels(tmp_path, value):
    log, _ = _log(tmp_path)
    labels = tmp_path / "labels.json"
    prepare_template(log, labels)
    spec = json.loads(labels.read_text())
    spec["labels_by_uid"] = {"C-normal": 0, "C-scenario": value}
    labels.write_text(json.dumps(spec))
    with pytest.raises(ValueError, match="binary"):
        verify_annotations(log, labels)


def test_duplicate_uids_and_duplicate_json_keys_fail_closed(tmp_path):
    log, _ = _log(tmp_path, duplicate=True)
    with pytest.raises(ValueError, match="Duplicate Zeek UIDs"):
        prepare_template(log, tmp_path / "labels.json")
    log, raw = _log(tmp_path)
    labels = tmp_path / "labels.json"
    labels.write_text(
        '{"source_sha256":"' + hashlib.sha256(raw).hexdigest()
        + '","labels_by_uid":{"C-normal":0,"C-normal":1,"C-scenario":1}}'
    )
    with pytest.raises(ValueError, match="Duplicate annotation"):
        verify_annotations(log, labels)


def test_oversized_annotation_and_bad_schema_rejected(tmp_path):
    log, _ = _log(tmp_path)
    labels = tmp_path / "labels.json"
    labels.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="size limit"):
        verify_annotations(log, labels)
    labels.write_text('{"labels_by_uid":{}}')
    with pytest.raises(ValueError, match="exact annotation"):
        verify_annotations(log, labels)


def test_cli_rejects_repo_output_and_never_overwrites(tmp_path):
    log, _ = _log(tmp_path)
    forbidden = ROOT / "scripts" / "private-annotation-should-not-exist.json"
    with pytest.raises(ValueError, match="outside the repository"):
        prepare_template(log, forbidden)
    assert not forbidden.exists()
    labels = tmp_path / "labels.json"
    cmd = [sys.executable, str(ROOT / "scripts" / "prepare_zeek_annotations.py"),
           "--log", str(log), "--output", str(labels)]
    first = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert first.returncode == 0, first.stderr
    second = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert second.returncode == 1
    assert "C-normal" not in second.stderr
    assert "192.168" not in second.stderr
    assert labels.exists()
    check = subprocess.run([sys.executable, str(ROOT / "scripts" / "prepare_zeek_annotations.py"),
                            "--log", str(log), "--verify-labels", str(labels)],
                           capture_output=True, text=True, check=False)
    assert check.returncode == 1  # null labels never count as completed annotations


def test_changed_source_bytes_invalidate_existing_annotations(tmp_path):
    log, _ = _log(tmp_path)
    labels = tmp_path / "labels.json"
    prepare_template(log, labels)
    spec = json.loads(labels.read_text())
    spec["labels_by_uid"] = {"C-normal": 0, "C-scenario": 1}
    labels.write_text(json.dumps(spec))
    log.write_bytes(log.read_bytes() + b"#added-comment\n")
    with pytest.raises(ValueError, match="does not match"):
        verify_annotations(log, labels)
