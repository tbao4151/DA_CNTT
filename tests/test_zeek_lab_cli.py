"""Synthetic-only offline manifest CLI tests; NOT lab attack-detection results."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from evaluate_zeek_lab import load_experiment_manifest, run_offline_experiment


def _lab_files(root):
    root.mkdir(parents=True, exist_ok=True)
    captures = []
    for index, split in enumerate(("train", "validation", "test")):
        raw = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
            "\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
            f"1630000000.25\tN{index}\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp"
            "\t-\t1.25\t100\t-\t2\t-\n"
            f"1630000001.0\tA{index}\t192.168.56.11\t52345\t192.168.56.21\t53\tudp"
            "\tdns\t-\t0\t25\t-\t1\n"
        ).encode()
        log_name, label_name = f"host-{index}.log", f"host-{index}-labels.json"
        (root / log_name).write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        (root / label_name).write_text(json.dumps({
            "source_sha256": digest, "labels_by_uid": {f"N{index}": 0, f"A{index}": 1},
        }), encoding="utf-8")
        captures.append({
            "log_path": log_name, "labels_path": label_name,
            "source_sha256": digest, "session_id": f"session-{index}",
            "host_group": f"host-{split}", "split": split,
            "label_method": "controlled_scenario_record",
            "label_reference": f"private-operator-note-{index}",
        })
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"manifest_version": 1, "captures": captures}), encoding="utf-8")
    return manifest


def test_real_cli_execution_on_synthetic_fixture(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    output = manifest.parent / "report.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["mode"] == "offline_labeled_zeek_research_only"
    assert report["test_metrics"]["support"] == 2
    assert report["input_manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert report["automated_alerts"] is False
    assert report["live_capture"] is False
    serialized = json.dumps(report)
    for forbidden in ("192.168.56.", "private-operator-note", "N0", "A0"):
        assert forbidden not in serialized
    again = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert again.returncode == 1
    assert "refusing overwrite" not in again.stderr
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_input_sha_mismatch_fails_before_model_fit(tmp_path):
    manifest = _lab_files(tmp_path)
    (tmp_path / "host-0.log").write_bytes((tmp_path / "host-0.log").read_bytes() + b"#tampered\n")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_experiment_manifest(manifest)


def test_annotation_digest_must_match_capture(tmp_path):
    manifest = _lab_files(tmp_path)
    path = tmp_path / "host-1-labels.json"
    labels = json.loads(path.read_text(encoding="utf-8"))
    labels["source_sha256"] = "0" * 64
    path.write_text(json.dumps(labels), encoding="utf-8")
    with pytest.raises(ValueError, match="Annotation source SHA-256 mismatch"):
        load_experiment_manifest(manifest)


def test_duplicate_annotation_json_keys_fail_closed(tmp_path):
    manifest = _lab_files(tmp_path)
    path = tmp_path / "host-1-labels.json"
    labels = json.loads(path.read_text(encoding="utf-8"))
    path.write_text('{"source_sha256":"' + labels["source_sha256"] + '",'
                    '"labels_by_uid":{"N1":0,"N1":1,"A1":1}}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        load_experiment_manifest(manifest)


def test_cross_split_host_reuse_rejected(tmp_path):
    manifest = _lab_files(tmp_path)
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    spec["captures"][1]["host_group"] = spec["captures"][0]["host_group"]
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(ValueError, match="Host group leaked"):
        run_offline_experiment(manifest)


def test_missing_labels_refused(tmp_path):
    manifest = _lab_files(tmp_path)
    label_path = tmp_path / "host-0-labels.json"
    labels = json.loads(label_path.read_text(encoding="utf-8"))
    del labels["labels_by_uid"]["A0"]
    label_path.write_text(json.dumps(labels), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly match"):
        run_offline_experiment(manifest)


def test_path_escape_refused(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    spec["captures"][0]["log_path"] = "../elsewhere.log"
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(ValueError, match="traversal"):
        load_experiment_manifest(manifest)


def test_oversized_manifest_and_extra_fields_rejected(tmp_path):
    manifest = _lab_files(tmp_path)
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    spec["captures"][0]["attack_cat"] = "fake"
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(ValueError, match="Unexpected capture"):
        load_experiment_manifest(manifest)
    manifest.write_bytes(b" " * (256 * 1024 + 1))
    with pytest.raises(ValueError, match="size limit"):
        load_experiment_manifest(manifest)


def test_report_output_outside_private_manifest_folder_is_refused(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    output = tmp_path / "public-report.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert not output.exists()
