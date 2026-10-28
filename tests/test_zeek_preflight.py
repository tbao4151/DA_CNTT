"""Synthetic-only Zeek preflight tests: no VMware or real detection evidence."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from evaluate_zeek_lab import inspect_offline_experiment


def _private_manifest(folder: Path) -> Path:
    folder.mkdir(parents=True)
    entries = []
    for i, split in enumerate(("train", "validation", "test")):
        raw = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            f"1630000000.25\tN{i}\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp\n"
            f"1630000001.0\tA{i}\t192.168.56.11\t52345\t192.168.56.21\t53\tudp\n"
        ).encode("utf-8")
        log = f"capture-{i}.log"
        annotation = f"labels-{i}.json"
        (folder / log).write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        (folder / annotation).write_text(json.dumps({
            "source_sha256": digest, "labels_by_uid": {f"N{i}": 0, f"A{i}": 1},
        }), encoding="utf-8")
        entries.append({
            "log_path": log,
            "labels_path": annotation,
            "source_sha256": digest,
            "session_id": f"session-{i}",
            "host_group": f"host-{i}",
            "split": split,
            "label_method": "controlled_scenario_record",
            "label_reference": f"private-evidence-{i}",
        })
    manifest = folder / "manifest.json"
    manifest.write_text(json.dumps({"manifest_version": 1, "captures": entries}), encoding="utf-8")
    return manifest


def test_preflight_validates_and_returns_only_aggregate_counts(tmp_path, monkeypatch):
    manifest = _private_manifest(tmp_path / "private")
    import evaluate_zeek_lab as cli
    monkeypatch.setattr(cli, "evaluate_offline_zeek_baseline",
                        lambda *_args: pytest.fail("Preflight must not fit or score a model"))
    report = inspect_offline_experiment(manifest)
    assert report["mode"] == "offline_zeek_structural_preflight_only"
    assert report["input_manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert report["capture_count"] == 3
    assert report["structural_validation_passed"] is True
    for field in ("label_truth_verified", "host_only_isolation_verified", "model_fitted", "test_scored"):
        assert report[field] is False
    assert report["partitions"]["test"] == {
        "flows": 2, "normal": 1, "attack": 1, "host_groups": 1, "sessions": 1,
    }
    assert report["warnings"]
    serialized = json.dumps(report)
    for private in ("192.168.", "private-evidence", "host-0", "session-0", "N0", "A0", str(tmp_path)):
        assert private not in serialized


def test_cli_preflight_does_not_write_any_output_file(tmp_path):
    manifest = _private_manifest(tmp_path / "private")
    before = {p.name: p.read_bytes() for p in manifest.parent.iterdir()}
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--preflight",
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["partitions"]["train"]["flows"] == 2
    assert {p.name: p.read_bytes() for p in manifest.parent.iterdir()} == before


def test_preflight_refuses_missing_labels_and_never_fabricates_metrics(tmp_path):
    manifest = _private_manifest(tmp_path / "private")
    label = manifest.parent / "labels-1.json"
    data = json.loads(label.read_text(encoding="utf-8"))
    del data["labels_by_uid"]["A1"]
    label.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly match"):
        inspect_offline_experiment(manifest)
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--preflight",
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "A1" not in proc.stderr


def test_preflight_refuses_cross_split_host_reuse(tmp_path):
    manifest = _private_manifest(tmp_path / "private")
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    spec["captures"][2]["host_group"] = spec["captures"][0]["host_group"]
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(ValueError, match="Host group leaked"):
        inspect_offline_experiment(manifest)


def test_cli_requires_exactly_one_mode(tmp_path):
    manifest = _private_manifest(tmp_path / "private")
    base = [sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
            "--manifest", str(manifest)]
    for extra in ([], ["--preflight", "--output", str(manifest.parent / "report.json")]):
        proc = subprocess.run(base + extra, capture_output=True, text=True, check=False)
        assert proc.returncode != 0
    assert not (manifest.parent / "report.json").exists()
