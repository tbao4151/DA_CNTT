"""Synthetic-only regression for the explicit offline Zeek input-gate bundle.

This checks CLI behavior, not VMware isolation or independently true labels.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_zeek_lab_cli import _lab_files

CLI = ROOT / "scripts" / "evaluate_zeek_lab.py"
CIDR = "192.168.56.0/24"


def _run(manifest: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI), "--manifest", str(manifest), *args],
        capture_output=True, text=True, check=False,
    )


def _strict_fixture(tmp_path: Path) -> Path:
    """Make non-overlapping synthetic sessions and pin every label file."""
    manifest = _lab_files(tmp_path / "private")
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    for index, entry in enumerate(spec["captures"]):
        log = manifest.parent / entry["log_path"]
        raw = log.read_bytes()
        raw = raw.replace(b"1630000000.25", f"{1630000000 + index * 100}.25".encode())
        raw = raw.replace(b"1630000001.0", f"{1630000001 + index * 100}.0".encode())
        log.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        entry["source_sha256"] = digest
        labels_path = manifest.parent / entry["labels_path"]
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        labels["source_sha256"] = digest
        labels_path.write_text(json.dumps(labels), encoding="utf-8")
        entry["labels_sha256"] = hashlib.sha256(labels_path.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    return manifest


def test_strict_bundle_matches_three_individual_gates_in_preflight_and_report(tmp_path):
    manifest = _strict_fixture(tmp_path)
    base = ["--cidr", CIDR]
    strict = _run(manifest, *base, "--strict-input-gates", "--preflight")
    individual = _run(
        manifest, *base, "--require-label-sha256",
        "--require-telemetry-quality", "--require-uid-independent-overlap", "--preflight",
    )
    assert strict.returncode == individual.returncode == 0, strict.stderr
    assert json.loads(strict.stdout) == json.loads(individual.stdout)
    preflight = json.loads(strict.stdout)
    assert preflight["all_annotation_sha256_pins_required"] is True
    assert preflight["telemetry_quality"]["screened_captures"] == 3
    assert preflight["uid_independent_overlap_screen"]["screened_flows"] == 6
    assert preflight["label_truth_verified"] is False
    assert preflight["host_only_isolation_verified"] is False

    target = manifest.parent / "strict-report.json"
    scored = _run(manifest, *base, "--strict-input-gates", "--output", str(target))
    assert scored.returncode == 0, scored.stderr
    report = json.loads(target.read_text(encoding="utf-8"))
    assert report["all_annotation_sha256_pins_required"] is True
    assert report["telemetry_quality"] == preflight["telemetry_quality"]
    assert report["uid_independent_overlap_screen"] == preflight["uid_independent_overlap_screen"]
    assert report["automated_alerts"] is False
    assert report["live_capture"] is False
    for private in ("192.168.56.", "private-operator-note", "host-train", "N0", "A1"):
        assert private not in json.dumps(report)
        assert private not in strict.stdout


def test_strict_bundle_fails_closed_without_cidr_or_complete_label_pins(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    target = manifest.parent / "refused.json"
    for flags in (
        ["--strict-input-gates"],
        ["--strict-input-gates", "--cidr", CIDR],
        ["--strict-input-gates", "--cidr", "10.0.0.0/24"],
    ):
        for mode in (["--preflight"], ["--output", str(target)]):
            proc = _run(manifest, *flags, *mode)
            assert proc.returncode != 0
            assert not proc.stdout
            assert not target.exists()
            assert str(manifest) not in proc.stderr
            assert "192.168.56." not in proc.stderr
    # Backwards-compatible legacy preflight is intentionally still available.
    assert _run(manifest, "--preflight").returncode == 0


def test_strict_bundle_rejects_cross_split_reuse_and_tampered_labels(tmp_path):
    manifest = _strict_fixture(tmp_path)
    target = manifest.parent / "refused.json"
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    # Restore the TRAIN timestamp pattern in TEST, preserving its different UIDs.
    test_entry = spec["captures"][2]
    log = manifest.parent / test_entry["log_path"]
    raw = log.read_bytes().replace(b"1630000200.25", b"1630000000.25")
    raw = raw.replace(b"1630000201.0", b"1630000001.0")
    log.write_bytes(raw)
    test_entry["source_sha256"] = hashlib.sha256(raw).hexdigest()
    labels_path = manifest.parent / test_entry["labels_path"]
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    labels["source_sha256"] = test_entry["source_sha256"]
    labels_path.write_text(json.dumps(labels), encoding="utf-8")
    test_entry["labels_sha256"] = hashlib.sha256(labels_path.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    for mode in (["--preflight"], ["--output", str(target)]):
        proc = _run(manifest, "--strict-input-gates", "--cidr", CIDR, *mode)
        assert proc.returncode == 1
        assert not target.exists()

    # Restore independent sessions, then mutate labels without re-pinning.
    manifest = _strict_fixture(tmp_path / "other")
    labels_path = manifest.parent / "host-1-labels.json"
    labels_path.write_bytes(labels_path.read_bytes() + b" ")
    target = manifest.parent / "tampered.json"
    for mode in (["--preflight"], ["--output", str(target)]):
        proc = _run(manifest, "--strict-input-gates", "--cidr", CIDR, *mode)
        assert proc.returncode == 1
        assert not target.exists()
