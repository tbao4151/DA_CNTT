"""Synthetic-only regression for optional Zeek originator-address split separation.

Address disjointness is a conservative heuristic, not proof of physical hosts,
authorized VMware isolation, independent labels or detection performance.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from blue_team_ai.originator_split import screen_originator_ip_disjoint_splits
from test_zeek_lab_cli import _lab_files

CLI = ROOT / "scripts" / "evaluate_zeek_lab.py"


def _run(manifest: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI), "--manifest", str(manifest), *args],
        capture_output=True, text=True, check=False,
    )


def _distinct_originators(tmp_path: Path) -> Path:
    """Retain a common responder but give each synthetic split distinct clients."""
    manifest = _lab_files(tmp_path / "private")
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    for index, entry in enumerate(spec["captures"]):
        log_path = manifest.parent / entry["log_path"]
        raw = log_path.read_bytes()
        raw = raw.replace(b"192.168.56.10", f"192.168.56.{10 + index * 10}".encode())
        raw = raw.replace(b"192.168.56.11", f"192.168.56.{11 + index * 10}".encode())
        log_path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        entry["source_sha256"] = digest
        label_path = manifest.parent / entry["labels_path"]
        annotation = json.loads(label_path.read_text(encoding="utf-8"))
        annotation["source_sha256"] = digest
        label_path.write_text(json.dumps(annotation), encoding="utf-8")
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    return manifest


def test_reused_originator_across_splits_refused_even_with_distinct_uids(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    # Legacy mode does not assert that operator-assigned host_group is an IP identity.
    assert _run(manifest, "--preflight").returncode == 0
    output = manifest.parent / "blocked.json"
    for mode in (("--preflight",), ("--output", str(output)),
                 ("--trace-output", str(output))):
        refused = _run(manifest, "--require-originator-ip-disjoint", *mode)
        assert refused.returncode == 1
        assert refused.stdout == ""
        assert not output.exists()
        for secret in ("192.168.56.", "private-operator-note", str(manifest)):
            assert secret not in refused.stderr


def test_distinct_clients_shared_responder_pass_preflight_and_scoring(tmp_path):
    manifest = _distinct_originators(tmp_path)
    source = [(manifest.parent / f"host-{i}.log").read_bytes() for i in range(3)]
    preflight = _run(manifest, "--require-originator-ip-disjoint", "--preflight")
    assert preflight.returncode == 0, preflight.stderr
    report = json.loads(preflight.stdout)
    screen = report["originator_ip_split_screen"]
    assert screen["screened_flows"] == 6
    assert screen["unique_originator_counts"] == {
        "train": 2, "validation": 2, "test": 2,
    }
    assert screen["shared_responder_addresses_allowed"] is True
    assert screen["host_identity_verified"] is False
    assert screen["label_truth_verified"] is False
    assert "originator_ip_split_screen" not in json.loads(
        _run(manifest, "--preflight").stdout
    )
    output = manifest.parent / "research.json"
    scored = _run(manifest, "--require-originator-ip-disjoint",
                  "--output", str(output))
    assert scored.returncode == 0, scored.stderr
    scored_report = json.loads(output.read_text(encoding="utf-8"))
    assert scored_report["originator_ip_split_screen"] == screen
    assert scored_report["automated_alerts"] is False
    assert scored_report["live_capture"] is False
    for private in ("192.168.56.", "private-operator-note", "N0", "A1"):
        assert private not in preflight.stdout
        assert private not in json.dumps(scored_report)
    assert source == [(manifest.parent / f"host-{i}.log").read_bytes() for i in range(3)]


def test_direct_screen_refuses_invalid_capture_contract():
    with pytest.raises(ValueError):
        screen_originator_ip_disjoint_splits("not captures")
    with pytest.raises(ValueError):
        screen_originator_ip_disjoint_splits([{"split": "training", "log_bytes": b""}])
    with pytest.raises(ValueError):
        screen_originator_ip_disjoint_splits([{"split": "train", "log_bytes": "not bytes"}])
