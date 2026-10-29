"""Synthetic-only tests for optional pinned partition checks in manual SOC triage."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.new_log_inference import score_new_zeek_log
from blue_team_ai.new_log_triage import create_new_log_candidate_case
from siem_ai.core import list_cases
from test_zeek_partition_guard import _inputs

CIDR = "192.168.56.0/24"


def _setup(tmp_path):
    manifest, dataset, model, new_log = _inputs(tmp_path)
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    for capture in spec["captures"]:
        labels = manifest.parent / capture["labels_path"]
        capture["labels_sha256"] = hashlib.sha256(labels.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    model["input_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    # Synthetic-only threshold for deterministic candidate coverage, NOT a
    # scientifically selected operational threshold.
    model["selected_threshold"] = 0.000001
    model_path = manifest.parent / "model-for-triage.json"
    model_path.write_text(json.dumps(model, allow_nan=False), encoding="utf-8")
    model_sha = hashlib.sha256(model_path.read_bytes()).hexdigest()
    source_sha = hashlib.sha256(new_log.read_bytes()).hexdigest()
    report = score_new_zeek_log(
        new_log.read_bytes(), model, expected_log_sha256=source_sha,
        lab_cidrs=[CIDR], model_sha256=model_sha,
    )
    report_path = manifest.parent / "new-predictions.json"
    report_path.write_text(json.dumps(report, allow_nan=False), encoding="utf-8")
    index = next(i for i, row in enumerate(report["predictions"])
                 if row["research_candidate"] is True)
    command = [
        sys.executable, str(ROOT / "scripts" / "triage_zeek_new_log.py"),
        "--model", str(model_path), "--expected-model-sha256", model_sha,
        "--log", str(new_log), "--expected-log-sha256", source_sha,
        "--report", str(report_path), "--cidr", CIDR,
    ]
    pinned = [
        "--manifest", str(manifest),
        "--expected-manifest-sha256", hashlib.sha256(manifest.read_bytes()).hexdigest(),
    ]
    return manifest, dataset, model, new_log, report, index, command, pinned


def _run(command):
    return subprocess.run(command, capture_output=True, text=True, check=False)


def test_pinned_listing_and_manual_case_with_audit(tmp_path):
    manifest, _, _, _, _, index, base, pinned = _setup(tmp_path)
    private = manifest.parent
    before = {p.name: p.read_bytes() for p in private.iterdir() if p.is_file()}
    listing = _run(base + pinned + ["--list-candidates"])
    assert listing.returncode == 0, listing.stderr
    assert "exact-byte non-reuse checked" in listing.stdout
    assert before == {p.name: p.read_bytes() for p in private.iterdir() if p.is_file()}
    db = private / "cases.sqlite3"
    write = base + pinned + [
        "--record-index", str(index), "--db", str(db),
        "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture",
    ]
    accepted = _run(write)
    assert accepted.returncode == 0, accepted.stderr
    note = list_cases(db).iloc[0]["analyst_note"]
    assert "Declared exact-byte TRAIN/VALIDATION/TEST exclusion checked" in note
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() in note
    assert "historical completeness and semantic flow non-reuse unverified" in note
    assert len(list_cases(db)) == 1
    assert _run(write).returncode == 0
    assert len(list_cases(db)) == 1


def test_declared_test_capture_reuse_rejected_before_any_soc_write(tmp_path):
    manifest, _, model, new_log, _, index, base, pinned = _setup(tmp_path)
    # The scorer by itself does not check reserved TEST; generate a fully
    # internally consistent report for TEST bytes to test this extra gate.
    new_log.write_bytes((manifest.parent / "host-2.log").read_bytes())
    source_sha = hashlib.sha256(new_log.read_bytes()).hexdigest()
    model_sha = base[base.index("--expected-model-sha256") + 1]
    report = score_new_zeek_log(
        new_log.read_bytes(), model, expected_log_sha256=source_sha,
        lab_cidrs=[CIDR], model_sha256=model_sha,
    )
    (manifest.parent / "new-predictions.json").write_text(
        json.dumps(report, allow_nan=False), encoding="utf-8",
    )
    changed = base.copy()
    changed[changed.index("--expected-log-sha256") + 1] = source_sha
    db = manifest.parent / "cases.sqlite3"
    for action in (
        ["--list-candidates"],
        ["--record-index", str(index), "--db", str(db),
         "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture"],
    ):
        refused = _run(changed + pinned + action)
        assert refused.returncode == 1
        assert not db.exists()
        assert "192.168" not in refused.stderr


@pytest.mark.parametrize("change", ["missing_pin", "missing_manifest", "wrong_pin"])
def test_bad_or_partial_manifest_pin_fails_closed(tmp_path, change):
    manifest, _, _, _, _, index, base, pinned = _setup(tmp_path)
    if change == "missing_pin":
        extra = pinned[:2]
    elif change == "missing_manifest":
        extra = pinned[2:]
    else:
        extra = pinned.copy()
        extra[-1] = "0" * 64
    db = manifest.parent / "cases.sqlite3"
    cmd = base + extra + [
        "--record-index", str(index), "--db", str(db),
        "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture",
    ]
    refused = _run(cmd)
    assert refused.returncode == 1
    assert not db.exists()
    assert str(manifest) not in refused.stderr


def test_direct_case_api_rechecks_declared_partition_evidence(tmp_path):
    manifest, dataset, model, new_log, report, index, base, _ = _setup(tmp_path)
    db = manifest.parent / "cases.sqlite3"
    with pytest.raises(ValueError, match="different experiment manifest"):
        create_new_log_candidate_case(
            db, source_data=new_log.read_bytes(), model=model,
            report_data=json.dumps(report).encode("utf-8"),
            expected_log_sha256=hashlib.sha256(new_log.read_bytes()).hexdigest(),
            model_sha256=base[base.index("--expected-model-sha256") + 1],
            lab_cidrs=[CIDR], record_index=index,
            analyst_confirmed=True, operator_confirmed_authorized=True,
            operator_confirmed_new_capture=True,
            declared_dataset=dataset, declared_manifest_sha256="f" * 64,
        )
    assert not db.exists()

@pytest.mark.parametrize("change", ["annotation_modified", "missing_annotation_pin"])
def test_cli_soc_refuses_unpinned_or_changed_annotation_before_write(tmp_path, change):
    manifest, _, _, _, _, index, base, pinned = _setup(tmp_path)
    if change == "annotation_modified":
        labels = manifest.parent / "host-0-labels.json"
        labels.write_bytes(labels.read_bytes() + b"\n")
    else:
        spec = json.loads(manifest.read_text(encoding="utf-8"))
        del spec["captures"][0]["labels_sha256"]
        manifest.write_text(json.dumps(spec), encoding="utf-8")
        model_path = Path(base[base.index("--model") + 1])
        model = json.loads(model_path.read_text(encoding="utf-8"))
        model["input_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        model_path.write_text(json.dumps(model), encoding="utf-8")
        base[base.index("--expected-model-sha256") + 1] = hashlib.sha256(
            model_path.read_bytes()
        ).hexdigest()
        pinned[-1] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    db = manifest.parent / "cases.sqlite3"
    for action in (
        ["--list-candidates"],
        ["--record-index", str(index), "--db", str(db),
         "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture"],
    ):
        refused = _run(base + pinned + action)
        assert refused.returncode == 1
        assert not db.exists()
        assert str(manifest) not in refused.stderr
        assert "192.168.56" not in refused.stderr
