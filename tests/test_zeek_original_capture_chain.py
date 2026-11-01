"""Synthetic-only regression for original-source research trace verification."""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from evaluate_zeek_lab import run_offline_experiment
from verify_zeek_original_capture_chain import main, verify_original_capture_chain


@pytest.fixture(scope="module")
def originals(tmp_path_factory):
    folder = tmp_path_factory.mktemp("zeek-originals")
    entries = []
    for index, split in enumerate(("train", "validation", "test", "test")):
        raw = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
            "\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
            f"1630000000.25\tN{index}\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp"
            "\t-\t1.25\t100\t-\t2\t-\n"
            f"1630000001.0\tA{index}\t192.168.56.11\t52345\t192.168.56.21\t53\tudp"
            "\tdns\t-\t0\t25\t-\t1\n"
        ).encode()
        digest = hashlib.sha256(raw).hexdigest()
        log_name, labels_name = f"host{index}.log", f"host{index}-labels.json"
        (folder / log_name).write_bytes(raw)
        (folder / labels_name).write_text(json.dumps({
            "source_sha256": digest,
            "labels_by_uid": {f"N{index}": 0, f"A{index}": 1},
        }), encoding="utf-8")
        entries.append({
            "log_path": log_name, "labels_path": labels_name,
            "source_sha256": digest, "session_id": f"session{index}",
            "host_group": f"host{index}", "split": split,
            "label_method": "controlled_scenario_record",
            "label_reference": f"synthetic-note{index}",
        })
    manifest = folder / "manifest.json"
    manifest.write_text(json.dumps({
        "manifest_version": 1, "captures": entries,
    }), encoding="utf-8")
    report = run_offline_experiment(manifest, include_private_test_trace=True)
    trace = folder / "trace.json"
    trace.write_text(json.dumps(report, allow_nan=False), encoding="utf-8")
    return folder, manifest, trace, report


def _altered_trace(folder, report, tmp_path):
    path = folder / f"mutated-{tmp_path.name}.json"
    path.write_text(json.dumps(report, allow_nan=False), encoding="utf-8")
    return path


def test_verifies_all_four_original_sources_without_private_output(originals, capsys):
    folder, manifest, trace, _ = originals
    assert main(["--manifest", str(manifest), "--trace", str(trace)]) == 0
    out = capsys.readouterr().out
    summary = json.loads(out)
    assert summary["original_capture_sources_verified"] == 4
    assert summary["heldout_test_sources_verified"] == 2
    assert summary["heldout_test_flows_verified"] == 4
    assert summary["independent_ground_truth_verified"] is False
    assert "192.168." not in out and "N2" not in out
    assert str(folder) not in out


def test_opt_in_recomputes_model_predictions_from_all_originals(originals, capsys):
    _, manifest, trace, _ = originals
    result = verify_original_capture_chain(
        manifest, trace, recompute_model_predictions=True,
    )
    assert result["model_predictions_recomputed"] is True
    assert main([
        "--manifest", str(manifest), "--trace", str(trace),
        "--recompute-model-predictions",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["model_predictions_recomputed"] is True


def test_opt_in_rejects_forged_probability_even_when_verdict_is_unchanged(originals, tmp_path):
    folder, manifest, _, report = originals
    modified = copy.deepcopy(report)
    row = modified["private_test_trace"]["flows"][0]
    probability = row["attack_probability"]
    threshold = modified["selected_threshold"]
    if row["predicted_attack"]:
        replacement = 1.0 if probability < 0.999999 else threshold
    else:
        replacement = 0.0 if probability > 0.000001 else threshold / 2
    assert abs(replacement - probability) > 1e-8
    row["attack_probability"] = replacement
    altered = _altered_trace(folder, modified, tmp_path)
    # An internally consistent verdict is insufficient to prove that the
    # supplied probability came from the declared train-only research model.
    with pytest.raises(ValueError, match="recomputed model probabilities"):
        verify_original_capture_chain(
            manifest, altered, recompute_model_predictions=True,
        )


def test_opt_in_rejects_forged_validation_metric(originals, tmp_path):
    folder, manifest, _, report = originals
    modified = copy.deepcopy(report)
    modified["validation_metrics"]["precision"] = 0.123456
    with pytest.raises(ValueError, match="recomputed model metrics"):
        verify_original_capture_chain(
            manifest, _altered_trace(folder, modified, tmp_path),
            recompute_model_predictions=True,
        )


def test_refuses_edited_train_provenance_even_with_same_test_trace(originals, tmp_path):
    folder, manifest, _, report = originals
    modified = copy.deepcopy(report)
    modified["provenance"]["train"]["source_sha256"] = ["a" * 64]
    with pytest.raises(ValueError, match="split provenance"):
        verify_original_capture_chain(manifest, _altered_trace(folder, modified, tmp_path))


def test_refuses_test_label_forged_in_trace(originals, tmp_path):
    folder, manifest, _, report = originals
    modified = copy.deepcopy(report)
    modified["private_test_trace"]["flows"][0]["operator_supplied_label"] = 1
    with pytest.raises(ValueError, match="labels/UIDs"):
        verify_original_capture_chain(manifest, _altered_trace(folder, modified, tmp_path))


def test_refuses_missing_second_test_capture_rows(originals, tmp_path):
    folder, manifest, _, report = originals
    modified = copy.deepcopy(report)
    modified["private_test_trace"]["flows"] = modified["private_test_trace"]["flows"][:2]
    with pytest.raises(ValueError, match="labels/UIDs"):
        verify_original_capture_chain(manifest, _altered_trace(folder, modified, tmp_path))


def test_refuses_changed_manifest_digest(originals, tmp_path):
    folder, manifest, _, report = originals
    modified = copy.deepcopy(report)
    modified["input_manifest_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="manifest SHA-256"):
        verify_original_capture_chain(manifest, _altered_trace(folder, modified, tmp_path))


def test_refuses_tampered_original_log_before_any_report_success(originals, tmp_path):
    folder, _, _, _ = originals
    copied = tmp_path / "private"
    shutil.copytree(folder, copied)
    with (copied / "host0.log").open("ab") as stream:
        stream.write(b"#changed\n")
    with pytest.raises(ValueError, match="SHA-256"):
        verify_original_capture_chain(copied / "manifest.json", copied / "trace.json")


def test_opt_in_annotation_hash_pinning_rejects_legacy_manifest(originals):
    _, manifest, trace, _ = originals
    with pytest.raises(ValueError, match="labels_sha256"):
        verify_original_capture_chain(manifest, trace, require_label_sha256=True)


def test_trace_must_remain_in_private_manifest_directory(originals, tmp_path):
    _, manifest, trace, _ = originals
    outside = tmp_path / "trace.json"
    outside.write_bytes(trace.read_bytes())
    with pytest.raises(ValueError, match="within the manifest directory"):
        verify_original_capture_chain(manifest, outside)
