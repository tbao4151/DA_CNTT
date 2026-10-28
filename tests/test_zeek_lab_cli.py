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


def test_declared_cidr_gate_applies_to_all_captures_and_hides_private_endpoints(tmp_path):
    """A passing screen means only declared address membership, not isolation."""
    from evaluate_zeek_lab import inspect_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    result = inspect_offline_experiment(manifest, lab_cidrs=["192.168.56.0/24"])
    assert result["declared_scope_screened"] is True
    assert result["all_endpoints_within_declared_scope"] is True
    assert result["host_only_isolation_verified"] is False
    assert result["label_truth_verified"] is False
    assert result["model_fitted"] is False
    assert "192.168.56." not in json.dumps(result)
    assert "private-operator-note" not in json.dumps(result)
    # Backwards-compatible: no opt-in means no scope claim.
    without = inspect_offline_experiment(manifest)
    assert without["declared_scope_screened"] is False
    assert without["all_endpoints_within_declared_scope"] is None


def test_scope_gate_refuses_out_of_scope_capture_even_with_valid_hash_and_labels(tmp_path):
    from evaluate_zeek_lab import inspect_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    entry = spec["captures"][-1]
    log = manifest.parent / entry["log_path"]
    raw = log.read_bytes().replace(b"192.168.56.20", b"8.8.8.8")
    log.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    entry["source_sha256"] = digest
    labels = manifest.parent / entry["labels_path"]
    annotation = json.loads(labels.read_text(encoding="utf-8"))
    annotation["source_sha256"] = digest
    labels.write_text(json.dumps(annotation), encoding="utf-8")
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    # A fully consistent manifest is NOT sufficient to pass a declared scope.
    assert inspect_offline_experiment(manifest)["structural_validation_passed"] is True
    with pytest.raises(ValueError, match="outside the declared lab scope"):
        inspect_offline_experiment(manifest, lab_cidrs=["192.168.56.0/24"])
    output = manifest.parent / "blocked-report.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--output", str(output),
        "--cidr", "192.168.56.0/24",
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert not output.exists()
    assert "8.8.8.8" not in proc.stderr
    assert str(manifest) not in proc.stderr


@pytest.mark.parametrize("cidr", ["10.0.0.0/8", "0.0.0.0/0", "192.168.56.1/24", "8.8.8.0/24"])
def test_scope_gate_rejects_invalid_or_overbroad_cidr(tmp_path, cidr):
    manifest = _lab_files(tmp_path / "private")
    with pytest.raises(ValueError):
        load_experiment_manifest(manifest, lab_cidrs=[cidr])


def test_scoped_cli_preflight_and_research_report_remain_offline(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    base = [
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--cidr", "192.168.56.0/24",
    ]
    preflight = subprocess.run(base + ["--preflight"], capture_output=True, text=True, check=False)
    assert preflight.returncode == 0, preflight.stderr
    assert json.loads(preflight.stdout)["declared_scope_screened"] is True
    output = manifest.parent / "scoped-research.json"
    experiment = subprocess.run(base + ["--output", str(output)], capture_output=True, text=True, check=False)
    assert experiment.returncode == 0, experiment.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["declared_scope_screened"] is True
    assert report["all_endpoints_within_declared_scope"] is True
    assert report["automated_alerts"] is False
    assert report["live_capture"] is False
    assert "192.168.56." not in json.dumps(report)


def test_private_heldout_trace_is_opt_in_and_joinable_to_verified_log(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    private_output = manifest.parent / "private-heldout-trace.json"
    base = [
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--cidr", "192.168.56.0/24",
    ]
    proc = subprocess.run(
        base + ["--trace-output", str(private_output)],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(private_output.read_text(encoding="utf-8"))
    trace = result["private_test_trace"]
    assert result["report_version"] == 4
    assert trace["mode"] == "offline_zeek_heldout_test_predictions_only"
    assert trace["selected_threshold"] == result["selected_threshold"]
    assert trace["automated_alerts"] is False
    assert len(trace["flows"]) == result["test_metrics"]["support"] == 2
    test_log = manifest.parent / "host-2.log"
    for row in trace["flows"]:
        assert row["source_sha256"] == hashlib.sha256(test_log.read_bytes()).hexdigest()
        assert row["uid"] in ("N2", "A2")
        assert 0 <= row["attack_probability"] <= 1
        assert row["predicted_attack"] == (row["attack_probability"] >= trace["selected_threshold"])
        assert row["operator_supplied_label"] in (0, 1)
        assert row["outcome_against_supplied_label"] in (
            "true_positive", "false_positive", "true_negative", "false_negative",
        )
    # Aggregate mode must never leak the private UID/label trace.
    aggregate = run_offline_experiment(manifest)
    assert "private_test_trace" not in aggregate
    assert "N2" not in json.dumps(aggregate)
    assert "A2" not in json.dumps(aggregate)
    assert "192.168.56." not in json.dumps(result)
    assert "private-operator-note" not in json.dumps(result)
    again = subprocess.run(
        base + ["--trace-output", str(private_output)],
        capture_output=True, text=True, check=False,
    )
    assert again.returncode == 1
    assert json.loads(private_output.read_text(encoding="utf-8")) == result


def test_private_trace_never_tunes_model_with_test_labels(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    first = run_offline_experiment(manifest, include_private_test_trace=True)
    annotation_path = manifest.parent / "host-2-labels.json"
    annotation = json.loads(annotation_path.read_text(encoding="utf-8"))
    annotation["labels_by_uid"] = {"N2": 1, "A2": 0}
    annotation_path.write_text(json.dumps(annotation), encoding="utf-8")
    second = run_offline_experiment(manifest, include_private_test_trace=True)
    assert first["selected_threshold"] == second["selected_threshold"]
    assert first["validation_metrics"] == second["validation_metrics"]
    a, b = first["private_test_trace"]["flows"], second["private_test_trace"]["flows"]
    assert [(x["uid"], x["attack_probability"], x["predicted_attack"]) for x in a] == [
        (x["uid"], x["attack_probability"], x["predicted_attack"]) for x in b
    ]
    assert [x["operator_supplied_label"] for x in a] != [x["operator_supplied_label"] for x in b]


def test_private_trace_fails_closed_before_writing_on_invalid_scope(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    output = manifest.parent / "should-not-exist.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--trace-output", str(output),
        "--cidr", "10.42.0.0/16",
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert not output.exists()
    assert "192.168.56." not in proc.stderr


def test_private_trace_mode_is_mutually_exclusive_with_aggregate_and_preflight(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    output = manifest.parent / "trace.json"
    for extra in (["--output", str(manifest.parent / "aggregate.json")], ["--preflight"]):
        proc = subprocess.run([
            sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
            "--manifest", str(manifest), "--trace-output", str(output), *extra,
        ], capture_output=True, text=True, check=False)
        assert proc.returncode != 0
        assert not output.exists()


def test_preflight_and_fit_refuse_reencoded_cross_split_flow_reuse(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    train = (manifest.parent / "host-0.log").read_bytes()
    test_entry = spec["captures"][2]
    test_path = manifest.parent / test_entry["log_path"]
    test_raw = train.replace(
        b"#fields\\t", b"# alternate Zeek header\\n#fields\\t", 1
    )
    test_path.write_bytes(test_raw)
    test_entry["source_sha256"] = hashlib.sha256(test_raw).hexdigest()
    annotation_path = manifest.parent / test_entry["labels_path"]
    annotation_path.write_text(json.dumps({
        "source_sha256": test_entry["source_sha256"],
        "labels_by_uid": {"N0": 0, "A0": 1},
    }), encoding="utf-8")
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    base = [
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest),
    ]
    preflight = subprocess.run(
        base + ["--preflight"], capture_output=True, text=True, check=False
    )
    assert preflight.returncode == 1
    assert not preflight.stdout
    output = manifest.parent / "must-not-create.json"
    evaluated = subprocess.run(
        base + ["--output", str(output)], capture_output=True, text=True, check=False
    )
    assert evaluated.returncode == 1
    assert not output.exists()
    assert "192.168.56" not in evaluated.stderr
    assert str(manifest) not in evaluated.stderr
