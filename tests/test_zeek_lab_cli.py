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
    assert result["report_version"] == 5
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
        b"#fields\t", b"# alternate Zeek header\n#fields\t", 1
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


def _pin_annotation_files(manifest):
    """Freeze exact annotation bytes, independently of the Zeek source hashes."""
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    for entry in spec["captures"]:
        label_path = manifest.parent / entry["labels_path"]
        entry["labels_sha256"] = hashlib.sha256(label_path.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    return spec


def test_strict_annotation_pins_require_every_capture_before_preflight_or_fit(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    output = manifest.parent / "should-not-exist.json"
    base = [sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
            "--manifest", str(manifest), "--require-label-sha256"]
    for args in (["--preflight"], ["--output", str(output)]):
        result = subprocess.run(base + args, capture_output=True, text=True, check=False)
        assert result.returncode == 1
        assert "192.168.56." not in result.stderr
        assert not output.exists()
    assert load_experiment_manifest(manifest)[0]  # legacy manifest remains supported
    with pytest.raises(ValueError, match="requires labels_sha256"):
        load_experiment_manifest(manifest, require_label_sha256=True)


def test_pinned_annotation_bytes_are_checked_before_fit_and_report(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    _pin_annotation_files(manifest)
    preflight = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--require-label-sha256", "--preflight",
    ], capture_output=True, text=True, check=False)
    assert preflight.returncode == 0, preflight.stderr
    summary = json.loads(preflight.stdout)
    assert summary["all_annotation_sha256_pins_required"] is True
    assert summary["annotation_chain_verified"] is False
    assert summary["label_truth_verified"] is False
    output = manifest.parent / "pinned-report.json"
    run = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--require-label-sha256",
        "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["all_annotation_sha256_pins_required"] is True
    assert report["annotation_chain_verified"] is False
    assert report["test_metrics"]["support"] == 2


def test_changed_annotation_bytes_fail_even_when_source_hash_and_uids_match(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    _pin_annotation_files(manifest)
    label_path = manifest.parent / "host-2-labels.json"
    before = label_path.read_bytes()
    labels = json.loads(before)
    labels["labels_by_uid"] = {"N2": 1, "A2": 0}
    label_path.write_text(json.dumps(labels), encoding="utf-8")
    with pytest.raises(ValueError, match="Annotation file SHA-256 mismatch"):
        load_experiment_manifest(manifest, require_label_sha256=True)
    output = manifest.parent / "must-not-exist.json"
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--require-label-sha256",
        "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert not output.exists()
    assert "N2" not in result.stderr and "192.168.56." not in result.stderr
    # Byte-exact pinning also catches harmless formatting changes.
    label_path.write_bytes(before + b" ")
    with pytest.raises(ValueError, match="Annotation file SHA-256 mismatch"):
        load_experiment_manifest(manifest)


def test_malformed_or_partial_annotation_pins_are_rejected(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    spec = _pin_annotation_files(manifest)
    spec["captures"][0]["labels_sha256"] = "BAD"
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(ValueError, match="Expected lowercase SHA-256"):
        load_experiment_manifest(manifest)
    spec["captures"][0].pop("labels_sha256")
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    # Mixed legacy/pinned entries are allowed only without strict opt-in.
    assert load_experiment_manifest(manifest)[0]
    with pytest.raises(ValueError, match="requires labels_sha256"):
        load_experiment_manifest(manifest, require_label_sha256=True)


def test_repinning_changed_labels_does_not_authenticate_ground_truth(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    spec = _pin_annotation_files(manifest)
    label_path = manifest.parent / "host-1-labels.json"
    labels = json.loads(label_path.read_text(encoding="utf-8"))
    labels["labels_by_uid"] = {"N1": 1, "A1": 0}
    label_path.write_text(json.dumps(labels), encoding="utf-8")
    spec["captures"][1]["labels_sha256"] = hashlib.sha256(label_path.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    from evaluate_zeek_lab import inspect_offline_experiment
    summary = inspect_offline_experiment(manifest, require_label_sha256=True)
    assert summary["structural_validation_passed"] is True
    assert summary["annotation_chain_verified"] is False
    assert summary["label_truth_verified"] is False


def test_opt_in_quality_screen_covers_all_pinned_splits_without_private_identifiers(tmp_path):
    from evaluate_zeek_lab import inspect_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    _pin_annotation_files(manifest)
    opts = {
        "lab_cidrs": ["192.168.56.0/24"],
        "require_label_sha256": True,
        "require_telemetry_quality": True,
    }
    preflight = inspect_offline_experiment(manifest, **opts)
    quality = preflight["telemetry_quality"]
    assert quality["mode"] == "offline_pinned_zeek_manifest_quality_only"
    assert quality["screened_captures"] == 3
    assert quality["host_only_isolation_verified"] is False
    assert quality["independent_ground_truth_verified"] is False
    assert quality["real_attack_detection_validated"] is False
    for split in ("train", "validation", "test"):
        part = quality["partitions"][split]
        assert part["captures"] == 1
        assert part["flows"] == 2
        assert part["protocol_bucket_counts"] == {
            "tcp": 1, "udp": 1, "icmp": 0, "other": 0,
        }
        assert part["missing_optional_feature_counts"] == {
            "service": 1, "duration_s": 1, "orig_bytes": 0,
            "resp_bytes": 1, "orig_pkts": 1, "resp_pkts": 1,
        }
        assert part["warning_capture_counts"]["fewer_than_30_flows"] == 1
        assert part["warning_capture_counts"]["optional_feature_measurements_missing"] == 1
    result = run_offline_experiment(manifest, **opts)
    assert result["telemetry_quality"] == quality
    assert result["test_metrics"]["support"] == 2
    assert result["all_annotation_sha256_pins_required"] is True
    for forbidden in ("192.168.56.", "private-operator-note", "N0", "A1", "host-train"):
        assert forbidden not in json.dumps(result)
        assert forbidden not in json.dumps(preflight)
    assert "telemetry_quality" not in inspect_offline_experiment(manifest)
    assert "telemetry_quality" not in run_offline_experiment(manifest)


def test_quality_opt_in_requires_explicit_scope_before_preflight_or_fit(tmp_path):
    from evaluate_zeek_lab import inspect_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    with pytest.raises(ValueError, match="requires explicit lab CIDRs"):
        inspect_offline_experiment(manifest, require_telemetry_quality=True)
    with pytest.raises(ValueError, match="requires explicit lab CIDRs"):
        run_offline_experiment(manifest, require_telemetry_quality=True)
    output = manifest.parent / "blocked-quality.json"
    base = [
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--require-telemetry-quality",
    ]
    for mode in (["--preflight"], ["--output", str(output)],
                 ["--trace-output", str(output)]):
        proc = subprocess.run(base + mode, capture_output=True, text=True, check=False)
        assert proc.returncode == 1
        assert not proc.stdout
        assert not output.exists()
        assert "192.168.56." not in proc.stderr
        assert str(manifest) not in proc.stderr


def test_quality_opt_in_cli_preflight_and_research_output_are_consistent(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    base = [
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--cidr", "192.168.56.0/24",
        "--require-telemetry-quality",
    ]
    preflight = subprocess.run(base + ["--preflight"], capture_output=True, text=True, check=False)
    assert preflight.returncode == 0, preflight.stderr
    pre = json.loads(preflight.stdout)
    output = manifest.parent / "quality-scored.json"
    run = subprocess.run(base + ["--output", str(output)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["telemetry_quality"] == pre["telemetry_quality"]
    assert report["telemetry_quality"]["screened_captures"] == 3
    assert report["automated_alerts"] is False
    assert report["live_capture"] is False
    assert "192.168.56." not in json.dumps(report)
    again = subprocess.run(base + ["--output", str(output)], capture_output=True, text=True, check=False)
    assert again.returncode == 1
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_quality_opt_in_rejects_changed_source_even_with_labels_pinned(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    _pin_annotation_files(manifest)
    source = manifest.parent / "host-1.log"
    source.write_bytes(source.read_bytes() + b"#changed\n")
    output = manifest.parent / "must-not-create-quality.json"
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--cidr", "192.168.56.0/24",
        "--require-telemetry-quality", "--require-label-sha256",
        "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert not output.exists()
    assert "192.168.56." not in result.stderr
    assert str(manifest) not in result.stderr


def test_uid_independent_overlap_opt_in_rejects_renamed_uids_across_splits(tmp_path):
    """Default fixture uses different UIDs but identical timestamp/five-tuples."""
    from evaluate_zeek_lab import inspect_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    # Legacy evaluation is unchanged unless explicitly opted in.
    assert inspect_offline_experiment(manifest)["structural_validation_passed"] is True
    with pytest.raises(ValueError, match="Cross-split timestamp/five-tuple overlap"):
        inspect_offline_experiment(manifest, require_uid_independent_overlap=True)
    output = manifest.parent / "must-not-exist.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--require-uid-independent-overlap",
        "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert not output.exists()
    assert "192.168.56." not in proc.stderr
    assert str(manifest) not in proc.stderr


def test_uid_independent_overlap_opt_in_accepts_distinct_times_and_reports_only_aggregates(tmp_path):
    """Same endpoints may legitimately recur in separate nonoverlapping sessions."""
    from evaluate_zeek_lab import inspect_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    for index, entry in enumerate(spec["captures"]):
        path = manifest.parent / entry["log_path"]
        raw = path.read_bytes()
        raw = raw.replace(b"1630000000.25", f"{1630000000 + index * 100}.25".encode())
        raw = raw.replace(b"1630000001.0", f"{1630000001 + index * 100}.0".encode())
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        entry["source_sha256"] = digest
        label_path = manifest.parent / entry["labels_path"]
        annotation = json.loads(label_path.read_text(encoding="utf-8"))
        annotation["source_sha256"] = digest
        label_path.write_text(json.dumps(annotation), encoding="utf-8")
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    report = inspect_offline_experiment(manifest, require_uid_independent_overlap=True)
    overlap = report["uid_independent_overlap_screen"]
    assert overlap["screened_flows"] == 6
    assert overlap["cross_split_overlaps"] == 0
    assert overlap["uid_excluded_from_identity"] is True
    assert overlap["capture_independence_verified"] is False
    assert "uid_independent_overlap_screen" not in inspect_offline_experiment(manifest)
    output = manifest.parent / "screened-research.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--require-uid-independent-overlap",
        "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["uid_independent_overlap_screen"]["screened_flows"] == 6
    assert result["automated_alerts"] is False
    serialized = json.dumps(result)
    assert "192.168.56." not in serialized
    assert "private-operator-note" not in serialized



def test_independently_pinned_manifest_matches_preflight_and_report(tmp_path):
    """An external manifest pin binds preflight to the exact experiment plan bytes."""
    from evaluate_zeek_lab import inspect_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
    legacy = inspect_offline_experiment(manifest)
    assert "manifest_sha256_pin_verified" not in legacy
    checked = inspect_offline_experiment(manifest, expected_manifest_sha256=pin)
    assert checked["manifest_sha256_pin_verified"] is True
    assert checked["input_manifest_sha256"] == pin
    assert checked["model_fitted"] is False
    output = manifest.parent / "pinned-report.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--expected-manifest-sha256", pin,
        "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["manifest_sha256_pin_verified"] is True
    assert report["input_manifest_sha256"] == pin
    assert report["automated_alerts"] is False
    assert "192.168.56." not in json.dumps(report)
    assert "private-operator-note" not in json.dumps(report)


def test_manifest_pin_detects_plan_change_between_preflight_and_fit(tmp_path):
    """Even a valid metadata-only manifest edit must invalidate the old pin."""
    from evaluate_zeek_lab import inspect_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert inspect_offline_experiment(
        manifest, expected_manifest_sha256=pin,
    )["structural_validation_passed"] is True
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    spec["captures"][0]["label_reference"] = "private-operator-note-revised"
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    assert inspect_offline_experiment(manifest)["structural_validation_passed"] is True
    with pytest.raises(ValueError, match="Experiment manifest SHA-256 mismatch"):
        inspect_offline_experiment(manifest, expected_manifest_sha256=pin)
    for mode in ("--output", "--trace-output"):
        output = manifest.parent / ("must-not-write-" + mode[2:] + ".json")
        proc = subprocess.run([
            sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
            "--manifest", str(manifest), "--expected-manifest-sha256", pin,
            mode, str(output),
        ], capture_output=True, text=True, check=False)
        assert proc.returncode == 1
        assert not output.exists()
        assert str(manifest) not in proc.stderr
        assert "private-operator-note" not in proc.stderr


@pytest.mark.parametrize("pin", ["0" * 63, "A" * 64, "0" * 64 + " ", "", "not-a-sha"])
def test_manifest_pin_rejects_invalid_or_unmatched_sha(tmp_path, pin):
    from evaluate_zeek_lab import inspect_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    with pytest.raises(ValueError):
        inspect_offline_experiment(manifest, expected_manifest_sha256=pin)
    output = manifest.parent / "refused-report.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--expected-manifest-sha256", pin,
        "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert not output.exists()
    assert "192.168.56." not in proc.stderr


def test_manifest_pin_preflight_cli_does_not_write_files(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
    before = {p.name: p.read_bytes() for p in manifest.parent.iterdir()}
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--expected-manifest-sha256", pin,
        "--preflight",
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["manifest_sha256_pin_verified"] is True
    assert result["model_fitted"] is False
    assert "private-operator-note" not in proc.stdout
    assert {p.name: p.read_bytes() for p in manifest.parent.iterdir()} == before


def test_manifest_zeek_types_opt_in_refuses_missing_header_before_fit(tmp_path):
    """Legacy minimal fixtures remain accepted unless the new flag is set."""
    from evaluate_zeek_lab import inspect_offline_experiment, run_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    with pytest.raises(ValueError, match="requires explicit lab CIDRs"):
        inspect_offline_experiment(manifest, require_zeek_types=True)
    with pytest.raises(ValueError, match="Zeek types must precede flow records"):
        inspect_offline_experiment(
            manifest, lab_cidrs=["192.168.56.0/24"], require_zeek_types=True,
        )
    with pytest.raises(ValueError, match="Zeek types must precede flow records"):
        run_offline_experiment(
            manifest, lab_cidrs=["192.168.56.0/24"], require_zeek_types=True,
        )
    output = manifest.parent / "should-not-exist.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--cidr", "192.168.56.0/24",
        "--require-zeek-types", "--output", str(output),
    ], capture_output=True, text=True)
    assert proc.returncode == 1
    assert not output.exists()


# Synthetic-only regression for opt-in manifest-wide Zeek connection-start UTC bounds.
# These checks do not attest to the real capture clock or measure alert timing.
@pytest.mark.parametrize("mode", ["preflight", "output"])
def test_manifest_wide_utc_event_start_gate_accepts_pinned_fixture(tmp_path, mode):
    from evaluate_zeek_lab import inspect_offline_experiment, run_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    start, end = "2021-08-26T17:46:40Z", "2021-08-26T17:46:42Z"
    kwargs = dict(lab_cidrs=["192.168.56.0/24"],
                  event_window_start_utc=start, event_window_end_utc=end)
    result = (inspect_offline_experiment(manifest, **kwargs) if mode == "preflight"
              else run_offline_experiment(manifest, **kwargs))
    assert result["telemetry_quality"]["operator_event_window_checked"] is True
    assert result["telemetry_quality"]["screened_captures"] == 3
    assert result["telemetry_quality"]["host_only_isolation_verified"] is False
    serialized = json.dumps(result)
    assert start not in serialized and end not in serialized
    assert "private-operator-note" not in serialized and "192.168.56." not in serialized
    args = ["--preflight"] if mode == "preflight" else ["--output", str(manifest.parent / "utc-report.json")]
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--cidr", "192.168.56.0/24",
        "--event-start-utc", start, "--event-end-utc", end, *args,
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    if mode == "preflight":
        assert json.loads(proc.stdout)["telemetry_quality"]["operator_event_window_checked"] is True
        assert not (manifest.parent / "utc-report.json").exists()
    else:
        assert json.loads((manifest.parent / "utc-report.json").read_text(encoding="utf-8"))["telemetry_quality"]["operator_event_window_checked"] is True


@pytest.mark.parametrize("start,end", [
    ("2021-08-26T17:46:40Z", None),
    (None, "2021-08-26T17:46:42Z"),
    ("2021-08-26T17:46:42Z", "2021-08-26T17:46:40Z"),
    ("2021-08-26T17:46:41Z", "2021-08-26T17:46:42Z"),
    ("2021-08-26T17:46:40+00:00", "2021-08-26T17:46:42Z"),
    ("2021-02-30T00:00:00Z", "2021-08-26T17:46:42Z"),
])
def test_manifest_wide_utc_event_start_gate_refuses_before_output(tmp_path, start, end):
    from evaluate_zeek_lab import inspect_offline_experiment, run_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    kwargs = dict(lab_cidrs=["192.168.56.0/24"],
                  event_window_start_utc=start, event_window_end_utc=end)
    with pytest.raises(ValueError):
        inspect_offline_experiment(manifest, **kwargs)
    with pytest.raises(ValueError):
        run_offline_experiment(manifest, **kwargs)
    output = manifest.parent / "refused-utc.json"
    args = []
    if start is not None:
        args.extend(["--event-start-utc", start])
    if end is not None:
        args.extend(["--event-end-utc", end])
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--cidr", "192.168.56.0/24",
        *args, "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert not output.exists()
    assert "192.168.56." not in proc.stderr
    assert "private-operator-note" not in proc.stderr


def test_manifest_wide_utc_event_window_requires_cidr_and_legacy_unchanged(tmp_path):
    from evaluate_zeek_lab import inspect_offline_experiment
    manifest = _lab_files(tmp_path / "private")
    with pytest.raises(ValueError, match="requires explicit lab CIDRs"):
        inspect_offline_experiment(
            manifest, event_window_start_utc="2021-08-26T17:46:40Z",
            event_window_end_utc="2021-08-26T17:46:42Z",
        )
    legacy = inspect_offline_experiment(manifest)
    assert "telemetry_quality" not in legacy
