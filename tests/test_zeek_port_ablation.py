"""Synthetic-only port ablation tests: NOT measured VMware attack detection."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.offline_baseline import evaluate_offline_zeek_baseline
from blue_team_ai.port_ablation import evaluate_zeek_port_ablation, _portless_pipeline
from test_zeek_offline_baseline import _dataset
from test_zeek_lab_cli import _lab_files


def test_portless_excludes_both_ports_and_full_matches_existing_baseline():
    dataset = _dataset()
    original = copy.deepcopy(dataset)
    report = evaluate_zeek_port_ablation(dataset)
    assert dataset == original
    assert report["mode"] == "offline_zeek_port_feature_ablation_research_only"
    assert report["variants"]["full"]["test_metrics"] == evaluate_offline_zeek_baseline(dataset)["test_metrics"]
    assert report["variants"]["full"]["selected_validation_threshold"] == evaluate_offline_zeek_baseline(dataset)["selected_threshold"]
    assert report["excluded_port_features"] == ["dst_port", "src_port"]
    assert len(report["variants"]["full"]["used_feature_columns"]) == 9
    assert len(report["variants"]["without_ports"]["used_feature_columns"]) == 7
    assert not {"src_port", "dst_port"} & set(report["variants"]["without_ports"]["used_feature_columns"])
    assert report["test_metrics_used_for_model_selection"] is False
    assert report["causal_feature_effect_established"] is False
    assert report["automated_alerts"] is False
    assert report["live_capture"] is False
    assert report["independent_ground_truth_verified"] is False
    assert sum(report["variants"]["without_ports"]["test_metrics"][key] for key in ("tp", "fp", "tn", "fn")) == 2
    assert "192.168.56." not in json.dumps(report)
    assert "operator-note" not in json.dumps(report)
    assert "N0" not in json.dumps(report)



def test_paired_ablation_reports_anonymous_host_variability_with_matching_counts():
    dataset = _dataset()
    # A second operator-declared TEST group makes host-level variation visible.
    dataset.provenance["test"][1]["host_group"] = "private-second-test-host"
    report = evaluate_zeek_port_ablation(dataset)
    assert report["report_version"] == 2
    assert report["host_group_variability_is_descriptive_only"] is True
    for variant in ("full", "without_ports"):
        result = report["variants"][variant]
        for split in ("validation", "test"):
            summary = result[f"{split}_host_variability"]
            assert summary["unit_of_grouping"] == "operator_declared_host_group"
            assert summary["group_count"] == (2 if split == "test" else 1)
            assert summary["small_group_warning"] is True
            assert summary["single_group_warning"] is (split == "validation")
            # Even though paired TEST cells are suppressed, the per-variant
            # confusion rows and macro ranges would reveal tiny host groups.
            assert summary["minimum_support_per_group"] == 30
            assert summary["all_group_counts_suppressed"] is True
            assert summary["groups"] == []
            assert summary["rate_ranges"] is None
    serialized = json.dumps(report)
    for forbidden in ("private-second-test-host", "host-validation", "host-test", "192.168.56.", "operator-note"):
        assert forbidden not in serialized


def test_heldout_labels_change_host_diagnostics_but_not_validation_selection():
    dataset = _dataset()
    dataset.provenance["test"][1]["host_group"] = "private-second-test-host"
    before = evaluate_zeek_port_ablation(dataset)
    altered = copy.deepcopy(dataset)
    altered.labels["test"] = [1, 0]
    after = evaluate_zeek_port_ablation(altered)
    for variant in ("full", "without_ports"):
        a, b = before["variants"][variant], after["variants"][variant]
        assert a["selected_validation_threshold"] == b["selected_validation_threshold"]
        assert a["validation_host_variability"] == b["validation_host_variability"]
        assert a["test_host_variability"] == b["test_host_variability"]
        assert a["test_metrics"] != b["test_metrics"]

def test_portless_is_invariant_to_port_values_across_all_splits():
    dataset = _dataset()
    baseline = evaluate_zeek_port_ablation(dataset)["variants"]["without_ports"]
    changed = copy.deepcopy(dataset)
    for split in ("train", "validation", "test"):
        for row in changed.features[split]:
            row["src_port"] = 65535
            row["dst_port"] = 1
    assert evaluate_zeek_port_ablation(changed)["variants"]["without_ports"] == baseline
    # Inspect the actual fitted transformer's column list, not merely report metadata.
    transformer = _portless_pipeline().named_steps["preprocessing"]
    used = [column for _, _, columns in transformer.transformers for column in columns]
    assert "src_port" not in used and "dst_port" not in used


def test_heldout_test_labels_cannot_change_validation_thresholds():
    dataset = _dataset()
    reference = evaluate_zeek_port_ablation(dataset)
    altered = copy.deepcopy(dataset)
    altered.labels["test"] = [1, 0]
    changed = evaluate_zeek_port_ablation(altered)
    for variant in ("full", "without_ports"):
        assert reference["variants"][variant]["selected_validation_threshold"] == changed["variants"][variant]["selected_validation_threshold"]
        assert reference["variants"][variant]["validation_metrics"] == changed["variants"][variant]["validation_metrics"]
    assert reference["variants"]["full"]["test_metrics"] != changed["variants"]["full"]["test_metrics"]


@pytest.mark.parametrize("mutation", [
    lambda d: d.features["train"][0].update(label=1),
    lambda d: d.labels["train"].__setitem__(0, True),
    lambda d: d.provenance["test"][0].update(host_group="host-train"),
])
def test_ablation_refuses_invalid_research_inputs(mutation):
    dataset = _dataset()
    mutation(dataset)
    with pytest.raises(ValueError):
        evaluate_zeek_port_ablation(dataset)


def _pinned_manifest(tmp_path):
    manifest = _lab_files(tmp_path / "private")
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    # The generic CLI fixture deliberately repeats identical flow tuples
    # across splits; strict ablation input gates must reject those. Give each
    # synthetic session distinct source ports and repin BOTH log and labels.
    for index, entry in enumerate(spec["captures"]):
        log = manifest.parent / entry["log_path"]
        raw = log.read_bytes().replace(
            b"\t52344\t", f"\t{52344 + 10 * index}\t".encode(),
        ).replace(
            b"\t52345\t", f"\t{52345 + 10 * index}\t".encode(),
        )
        log.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        entry["source_sha256"] = digest
        labels = manifest.parent / entry["labels_path"]
        annotation = json.loads(labels.read_text(encoding="utf-8"))
        annotation["source_sha256"] = digest
        labels.write_text(json.dumps(annotation), encoding="utf-8")
        entry["labels_sha256"] = hashlib.sha256(labels.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(spec), encoding="utf-8")
    return manifest


def test_cli_private_strict_pinned_ablation_and_refusals(tmp_path):
    manifest = _pinned_manifest(tmp_path)
    pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
    output = manifest.parent / "port-ablation.json"
    base = [
        sys.executable, str(ROOT / "scripts" / "evaluate_zeek_lab.py"),
        "--manifest", str(manifest), "--cidr", "192.168.56.0/24",
        "--strict-input-gates", "--expected-manifest-sha256", pin,
        "--port-ablation-output", str(output),
    ]
    accepted = subprocess.run(base, capture_output=True, text=True)
    assert accepted.returncode == 0, accepted.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["input_manifest_sha256"] == pin
    assert report["manifest_sha256_pin_verified"] is True
    assert report["all_annotation_sha256_pins_required"] is True
    assert report["mode"] == "offline_zeek_port_feature_ablation_research_only"
    assert "192.168.56." not in json.dumps(report)
    original = output.read_bytes()
    assert subprocess.run(base, capture_output=True).returncode == 1
    assert output.read_bytes() == original

    for removed in ("--strict-input-gates", "--expected-manifest-sha256", "--cidr"):
        rejected_output = manifest.parent / ("rejected-" + removed[2:] + ".json")
        command = base.copy()
        if removed == "--strict-input-gates":
            command.remove(removed)
        else:
            at = command.index(removed)
            del command[at:at + 2]
        command[command.index("--port-ablation-output") + 1] = str(rejected_output)
        rejected = subprocess.run(command, capture_output=True, text=True)
        assert rejected.returncode == 1
        assert not rejected_output.exists()
        assert str(manifest) not in rejected.stderr
    bad_output = manifest.parent / "rejected-bad-pin.json"
    altered = base.copy()
    altered[altered.index("--expected-manifest-sha256") + 1] = "0" * 64
    altered[altered.index("--port-ablation-output") + 1] = str(bad_output)
    assert subprocess.run(altered, capture_output=True).returncode == 1
    assert not bad_output.exists()

def test_paired_test_correctness_matches_both_confusion_matrices():
    report = evaluate_zeek_port_ablation(_dataset())
    paired = report["paired_test_correctness"]
    full = report["variants"]["full"]["test_metrics"]
    portless = report["variants"]["without_ports"]["test_metrics"]
    overall = paired["overall"]
    assert paired["support"] == full["support"] == portless["support"]
    assert sum(overall.values()) == paired["support"]
    assert sum(paired["by_operator_supplied_label"]["normal"].values()) == full["tn"] + full["fp"]
    assert sum(paired["by_operator_supplied_label"]["attack"].values()) == full["tp"] + full["fn"]
    assert overall["both_correct"] + overall["full_only_correct"] == full["tp"] + full["tn"]
    assert overall["both_correct"] + overall["without_ports_only_correct"] == portless["tp"] + portless["tn"]
    assert paired["discordant_correctness_count"] == (
        overall["full_only_correct"] + overall["without_ports_only_correct"]
    )
    assert paired["statistical_significance_test_performed"] is False
    assert paired["independent_ground_truth_verified"] is False
    assert "192.168.56." not in json.dumps(paired)


def test_paired_summary_rejects_misalignment_and_nonboolean_values():
    from blue_team_ai.paired_disagreement import summarize_paired_zeek_test

    assert summarize_paired_zeek_test(
        [0, 1, 0, 1], [False, True, True, False], [False, False, True, True]
    )["overall"] == {
        "both_correct": 1,
        "full_only_correct": 1,
        "without_ports_only_correct": 1,
        "neither_correct": 1,
    }
    for labels, full, portless in (
        ([], [], []),
        ([0], [False, True], [False]),
        ([0], [False], []),
        ([True], [False], [False]),
        ([2], [False], [False]),
        ([0], [0], [False]),
        ([0], [False], [1]),
    ):
        with pytest.raises(ValueError):
            summarize_paired_zeek_test(labels, full, portless)


def test_paired_predictions_are_stable_when_only_test_labels_change():
    original = _dataset()
    reference = evaluate_zeek_port_ablation(original)
    altered = copy.deepcopy(original)
    altered.labels["test"] = [1 - value for value in altered.labels["test"]]
    changed = evaluate_zeek_port_ablation(altered)
    for variant in ("full", "without_ports"):
        assert (reference["variants"][variant]["selected_validation_threshold"]
                == changed["variants"][variant]["selected_validation_threshold"])
    assert reference["paired_test_correctness"]["support"] == changed["paired_test_correctness"]["support"]
    assert reference["paired_test_correctness"]["discordant_correctness_count"] == changed["paired_test_correctness"]["discordant_correctness_count"]



def test_paired_host_discordance_anonymized_when_all_groups_large():
    from blue_team_ai.paired_disagreement import summarize_paired_zeek_test

    labels = [0, 1] * 30
    full = [False, False] * 30
    without_ports = [False, True] * 30
    groups = ["private-group-one"] * 30 + ["private-group-two"] * 30
    report = summarize_paired_zeek_test(
        labels, full, without_ports, host_groups=groups,
    )
    by_host = report["by_anonymous_host_group"]
    assert by_host["group_count"] == 2
    assert by_host["all_group_counts_suppressed"] is False
    assert by_host["single_group_warning"] is False
    assert [row["support"] for row in by_host["groups"]] == [30, 30]
    for cell in ("both_correct", "full_only_correct", "without_ports_only_correct", "neither_correct"):
        assert sum(row[cell] for row in by_host["groups"]) == report["overall"][cell]
    assert sum(row["discordant_correctness_count"] for row in by_host["groups"]) == report["discordant_correctness_count"]
    assert "private-group" not in json.dumps(report)
    assert report["statistical_significance_test_performed"] is False


def test_paired_host_discordance_suppresses_all_groups_against_differencing():
    from blue_team_ai.paired_disagreement import summarize_paired_zeek_test

    labels = [0, 1] * 30
    full = [False] * 60
    without_ports = [True] * 60
    # If the 31-flow group's counts were visible, subtraction from overall
    # would reveal the 29-flow group's correctness. Suppress both groups.
    report = summarize_paired_zeek_test(
        labels, full, without_ports,
        host_groups=["private-small"] * 29 + ["private-large"] * 31,
    )
    by_host = report["by_anonymous_host_group"]
    assert by_host["group_count"] == 2
    assert by_host["all_group_counts_suppressed"] is True
    assert by_host["groups"] == []
    assert "private-small" not in json.dumps(report)
    assert "private-large" not in json.dumps(report)
    # Legacy three-argument calls preserve their previous schema.
    assert "by_anonymous_host_group" not in summarize_paired_zeek_test(
        labels, full, without_ports,
    )


@pytest.mark.parametrize("groups", [
    [],
    ["only-one"],
    [""] * 60,
    [" invalid"] * 60,
    ["bad\nline"] * 60,
    [123] * 60,
    ["x" * 257] * 60,
])
def test_paired_host_discordance_refuses_invalid_group_metadata(groups):
    from blue_team_ai.paired_disagreement import summarize_paired_zeek_test

    with pytest.raises(ValueError, match="host groups"):
        summarize_paired_zeek_test(
            [0] * 60, [False] * 60, [False] * 60, host_groups=groups,
        )


def test_ablation_paired_host_diagnostics_do_not_disclose_tiny_fixture_rows():
    report = evaluate_zeek_port_ablation(_dataset())
    host = report["paired_test_correctness"]["by_anonymous_host_group"]
    assert host["group_count"] == 1
    assert host["all_group_counts_suppressed"] is True
    assert host["groups"] == []
    assert host["single_group_warning"] is True


def test_ablation_all_splits_and_variants_suppress_small_group_cells():
    report = evaluate_zeek_port_ablation(_dataset())
    for variant in ("full", "without_ports"):
        for split in ("validation", "test"):
            summary = report["variants"][variant][f"{split}_host_variability"]
            assert summary["all_group_counts_suppressed"] is True
            assert summary["groups"] == []
            assert summary["rate_ranges"] is None
    assert report["paired_test_correctness"]["by_anonymous_host_group"]["groups"] == []
    # Aggregate model metrics remain available for legitimate research.
    assert report["variants"]["full"]["test_metrics"]["support"] == 2
