"""Synthetic-only tests for the offline Zeek research baseline (NOT lab metrics)."""
import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.offline_baseline import evaluate_offline_zeek_baseline


def _capture(split, suffix):
    raw = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
        "\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
        f"1630000000.25\tN{suffix}\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp"
        "\t-\t1.25\t100\t-\t2\t-\n"
        f"1630000001.0\tA{suffix}\t192.168.56.11\t52345\t192.168.56.21\t53\tudp"
        "\tdns\t-\t0\t25\t-\t1\n"
    ).encode("utf-8")
    return {
        "log_bytes": raw, "session_id": f"session-{suffix}",
        "host_group": f"host-{split}", "split": split,
        "label_method": "controlled_scenario_record",
        "label_reference": f"operator-note-{suffix}",
        "labels_by_uid": {f"N{suffix}": 0, f"A{suffix}": 1},
    }


def _dataset():
    return build_labeled_lab_dataset([
        _capture(split, i) for i, split in enumerate(("train", "validation", "test"))
    ])


def test_baseline_reports_real_synthetic_fit_without_identity_or_labels():
    dataset = _dataset()
    original = copy.deepcopy(dataset)
    report = evaluate_offline_zeek_baseline(dataset)
    assert dataset == original
    assert report["feature_schema_version"] == 1
    assert report["feature_columns"] == list(dataset.feature_columns)
    assert report["selected_threshold"] in (0.25, 0.40, 0.50, 0.60, 0.75)
    assert report["validation_metrics"]["support"] == 2
    assert report["report_version"] == 4
    assert report["validation_probability_diagnostics"]["sample_size"] == 2
    assert report["test_probability_diagnostics"]["sample_size"] == 2
    for split in ("validation", "test"):
        quality = report[f"{split}_probability_diagnostics"]
        assert 0 <= quality["brier_score"] <= 1
        assert 0 <= quality["expected_calibration_error"] <= 1
        assert sum(b["count"] for b in quality["reliability_bins"]) == 2
        assert quality["small_sample_warning"] is True
    assert report["test_metrics"]["support"] == 2
    for split in ("validation", "test"):
        grouped = report[f"{split}_host_variability"]
        assert grouped["group_count"] == 1
        assert grouped["single_group_warning"] is True
        assert grouped["small_group_warning"] is True
        assert sum(group["support"] for group in grouped["groups"]) == 2
        for key in ("tp", "fp", "tn", "fn"):
            assert sum(group[key] for group in grouped["groups"]) == report[f"{split}_metrics"][key]
    for split in ("validation", "test"):
        uncertainty = report[f"{split}_detection_uncertainty"]
        assert uncertainty["attack_recall"]["trials"] == 1
        assert uncertainty["false_positive_rate"]["trials"] == 1
        assert uncertainty["small_denominator_warning"] is True
        assert "no_host_cluster_adjustment" in uncertainty["interpretation"]
    assert sum(report["test_metrics"][key] for key in ("tp", "fp", "tn", "fn")) == 2
    assert report["provenance"]["test"]["flows"] == 2
    assert len(report["provenance"]["train"]["source_sha256"]) == 1
    assert report["label_authenticity"] == "operator_supplied_not_verified"
    assert report["live_capture"] is False
    assert report["automated_alerts"] is False
    serialized = str(report)
    for forbidden in ("192.168.56.", "operator-note-", "N0", "A0"):
        assert forbidden not in serialized


def test_test_labels_do_not_change_fit_validation_or_selected_threshold():
    dataset = _dataset()
    baseline = evaluate_offline_zeek_baseline(dataset)
    changed = copy.deepcopy(dataset)
    changed.labels["test"] = [1, 0]
    result = evaluate_offline_zeek_baseline(changed)
    assert baseline["selected_threshold"] == result["selected_threshold"]
    assert baseline["validation_metrics"] == result["validation_metrics"]
    assert baseline["validation_probability_diagnostics"] == result["validation_probability_diagnostics"]
    assert baseline["test_probability_diagnostics"] != result["test_probability_diagnostics"]
    assert baseline["validation_detection_uncertainty"] == result["validation_detection_uncertainty"]
    assert baseline["validation_host_variability"] == result["validation_host_variability"]
    assert baseline["test_host_variability"] != result["test_host_variability"]
    assert baseline["test_metrics"] != result["test_metrics"]


def test_unseen_categories_and_missing_numeric_values_are_supported():
    dataset = _dataset()
    changed = copy.deepcopy(dataset)
    changed.features["validation"][0]["proto"] = "new_proto"
    changed.features["test"][1]["service"] = "unseen_service"
    changed.features["test"][0]["duration_s"] = None
    report = evaluate_offline_zeek_baseline(changed)
    assert report["test_metrics"]["support"] == 2


@pytest.mark.parametrize("mutate,match", [
    (lambda d: d.features["test"][0].update(label=1), "Unexpected Zeek feature"),
    (lambda d: d.features["test"][0].update(orig_bytes=float("nan")), "Invalid numeric"),
    (lambda d: d.features["train"][0].update(orig_pkts=-1), "Invalid numeric"),
    (lambda d: d.labels["train"].__setitem__(0, True), "binary classes"),
    (lambda d: d.provenance["test"][0].update(host_group="host-train"), "Cross-split host_group"),
    (lambda d: d.provenance["test"][0].update(source_sha256=d.provenance["train"][0]["source_sha256"]), "Cross-split source_sha256"),
    (lambda d: d.provenance["test"][0].update(uid=None), "Missing Zeek provenance"),
])
def test_rejects_tampered_dataset_contract(mutate, match):
    dataset = _dataset()
    mutate(dataset)
    with pytest.raises(ValueError, match=match):
        evaluate_offline_zeek_baseline(dataset)


def test_refuses_numeric_column_entirely_missing_from_training():
    dataset = _dataset()
    for row in dataset.features["train"]:
        row["orig_bytes"] = None
    with pytest.raises(ValueError, match="measured training value"):
        evaluate_offline_zeek_baseline(dataset)
