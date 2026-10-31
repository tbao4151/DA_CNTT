"""Synthetic-only end-to-end private Zeek trace review; no real lab detection."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from blue_team_ai.trace_review import review_private_zeek_trace
from blue_team_ai.uncertainty import summarize_detection_uncertainty
from evaluate_zeek_lab import run_offline_experiment


def _fixture(tmp_path):
    entries = []
    for i, split in enumerate(("train", "validation", "test")):
        raw = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
            "\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
            f"1630000000.25\tN{i}\t192.168.56.10\t52344\t192.168.56.20\t443\ttcp"
            "\t-\t1.25\t100\t-\t2\t-\n"
            f"1630000001.0\tA{i}\t192.168.56.11\t52345\t192.168.56.21\t53\tudp"
            "\tdns\t-\t0\t25\t-\t1\n"
        ).encode()
        digest = hashlib.sha256(raw).hexdigest()
        (tmp_path / f"host{i}.log").write_bytes(raw)
        (tmp_path / f"host{i}-labels.json").write_text(json.dumps({
            "source_sha256": digest, "labels_by_uid": {f"N{i}": 0, f"A{i}": 1},
        }), encoding="utf-8")
        entries.append({
            "log_path": f"host{i}.log", "labels_path": f"host{i}-labels.json",
            "source_sha256": digest, "session_id": f"session{i}",
            "host_group": f"host{i}", "split": split,
            "label_method": "controlled_scenario_record",
            "label_reference": f"private-note{i}",
        })
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"manifest_version": 1, "captures": entries}), encoding="utf-8")
    report = run_offline_experiment(manifest, include_private_test_trace=True)
    return (tmp_path / "host2.log").read_bytes(), report


def _encode(report):
    return json.dumps(report, allow_nan=False).encode("utf-8")


def test_real_synthetic_model_trace_join_is_read_only_and_label_free(tmp_path):
    raw, report = _fixture(tmp_path)
    result = review_private_zeek_trace(raw, _encode(report))
    assert result["source_join_verified"] is True
    assert result["model_provenance_authenticated"] is False
    assert result["label_truth_verified"] is False
    assert result["automated_alerts"] is False
    assert result["flow_count"] == 2
    assert result["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert [row["uid"] for row in result["rows"]] == ["N2", "A2"]
    assert all(row["predicted_attack"] == (
        row["attack_probability"] >= result["selected_threshold"]
    ) for row in result["rows"])
    assert result["candidate_count"] == sum(r["predicted_attack"] for r in result["rows"])
    assert "operator_supplied_label" not in json.dumps(result)
    assert "outcome_against_supplied_label" not in json.dumps(result)
    assert "192.168.56." not in json.dumps(result)


@pytest.mark.parametrize("change", ["source", "missing_uid", "duplicate_uid", "bad_probability",
                                    "bad_verdict", "bad_outcome", "bad_counts", "bad_threshold",
                                    "wrong_mode", "wrong_schema", "missing_manifest"])
def test_mismatched_or_forged_private_trace_refused(tmp_path, change):
    raw, report = _fixture(tmp_path)
    rows = report["private_test_trace"]["flows"]
    if change == "source":
        raw = raw.replace(b"192.168.56.10", b"192.168.56.12")
    elif change == "missing_uid":
        rows.pop()
    elif change == "duplicate_uid":
        rows[1]["uid"] = rows[0]["uid"]
    elif change == "bad_probability":
        rows[0]["attack_probability"] = 1.5
    elif change == "bad_verdict":
        rows[0]["predicted_attack"] = not rows[0]["predicted_attack"]
    elif change == "bad_outcome":
        rows[0]["outcome_against_supplied_label"] = "true_positive"
        rows[0]["operator_supplied_label"] = 0
    elif change == "bad_counts":
        report["test_metrics"]["fp"] += 1
    elif change == "bad_threshold":
        report["private_test_trace"]["selected_threshold"] = 0.99
    elif change == "wrong_mode":
        report["private_test_trace"]["mode"] = "live_capture"
    elif change == "wrong_schema":
        report["private_test_trace"]["feature_schema_version"] = -1
    elif change == "missing_manifest":
        report.pop("input_manifest_sha256")
    with pytest.raises(ValueError):
        review_private_zeek_trace(raw, _encode(report))


@pytest.mark.parametrize("mutation", [
    "precision", "recall", "f1", "false_positive_rate",
    "missing_rate", "boolean_rate", "string_rate", "negative_rate",
])
def test_private_trace_rejects_inconsistent_or_invalid_heldout_rates(tmp_path, mutation):
    raw, report = _fixture(tmp_path)
    metrics = report["test_metrics"]
    if mutation == "missing_rate":
        metrics.pop("precision")
    elif mutation == "boolean_rate":
        metrics["precision"] = True
    elif mutation == "string_rate":
        metrics["precision"] = "NaN"
    elif mutation == "negative_rate":
        metrics["precision"] = -0.1
    else:
        original = metrics[mutation]
        metrics[mutation] = 0.0 if original != 0.0 else 1.0
    with pytest.raises(ValueError, match="rate mismatch"):
        review_private_zeek_trace(raw, _encode(report))



@pytest.mark.parametrize("mutation", [
    "missing_section", "missing_interval", "changed_successes",
    "changed_trials", "changed_lower", "changed_upper", "changed_estimate",
    "changed_method", "changed_warning", "bool_count", "extra_key",
    "null_interval", "wrong_unit",
])
def test_private_trace_rejects_tampered_heldout_wilson_intervals(tmp_path, mutation):
    raw, report = _fixture(tmp_path)
    diagnostic = report["test_detection_uncertainty"]
    recall = diagnostic["attack_recall"]  # one positive label: defined interval
    if mutation == "missing_section":
        report.pop("test_detection_uncertainty")
    elif mutation == "missing_interval":
        diagnostic.pop("attack_recall")
    elif mutation == "changed_successes":
        recall["successes"] += 1
    elif mutation == "changed_trials":
        recall["trials"] += 1
    elif mutation == "changed_lower":
        recall["lower"] = 0.123456789
    elif mutation == "changed_upper":
        recall["upper"] = 0.876543211
    elif mutation == "changed_estimate":
        recall["estimate"] = 0.333333
    elif mutation == "changed_method":
        recall["method"] = "normal_approximation"
    elif mutation == "changed_warning":
        diagnostic["small_denominator_warning"] = False
    elif mutation == "bool_count":
        recall["trials"] = True
    elif mutation == "extra_key":
        diagnostic["unverified_confidence"] = 1.0
    elif mutation == "null_interval":
        recall["lower"] = None
    elif mutation == "wrong_unit":
        diagnostic["unit_of_analysis"] = "independent_host"
    with pytest.raises(ValueError, match="Wilson uncertainty mismatch"):
        review_private_zeek_trace(raw, _encode(report))

def test_trace_input_size_and_duplicate_json_keys_refused(tmp_path):
    raw, report = _fixture(tmp_path)
    with pytest.raises(ValueError, match="bounded"):
        review_private_zeek_trace(raw, b"x" * (16 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="Duplicate"):
        review_private_zeek_trace(raw, b'{"report_version":4,"report_version":4}')
    with pytest.raises(ValueError, match="Non-finite"):
        review_private_zeek_trace(raw, b'{"probability":NaN}')
    with pytest.raises((UnicodeError, ValueError)):
        review_private_zeek_trace(raw, b"\xff")


def test_test_label_reassignment_does_not_change_review_predictions(tmp_path):
    raw, report = _fixture(tmp_path)
    first = review_private_zeek_trace(raw, _encode(report))
    for row in report["private_test_trace"]["flows"]:
        row["operator_supplied_label"] = 1 - row["operator_supplied_label"]
        row["outcome_against_supplied_label"] = (
            "true_positive" if row["predicted_attack"] else "false_negative"
        ) if row["operator_supplied_label"] == 1 else (
            "false_positive" if row["predicted_attack"] else "true_negative"
        )
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    mapping = {"true_positive": "tp", "false_positive": "fp",
               "true_negative": "tn", "false_negative": "fn"}
    for row in report["private_test_trace"]["flows"]:
        counts[mapping[row["outcome_against_supplied_label"]]] += 1
    report["test_metrics"].update(counts)
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    report["test_metrics"].update({
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
    })
    report["test_detection_uncertainty"] = summarize_detection_uncertainty(
        report["test_metrics"]
    )
    second = review_private_zeek_trace(raw, _encode(report))
    assert first == second  # review exposes no ground truth and does not retrain


def test_no_database_or_artifact_written(tmp_path):
    raw, report = _fixture(tmp_path)
    before = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    review_private_zeek_trace(raw, _encode(report))
    after = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    assert before == after


@pytest.mark.parametrize("mutation", [
    "missing_provenance", "wrong_source", "wrong_flow_count",
    "duplicate_source", "bool_flow_count", "wrong_feature_schema",
])
def test_private_trace_requires_aggregate_heldout_provenance(tmp_path, mutation):
    raw, report = _fixture(tmp_path)
    test = report["provenance"]["test"]
    if mutation == "missing_provenance":
        report.pop("provenance")
    elif mutation == "wrong_source":
        test["source_sha256"] = ["0" * 64]
    elif mutation == "wrong_flow_count":
        test["flows"] += 1
    elif mutation == "duplicate_source":
        test["source_sha256"].append(test["source_sha256"][0])
    elif mutation == "bool_flow_count":
        test["flows"] = True
    elif mutation == "wrong_feature_schema":
        report["feature_schema_version"] = -1
    with pytest.raises(ValueError):
        review_private_zeek_trace(raw, _encode(report))


def test_private_trace_accepts_genuine_synthetic_experiment_provenance(tmp_path):
    raw, report = _fixture(tmp_path)
    test = report["provenance"]["test"]
    assert test["flows"] == len(report["private_test_trace"]["flows"])
    assert test["source_sha256"] == [hashlib.sha256(raw).hexdigest()]
    reviewed = review_private_zeek_trace(raw, _encode(report))
    assert reviewed["source_join_verified"] is True
    assert reviewed["model_provenance_authenticated"] is False


def test_private_trace_accepts_v4_v5_and_current_v6_but_refuses_other_versions(tmp_path):
    raw, report = _fixture(tmp_path)
    assert report["report_version"] == 6
    current = review_private_zeek_trace(raw, _encode(report))
    for compatible in (4, 5):  # Previously generated private traces remain readable.
        report["report_version"] = compatible
        assert review_private_zeek_trace(raw, _encode(report)) == current
    for invalid in (3, 7, True, 6.0, "6"):
        report["report_version"] = invalid
        with pytest.raises(ValueError, match="Unsupported offline Zeek research report"):
            review_private_zeek_trace(raw, _encode(report))
