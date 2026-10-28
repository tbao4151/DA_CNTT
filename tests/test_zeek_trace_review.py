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
    second = review_private_zeek_trace(raw, _encode(report))
    assert first == second  # review exposes no ground truth and does not retrain


def test_no_database_or_artifact_written(tmp_path):
    raw, report = _fixture(tmp_path)
    before = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    review_private_zeek_trace(raw, _encode(report))
    after = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    assert before == after
