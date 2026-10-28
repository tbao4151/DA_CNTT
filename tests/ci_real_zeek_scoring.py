"""CI-only acceptance: real Zeek importer output -> pinned research scoring -> review.

Uses a model FIT on deliberately synthetic, operator-supplied labels. This is
a software integration check, NOT a trained attack detector or lab experiment.
No socket, active Red Team, operational alert, SOC write, or benchmark change.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from blue_team_ai.model_artifact import build_zeek_research_artifact
from blue_team_ai.zeek_smoke import verify_fixture_feature_projection
from test_zeek_offline_baseline import _dataset

ROOT = Path(__file__).resolve().parents[1]
CIDR = "192.168.56.0/24"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_research_only_report(
    report: dict[str, object], *, log_sha: str, model_sha: str,
) -> None:
    """Fail closed if the CI result looks like live/verified attack evidence."""
    if (
        report.get("mode") != "offline_new_zeek_research_inference_only"
        or report.get("origin") != "offline_zeek_log"
        or report.get("source_sha256") != log_sha
        or report.get("model_sha256") != model_sha
        or type(report.get("flow_count")) is not int
        or report["flow_count"] != 1
        or type(report.get("research_candidate_count")) is not int
        or report["research_candidate_count"] not in (0, 1)
        or not isinstance(report.get("predictions"), list)
        or len(report["predictions"]) != 1
        or type(report["predictions"][0].get("research_candidate")) is not bool
        or report["research_candidate_count"] != int(report["predictions"][0]["research_candidate"])
        or type(report["predictions"][0].get("attack_probability")) is not float
        or not 0 <= report["predictions"][0]["attack_probability"] <= 1
        or any(report.get(flag) is not False for flag in (
            "labels_used", "test_partition_exclusion_verified",
            "host_only_isolation_verified", "capture_authenticity_verified",
            "model_authorship_verified", "operational_attack_detection_verified",
            "automated_alerts", "soc_cases_created", "live_capture",
        ))
    ):
        raise ValueError("Synthetic-only research scoring contract violated")


def _command(argv: list[str], *, should_succeed: bool) -> None:
    completed = subprocess.run(
        [sys.executable, *argv], capture_output=True, text=True,
        check=False, timeout=60,
    )
    if (completed.returncode == 0) != should_succeed:
        raise ValueError("CI synthetic scoring/review acceptance failed")


def run(root: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    if root.is_relative_to(ROOT) or not root.is_dir():
        raise ValueError("CI evidence must be in an existing private temp directory")
    pcap = root / "benign_synthetic.pcap"
    imported = root / "importer-real"
    log = imported / "conn.log"
    import_report = imported / "offline_import_report.json"
    verify_fixture_feature_projection(log)
    if not pcap.is_file() or not import_report.is_file():
        raise ValueError("Real Zeek production importer evidence is required")

    # This model is fitted on test fixtures with arbitrary synthetic labels.
    # It is NEVER an independently labeled, trusted, deployable research model.
    artifact = build_zeek_research_artifact(
        _dataset(), input_manifest_sha256="a" * 64,
    )
    model = root / "ci_synthetic_model_not_for_use.json"
    model_bytes = (json.dumps(artifact, sort_keys=True, allow_nan=False) + "\n").encode()
    with model.open("xb") as stream:
        stream.write(model_bytes)
    model_sha = _sha(model_bytes)
    log_sha = _sha(log.read_bytes())
    import_sha = _sha(import_report.read_bytes())
    prediction = imported / "ci_synthetic_predictions.json"
    common = [
        "--model", str(model), "--expected-model-sha256", model_sha,
        "--log", str(log), "--expected-log-sha256", log_sha,
        "--cidr", CIDR,
        "--offline-import-report", str(import_report),
        "--expected-offline-import-report-sha256", import_sha,
        "--offline-import-pcap", str(pcap),
    ]
    _command([
        str(ROOT / "scripts" / "score_zeek_new_log.py"), *common,
        "--output", str(prediction),
    ], should_succeed=True)
    report = json.loads(prediction.read_text(encoding="utf-8"))
    validate_research_only_report(report, log_sha=log_sha, model_sha=model_sha)
    verify = [
        str(ROOT / "scripts" / "verify_zeek_new_log_report.py"),
        *common, "--report", str(prediction),
    ]
    _command(verify, should_succeed=True)

    # An attacker changing a probability must fail the independent recompute.
    tampered = imported / "ci_tampered_predictions_expected_rejection.json"
    modified = json.loads(prediction.read_text(encoding="utf-8"))
    probability = modified["predictions"][0]["attack_probability"]
    modified["predictions"][0]["attack_probability"] = 0.0 if probability != 0.0 else 1.0
    with tampered.open("x", encoding="utf-8") as stream:
        json.dump(modified, stream, allow_nan=False)
    _command(verify[:-1] + [str(tampered)], should_succeed=False)

    # A model SHA mismatch must fail before any new prediction file is written.
    blocked = imported / "ci_blocked_model_pin.json"
    wrong_pin = common.copy()
    wrong_pin[wrong_pin.index("--expected-model-sha256") + 1] = "0" * 64
    _command([
        str(ROOT / "scripts" / "score_zeek_new_log.py"), *wrong_pin,
        "--output", str(blocked),
    ], should_succeed=False)
    if blocked.exists():
        raise ValueError("Scorer wrote an output despite invalid model pin")

    summary = {
        "source_kind": "synthetic_benign_udp_fixture",
        "execution": "real_zeek_importer_then_production_pinned_scoring_and_review_ci",
        "model_origin": "CI-only fitted synthetic labels; not independent ground truth",
        "model_sha256": model_sha,
        "zeek_conn_sha256": log_sha,
        "offline_import_report_sha256": import_sha,
        "flow_count": report["flow_count"],
        "research_scoring_executed": True,
        "independent_prediction_recomputation_passed": True,
        "tampered_probability_rejected": True,
        "wrong_model_pin_rejected": True,
        "pins_independently_preregistered": False,
        "vmware_capture_performed": False,
        "host_only_isolation_verified": False,
        "attack_ground_truth_verified": False,
        "operational_attack_detection_verified": False,
        "soc_case_created": False,
        "automated_alerts": False,
        "interpretation": (
            "Actual Zeek decoded a benign synthetic PCAP in GitHub CI; a CI-only "
            "model fitted on synthetic labels exercised research scoring and "
            "review. No independent model/label validity, attack detection, "
            "real Host-only capture, SOC response or Windows acceptance."
        ),
    }
    with (root / "ci_real_zeek_scoring_report.json").open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.root), indent=2, ensure_ascii=False))
