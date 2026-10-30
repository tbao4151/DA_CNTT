"""CI-only acceptance: real Zeek importer output -> pinned research scoring -> review.

Uses a model FIT on deliberately synthetic, operator-supplied labels. This is
a software integration check, NOT a trained attack detector or lab experiment.
No socket, active Red Team, operational alert, SOC write, or benchmark change.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

from blue_team_ai.model_artifact import build_zeek_research_artifact, validate_zeek_research_artifact
from blue_team_ai.pcap_zeek_tuple import corroborate_pcap_zeek_tuples
from blue_team_ai.zeek_smoke import verify_fixture_feature_projection
from siem_ai.case_report import export_case_report
from siem_ai.core import list_cases
from test_zeek_offline_baseline import _dataset
from ci_real_zeek_production_timestamp import exercise_production_timestamp_gate

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


def validate_ci_synthetic_case(
    export: dict[str, object], *, log_sha: str, model_sha: str,
    import_sha: str,
) -> None:
    """Require a human-gated Unclassified case, never a confirmed attack."""
    case = export.get("case")
    evidence = export.get("flow_evidence")
    events = export.get("case_events")
    if not isinstance(case, dict) or not isinstance(evidence, dict) or not isinstance(events, list):
        raise ValueError("Synthetic SOC case export structure invalid")
    note = case.get("analyst_note")
    if (
        export.get("report_type") != "DA005 educational SOC case"
        or "not signed" not in str(export.get("integrity_notice", ""))
        or type(case.get("case_id")) is not int
        or case["case_id"] < 1
        or case.get("verdict") != "Unclassified"
        or case.get("confidence") is not None
        or case.get("state") != "New"
        or not isinstance(note, str)
        or "NOT a verified attack or operational AI alert" not in note
        or "ground truth are unverified" not in note
        or f"source_sha256={log_sha}" not in note
        or f"model_sha256={model_sha}" not in note
        or f"import_report_sha256={import_sha}" not in note
        or evidence.get("source_sha256") != log_sha
        or any(key in evidence for key in ("label", "attack_cat", "AI_verdict", "AI_attack_probability"))
        or len(events) != 1
        or not isinstance(events[0], dict)
        or events[0].get("new_state") != "New"
        or events[0].get("old_state") is not None
        or type(events[0].get("event_id")) is not int
        or events[0]["event_id"] < 1
    ):
        failed = {
            "type": export.get("report_type") != "DA005 educational SOC case",
            "notice": "not signed" not in str(export.get("integrity_notice", "")),
            "case_id": type(case.get("case_id")) is not int or case.get("case_id", 0) < 1,
            "verdict": case.get("verdict") != "Unclassified",
            "confidence": case.get("confidence") is not None,
            "state": case.get("state") != "New",
            "note": not isinstance(note, str) or any(
                phrase not in note for phrase in (
                    "NOT a verified attack or operational AI alert",
                    "ground truth are unverified",
                    f"source_sha256={log_sha}",
                    f"model_sha256={model_sha}",
                    f"import_report_sha256={import_sha}",
                )
            ),
            "evidence_sha": evidence.get("source_sha256") != log_sha,
            "derived_fields": any(
                key in evidence for key in ("label", "attack_cat", "AI_verdict", "AI_attack_probability")
            ),
            "audit_count": len(events) != 1,
            "audit_event": not events or not isinstance(events[0], dict)
                or events[0].get("new_state") != "New"
                or events[0].get("old_state") is not None
                or type(events[0].get("event_id")) is not int
                or events[0]["event_id"] < 1,
        }
        raise ValueError(
            "Synthetic SOC case must remain unclassified and auditable; invalid fields: "
            + ",".join(name for name, bad in failed.items() if bad)
        )


def _command(argv: list[str], *, should_succeed: bool) -> None:
    completed = subprocess.run(
        [sys.executable, *argv], capture_output=True, text=True,
        check=False, timeout=60,
    )
    if (completed.returncode == 0) != should_succeed:
        raise ValueError("CI synthetic scoring/review acceptance failed")



def verify_synthetic_timestamp_gate_before_scoring(
    pcap_data: bytes, log_data: bytes,
) -> dict[str, object]:
    """CI-only: check real Zeek time alignment before research scoring.

    A timestamp-shifted copy retains the exact packet payload and five-tuples.
    The legacy tuple check must still pass, but the opt-in time check must
    refuse it. This is NOT a provenance, isolation or attack-label attestation.
    """
    accepted = corroborate_pcap_zeek_tuples(
        pcap_data, log_data, require_timestamp_corroboration=True,
    )
    if (accepted["matched_zeek_flow_count"] != 1
            or accepted["timestamps_correlated"] is not True
            or accepted["timestamp_corroboration_window_seconds"] != 1.0):
        raise ValueError("Real Zeek synthetic timestamp acceptance contract failed")

    # This acceptance fixture is deterministic little-endian classic PCAP.
    # Shift EVERY packet header; leaving the second packet at +1s would
    # accidentally satisfy the one-second tolerance.
    shifted = bytearray(pcap_data)
    if shifted[:4] != bytes.fromhex("d4c3b2a1"):
        raise ValueError("CI timestamp mutation requires little-endian microsecond PCAP")
    offset = 24
    shifted_count = 0
    while offset < len(shifted):
        if offset + 16 > len(shifted):
            raise ValueError("Truncated CI PCAP packet header")
        seconds, _fraction, included, _original = struct.unpack_from(
            "<IIII", shifted, offset,
        )
        if included == 0 or offset + 16 + included > len(shifted):
            raise ValueError("Invalid CI PCAP captured length")
        if seconds > 0xFFFFFFFF - 120:
            raise ValueError("CI PCAP timestamp cannot be shifted")
        struct.pack_into("<I", shifted, offset, seconds + 120)
        offset += 16 + included
        shifted_count += 1
    if shifted_count < 2 or offset != len(shifted):
        raise ValueError("Expected two or more complete CI fixture packets")
    shifted_bytes = bytes(shifted)
    legacy = corroborate_pcap_zeek_tuples(shifted_bytes, log_data)
    if legacy["matched_zeek_flow_count"] != 1:
        raise ValueError("Shifted fixture unexpectedly changed its five-tuple")
    try:
        corroborate_pcap_zeek_tuples(
            shifted_bytes, log_data, require_timestamp_corroboration=True,
        )
    except ValueError as exc:
        if "within one second" not in str(exc):
            raise
    else:
        raise ValueError("Timestamp gate accepted the 120-second-shifted fixture")
    return accepted


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
    # Fail before model fitting, scoring or the disposable manual SOC write.
    timestamp_gate = verify_synthetic_timestamp_gate_before_scoring(
        pcap.read_bytes(), log.read_bytes(),
    )

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
    production_timestamp = exercise_production_timestamp_gate(
        root=root, model=model, model_sha=model_sha,
        log=log, log_sha=log_sha, pcap=pcap,
        import_report=import_report, import_sha=import_sha,
        baseline_report=report,
    )
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

    # Preserve the original FITTED synthetic-model scoring above. A separate,
    # deliberately neutralized fixture-only data artifact guarantees one
    # candidate so the explicit manual SOC write boundary can be exercised.
    # Neutral coefficients and a 0.49 threshold are NOT trained attack detection.
    neutral = copy.deepcopy(artifact)
    neutral["intercept"] = 0.0
    neutral["selected_threshold"] = 0.49
    for entries in neutral["categorical_adjustments"].values():
        for key in entries:
            entries[key] = 0.0
    for params in neutral["numeric_parameters"].values():
        params["weight"] = 0.0
    validate_zeek_research_artifact(neutral)
    manual_model = root / "ci_neutral_model_not_for_research.json"
    manual_model_bytes = (json.dumps(neutral, sort_keys=True, allow_nan=False) + "\n").encode()
    with manual_model.open("xb") as stream:
        stream.write(manual_model_bytes)
    manual_model_sha = _sha(manual_model_bytes)
    manual_prediction = imported / "ci_neutral_model_predictions.json"
    manual_common = common.copy()
    manual_common[manual_common.index("--model") + 1] = str(manual_model)
    manual_common[manual_common.index("--expected-model-sha256") + 1] = manual_model_sha
    _command([
        str(ROOT / "scripts" / "score_zeek_new_log.py"),
        *manual_common, "--output", str(manual_prediction),
    ], should_succeed=True)
    manual_report = json.loads(manual_prediction.read_text(encoding="utf-8"))
    validate_research_only_report(
        manual_report, log_sha=log_sha, model_sha=manual_model_sha,
    )
    if manual_report["research_candidate_count"] != 1:
        raise ValueError("Neutral CI-only fixture did not produce one candidate")
    _command([
        str(ROOT / "scripts" / "verify_zeek_new_log_report.py"),
        *manual_common, "--report", str(manual_prediction),
    ], should_succeed=True)

    # Confirmations refer ONLY to the owned synthetic fixture, not a real
    # VMware capture, attack, independent ground truth or holdout evidence.
    triage = [
        str(ROOT / "scripts" / "triage_zeek_new_log.py"),
        *manual_common, "--report", str(manual_prediction),
    ]
    db = root / "ci_synthetic_manual_soc.sqlite3"
    _command([*triage, "--list-candidates"], should_succeed=True)
    if db.exists():
        raise ValueError("Read-only candidate listing created a SOC database")
    manual = [
        *triage, "--record-index", "0", "--db", str(db),
        "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture",
    ]
    _command(manual, should_succeed=True)
    cases = list_cases(db)
    if len(cases) != 1:
        raise ValueError("Manual synthetic triage must create exactly one case")
    case_id = int(cases.iloc[0]["case_id"])
    case_export = json.loads(export_case_report(db, case_id))
    validate_ci_synthetic_case(
        case_export, log_sha=log_sha, model_sha=manual_model_sha, import_sha=import_sha,
    )
    _command(manual, should_succeed=True)
    if len(list_cases(db)) != 1:
        raise ValueError("Repeated manual review must reuse the same case")

    # A modified PCAP must fail before creating a case in a fresh database.
    # Keep original PCAP, log, predictions and importer report untouched.
    tampered_pcap = root / "ci_modified_pcap_expected_rejection.pcap"
    with tampered_pcap.open("xb") as stream:
        stream.write(pcap.read_bytes() + b"tampered-after-scoring")
    refused_db = root / "ci_refused_soc.sqlite3"
    bad_triage = manual.copy()
    bad_triage[bad_triage.index("--offline-import-pcap") + 1] = str(tampered_pcap)
    bad_triage[bad_triage.index("--db") + 1] = str(refused_db)
    _command(bad_triage, should_succeed=False)
    if refused_db.exists():
        raise ValueError("Tampered PCAP produced a SOC database")
    no_confirm = [arg for arg in manual if arg != "--confirm-reviewed"]
    _command(no_confirm, should_succeed=False)

    summary = {
        "source_kind": "synthetic_benign_udp_fixture",
        "execution": "real_zeek_importer_then_production_pinned_scoring_and_review_ci",
        "model_origin": "CI-only fitted synthetic labels; not independent ground truth",
        "model_sha256": model_sha,
        "zeek_conn_sha256": log_sha,
        "offline_import_report_sha256": import_sha,
        "flow_count": report["flow_count"],
        "pcap_zeek_timestamp_presence_verified_ci_only": True,
        **production_timestamp,
        "pcap_zeek_timestamp_window_seconds": timestamp_gate["timestamp_corroboration_window_seconds"],
        "shifted_pcap_tuple_only_accepted_ci_only": True,
        "shifted_pcap_timestamp_gate_rejected_ci_only": True,
        "pcap_to_zeek_derivation_proven": False,
        "research_scoring_executed": True,
        "independent_prediction_recomputation_passed": True,
        "tampered_probability_rejected": True,
        "wrong_model_pin_rejected": True,
        "synthetic_manual_model_sha256": manual_model_sha,
        "synthetic_manual_model_origin": "CI-only neutralized coefficients and 0.49 threshold; not a trained detector",
        "synthetic_manual_soc_case_created": True,
        "synthetic_manual_case_unclassified_verified": True,
        "synthetic_manual_case_idempotency_verified": True,
        "tampered_pcap_soc_write_rejected": True,
        "missing_analyst_confirmation_rejected": True,
        "pins_independently_preregistered": False,
        "vmware_capture_performed": False,
        "host_only_isolation_verified": False,
        "attack_ground_truth_verified": False,
        "operational_attack_detection_verified": False,
        "soc_case_created": False,
        "operational_soc_case_created": False,
        "automated_alerts": False,
        "interpretation": (
            "Actual Zeek decoded a benign synthetic PCAP in GitHub CI; a CI-only "
            "model fitted on synthetic labels exercised research scoring and "
            "review. No independent model/label validity, attack detection, "
            "real Host-only capture, operational SOC response or Windows acceptance. "
            "One manually confirmed Unclassified synthetic-only case was "
            "created in a disposable CI SQLite database, never uploaded."
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
