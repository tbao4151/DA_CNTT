"""CI-only real-Zeek synthetic PCAP -> pinned research queue -> manual SOC.

The original Zeek log comes from a network-disabled container. The declared
TRAIN/VALIDATION/TEST manifest and model are synthetic test fixtures. This
does NOT validate labels, operational attack detection, VMware or latency.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from siem_ai.case_report import export_case_report
from siem_ai.core import list_cases
from test_zeek_new_log_scoring_partition_gate import _setup

ROOT = Path(__file__).resolve().parents[1]
CIDR = "192.168.56.0/24"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _command(argv: list[str], *, succeed: bool = True) -> str:
    proc = subprocess.run(
        [sys.executable, *argv], capture_output=True, text=True,
        check=False, timeout=90,
    )
    if (proc.returncode == 0) != succeed:
        raise ValueError("CI-only real-Zeek research queue handoff contract failed")
    return proc.stdout


def validate_ci_queue_bundle(
    bundle: dict[str, object], *, log_sha: str, model_sha: str,
    manifest_sha: str,
) -> dict[str, object]:
    """Reject any interpretation of the forced candidate as a real alert."""
    rows = bundle.get("research_alerts")
    if (
        bundle.get("mode") != "offline_zeek_research_alert_candidates_only"
        or bundle.get("origin") != "offline_zeek_log"
        or bundle.get("source_sha256") != log_sha
        or bundle.get("model_sha256") != model_sha
        or bundle.get("manifest_sha256") != manifest_sha
        or bundle.get("flow_count") != 1
        or bundle.get("research_alert_candidates_exported") != 1
        or bundle.get("research_candidate_count_total") != 1
        or bundle.get("declared_partition_and_flow_identity_nonreuse_checked") is not True
        or not isinstance(rows, list) or len(rows) != 1
        or not isinstance(rows[0], dict)
        or type(rows[0].get("record_index")) is not int
        or rows[0]["record_index"] != 0
        or rows[0].get("status") != "pending_manual_research_review"
        or rows[0].get("confirmed_attack") is not False
        or rows[0].get("soc_case_id") is not None
        or not isinstance(rows[0].get("research_alert_ref"), str)
        or len(rows[0]["research_alert_ref"]) != 64
        or any(c not in "0123456789abcdef" for c in rows[0]["research_alert_ref"])
        or any(bundle.get(key) is not False for key in (
            "independent_partition_history_verified",
            "independent_ground_truth_verified", "vmware_isolation_verified",
            "capture_authenticity_verified", "operational_alerts_created",
            "soc_cases_created", "live_capture",
        ))
    ):
        raise ValueError("CI synthetic research queue contract violated")
    return rows[0]



def validate_ci_empty_queue_bundle(
    bundle: dict[str, object], *, log_sha: str, model_sha: str,
    manifest_sha: str,
) -> None:
    """The CI-only zero-candidate path must never imply a SOC alert."""
    if (
        not isinstance(bundle, dict)
        or bundle.get("mode") != "offline_zeek_research_alert_candidates_only"
        or bundle.get("origin") != "offline_zeek_log"
        or bundle.get("source_sha256") != log_sha
        or bundle.get("model_sha256") != model_sha
        or bundle.get("manifest_sha256") != manifest_sha
        or type(bundle.get("flow_count")) is not int
        or bundle["flow_count"] != 1
        or type(bundle.get("research_alert_candidates_exported")) is not int
        or bundle["research_alert_candidates_exported"] != 0
        or type(bundle.get("research_candidate_count_total")) is not int
        or bundle["research_candidate_count_total"] != 0
        or bundle.get("research_alerts") != []
        or bundle.get("declared_partition_and_flow_identity_nonreuse_checked") is not True
        or any(bundle.get(key) is not False for key in (
            "independent_partition_history_verified",
            "independent_ground_truth_verified", "vmware_isolation_verified",
            "capture_authenticity_verified", "operational_alerts_created",
            "soc_cases_created", "live_capture",
        ))
    ):
        raise ValueError("CI synthetic empty research queue contract violated")


def exercise_real_zeek_queue_handoff(
    *, root: Path, log: Path, pcap: Path, import_report: Path,
) -> dict[str, object]:
    """Exercise real Zeek bytes through production score/export/triage/verify."""
    manifest, model_path, _unused_fixture_log, _unused_output = _setup(
        root / "ci_queue_declared_synthetic_partitions"
    )
    # Neutralize every coefficient to guarantee 0.5 on the benign fixture.
    # The threshold is CI-only, NOT a validation-selected operating point.
    model = json.loads(model_path.read_text(encoding="utf-8"))
    model["intercept"] = 0.0
    model["selected_threshold"] = 0.49
    for entries in model["categorical_adjustments"].values():
        for key in entries:
            entries[key] = 0.0
    for params in model["numeric_parameters"].values():
        params["weight"] = 0.0
    model_path.write_text(json.dumps(model, allow_nan=False), encoding="utf-8")

    model_sha = _sha(model_path.read_bytes())
    log_sha = _sha(log.read_bytes())
    manifest_sha = _sha(manifest.read_bytes())
    import_sha = _sha(import_report.read_bytes())
    common = [
        "--model", str(model_path), "--expected-model-sha256", model_sha,
        "--log", str(log), "--expected-log-sha256", log_sha,
        "--manifest", str(manifest), "--expected-manifest-sha256", manifest_sha,
        "--cidr", CIDR,
    ]
    import_flags = [
        "--offline-import-report", str(import_report),
        "--expected-offline-import-report-sha256", import_sha,
        "--offline-import-pcap", str(pcap),
    ]
    score_path = log.parent / "ci_pinned_queue_score.json"
    _command([
        str(ROOT / "scripts" / "score_zeek_new_log.py"),
        *common, *import_flags, "--output", str(score_path),
    ])
    scored = json.loads(score_path.read_text(encoding="utf-8"))
    if (
        scored.get("research_candidate_count") != 1
        or scored.get("test_partition_exclusion_verified") is not False
        or scored.get("operational_attack_detection_verified") is not False
        or scored.get("automated_alerts") is not False
    ):
        raise ValueError("CI synthetic queue scorer misrepresented a candidate")
    _command([
        str(ROOT / "scripts" / "verify_zeek_new_log_report.py"),
        *common[:8], "--cidr", CIDR, *import_flags,
        "--report", str(score_path),
    ])

    queue_path = log.parent / "ci_pinned_research_queue.json"
    _command([
        str(ROOT / "scripts" / "export_zeek_research_alerts.py"),
        *common, "--report", str(score_path),
        "--expected-report-sha256", _sha(score_path.read_bytes()),
        "--output", str(queue_path),
    ])
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    selected = validate_ci_queue_bundle(
        queue, log_sha=log_sha, model_sha=model_sha, manifest_sha=manifest_sha,
    )
    original_log_bytes = log.read_bytes()
    original_pcap_bytes = pcap.read_bytes()
    original_import_bytes = import_report.read_bytes()
    queue_sha = _sha(queue_path.read_bytes())
    db = root / "ci_pinned_queue_manual_soc.sqlite3"
    triage = [
        str(ROOT / "scripts" / "triage_zeek_new_log.py"),
        *common, *import_flags, "--report", str(score_path),
        "--record-index", "0", "--db", str(db),
        "--research-alert-bundle", str(queue_path),
        "--expected-research-alert-bundle-sha256", queue_sha,
        "--research-alert-ref", selected["research_alert_ref"],
        "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture",
    ]
    if db.exists():
        raise ValueError("Synthetic queue SOC database unexpectedly exists")
    # A wrong selection must not create a database even with all confirmations.
    refused_db = root / "ci_wrong_queue_ref_expected_rejection.sqlite3"
    wrong = triage.copy()
    wrong[wrong.index("--db") + 1] = str(refused_db)
    wrong[wrong.index("--research-alert-ref") + 1] = "0" * 64
    _command(wrong, succeed=False)
    if refused_db.exists() or db.exists():
        raise ValueError("Invalid research queue selection created a SOC database")

    _command(triage)
    cases = list_cases(db)
    if len(cases) != 1:
        raise ValueError("Expected exactly one synthetic manual queue case")
    case_id = int(cases.iloc[0]["case_id"])
    exported = json.loads(export_case_report(db, case_id))
    case = exported.get("case", {})
    note = case.get("analyst_note", "")
    if (
        case.get("verdict") != "Unclassified"
        or case.get("confidence") is not None
        or case.get("state") != "New"
        or f"bundle_sha256={queue_sha}" not in note
        or f"research_alert_ref={selected['research_alert_ref']}" not in note
        or len(exported.get("case_events", [])) != 1
    ):
        raise ValueError("Synthetic research queue case was not auditable")
    _command(triage)
    if len(list_cases(db)) != 1:
        raise ValueError("Repeat manual queue review created duplicate case")

    verify = [
        str(ROOT / "scripts" / "verify_zeek_soc_case_link.py"),
        *common, *import_flags, "--report", str(score_path),
        "--db", str(db), "--case-id", str(case_id), "--record-index", "0",
        "--research-alert-bundle", str(queue_path),
        "--expected-research-alert-bundle-sha256", queue_sha,
        "--research-alert-ref", selected["research_alert_ref"],
        "--require-pcap-framing", "--require-pcap-zeek-tuples",
        "--require-pcap-zeek-timestamps", "--timing-json",
    ]
    original_db = db.read_bytes()
    verified = json.loads(_command(verify))
    if (
        verified.get("pinned_research_queue_reverified") is not True
        or verified.get("pinned_research_queue_creation_audit_verified") is not True
        or verified.get("sqlite_read_only") is not True
        or verified.get("pcap_zeek_timestamps_corroborated") is not True
        or verified.get("operational_alert_verified") is not False
        or verified.get("event_to_soc_case_latency_measured") is not False
        or db.read_bytes() != original_db
    ):
        raise ValueError("Pinned synthetic queue SOC read-only link failed")

    wrong_verify = verify.copy()
    wrong_verify[wrong_verify.index("--expected-research-alert-bundle-sha256") + 1] = "0" * 64
    _command(wrong_verify, succeed=False)
    if db.read_bytes() != original_db:
        raise ValueError("Failed queue verifier modified the original SOC database")

    # Negative integration path: identical actual-Zeek bytes, declared
    # partitions and neutral coefficients, but a CI-only threshold of 0.51.
    # Probability 0.5 must yield ZERO candidates and no SOC write, even if
    # an operator supplies every confirmation and a fabricated queue ref.
    # This is a software control, NOT a specificity/false-positive metric.
    empty_model = json.loads(model_path.read_text(encoding="utf-8"))
    empty_model["selected_threshold"] = 0.51
    empty_model_path = root / "ci_empty_queue_model_not_for_research.json"
    with empty_model_path.open("x", encoding="utf-8") as stream:
        json.dump(empty_model, stream, allow_nan=False)
        stream.write("\n")
    empty_model_sha = _sha(empty_model_path.read_bytes())
    empty_common = common.copy()
    empty_common[empty_common.index("--model") + 1] = str(empty_model_path)
    empty_common[empty_common.index("--expected-model-sha256") + 1] = empty_model_sha
    empty_score_path = log.parent / "ci_empty_queue_score.json"
    _command([
        str(ROOT / "scripts" / "score_zeek_new_log.py"),
        *empty_common, *import_flags, "--output", str(empty_score_path),
    ])
    empty_score = json.loads(empty_score_path.read_text(encoding="utf-8"))
    if (
        empty_score.get("research_candidate_count") != 0
        or empty_score.get("flow_count") != 1
        or not isinstance(empty_score.get("predictions"), list)
        or len(empty_score["predictions"]) != 1
        or empty_score["predictions"][0].get("research_candidate") is not False
        or empty_score.get("operational_attack_detection_verified") is not False
        or empty_score.get("automated_alerts") is not False
    ):
        raise ValueError("Neutral CI-only no-candidate scoring contract failed")
    _command([
        str(ROOT / "scripts" / "verify_zeek_new_log_report.py"),
        *empty_common[:8], "--cidr", CIDR, *import_flags,
        "--report", str(empty_score_path),
    ])
    empty_queue_path = log.parent / "ci_empty_research_queue.json"
    _command([
        str(ROOT / "scripts" / "export_zeek_research_alerts.py"),
        *empty_common, "--report", str(empty_score_path),
        "--expected-report-sha256", _sha(empty_score_path.read_bytes()),
        "--output", str(empty_queue_path),
    ])
    validate_ci_empty_queue_bundle(
        json.loads(empty_queue_path.read_text(encoding="utf-8")),
        log_sha=log_sha, model_sha=empty_model_sha, manifest_sha=manifest_sha,
    )
    empty_db = root / "ci_empty_queue_must_not_create_soc.sqlite3"
    empty_triage = [
        str(ROOT / "scripts" / "triage_zeek_new_log.py"),
        *empty_common, *import_flags, "--report", str(empty_score_path),
        "--record-index", "0", "--db", str(empty_db),
        "--research-alert-bundle", str(empty_queue_path),
        "--expected-research-alert-bundle-sha256", _sha(empty_queue_path.read_bytes()),
        "--research-alert-ref", "0" * 64,
        "--confirm-reviewed", "--confirm-authorized", "--confirm-new-capture",
    ]
    if empty_db.exists():
        raise ValueError("No-candidate SOC database already exists")
    _command(empty_triage, succeed=False)
    if empty_db.exists() or db.read_bytes() != original_db:
        raise ValueError("No-candidate research queue caused a SOC write")
    if (
        log.read_bytes() != original_log_bytes
        or pcap.read_bytes() != original_pcap_bytes
        or import_report.read_bytes() != original_import_bytes
    ):
        raise ValueError("No-candidate path modified original Zeek/PCAP evidence")
    return {
        "real_zeek_synthetic_pinned_queue_export_verified": True,
        "real_zeek_synthetic_queue_to_manual_unclassified_soc_verified": True,
        "real_zeek_synthetic_queue_soc_readonly_link_verified": True,
        "wrong_queue_selection_refused_before_soc_write": True,
        "wrong_queue_pin_refused_without_soc_mutation": True,
        "queue_model_threshold_forced_ci_only": True,
        "real_zeek_synthetic_zero_candidate_queue_verified": True,
        "zero_candidate_manual_soc_write_refused": True,
        "zero_candidate_model_threshold_forced_ci_only": True,
        "queue_attack_ground_truth_verified": False,
        "queue_operational_alert_verified": False,
        "queue_live_capture": False,
    }
