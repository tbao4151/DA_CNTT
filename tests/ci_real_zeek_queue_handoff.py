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
        or rows[0].get("record_index") != 0
        or rows[0].get("status") != "pending_manual_research_review"
        or rows[0].get("confirmed_attack") is not False
        or rows[0].get("soc_case_id") is not None
        or not isinstance(rows[0].get("research_alert_ref"), str)
        or len(rows[0]["research_alert_ref"]) != 64
        or any(bundle.get(key) is not False for key in (
            "independent_partition_history_verified",
            "independent_ground_truth_verified", "vmware_isolation_verified",
            "capture_authenticity_verified", "operational_alerts_created",
            "soc_cases_created", "live_capture",
        ))
    ):
        raise ValueError("CI synthetic research queue contract violated")
    return rows[0]


def exercise_real_zeek_queue_handoff(
    *, root: Path, log: Path, pcap: Path, import_report: Path,
) -> dict[str, object]:
    """Exercise real Zeek bytes through production score/export/triage/verify."""
    manifest, model_path, _unused_fixture_log, _unused_output = _setup(
        root / "ci_queue_declared_synthetic_partitions"
    )
    # Threshold is deliberately forced for the benign fixture. This is NOT a
    # validation-selected operating point or evidence of a detected attack.
    model = json.loads(model_path.read_text(encoding="utf-8"))
    model["selected_threshold"] = 0.000001
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
        *common, *import_flags, "--report", str(score_path),
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
    return {
        "real_zeek_synthetic_pinned_queue_export_verified": True,
        "real_zeek_synthetic_queue_to_manual_unclassified_soc_verified": True,
        "real_zeek_synthetic_queue_soc_readonly_link_verified": True,
        "wrong_queue_selection_refused_before_soc_write": True,
        "wrong_queue_pin_refused_without_soc_mutation": True,
        "queue_model_threshold_forced_ci_only": True,
        "queue_attack_ground_truth_verified": False,
        "queue_operational_alert_verified": False,
        "queue_live_capture": False,
    }
