"""CI-only Red/Blue handoff using the *actual Zeek* offline importer output.

The PCAP is synthetic benign traffic. The model uses synthetic training labels.
The Red proposal is not executed and has NO verified semantic link to packets.
This is integration testing, not a student VMware experiment or attack detection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.trusted_model import load_pinned_zeek_research_model
from red_team_ai.planning_audit import append_proposal, export_planning_audit
from red_team_ai.scenario_policy import choose_scenario
from shared.offline_handoff import verify_red_blue_offline_handoff

CIDR = "192.168.56.0/24"
FALSE_CLAIMS = (
    "independent_authorization_verified",
    "physical_host_only_isolation_verified",
    "capture_authenticity_verified",
    "scenario_traffic_match_verified",
    "ground_truth_verified",
    "held_out_test_exclusion_verified",
    "blue_team_detection_verified",
    "operational_alerts_created",
    "soc_cases_created",
    "red_team_execution_enabled",
    "network_access",
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_ci_handoff_summary(
    summary: dict[str, object], *,
    log_sha: str, model_sha: str, blue_sha: str,
    audit_sha: str, import_sha: str, pcap_sha: str,
) -> None:
    """Reject any apparent operational/ground-truth claim in CI output."""
    expected = {
        "zeek_conn_sha256": log_sha,
        "blue_model_sha256": model_sha,
        "blue_report_sha256": blue_sha,
        "red_audit_sha256": audit_sha,
        "offline_import_report_sha256": import_sha,
        "pcap_sha256": pcap_sha,
    }
    if (
        not isinstance(summary, dict)
        or summary.get("mode") != "offline_red_blue_research_evidence_consistency_only"
        or summary.get("handoff_version") != 1
        or any(summary.get(key) != value for key, value in expected.items())
        or type(summary.get("zeek_flow_count")) is not int
        or summary["zeek_flow_count"] != 1
        or type(summary.get("blue_research_candidate_count")) is not int
        or summary["blue_research_candidate_count"] not in (0, 1)
        or type(summary.get("red_proposal_id")) is not int
        or summary["red_proposal_id"] != 1
        or summary.get("red_scenario_id") != "baseline_web"
        or summary.get("same_pinned_zeek_source_verified") is not True
        or summary.get("red_planning_history_replayed") is not True
        or summary.get("blue_report_recomputed") is not True
        or summary.get("pcap_framing_verified") is not True
        or any(summary.get(key) is not False for key in FALSE_CLAIMS)
    ):
        raise ValueError("CI real-Zeek Red/Blue research-only handoff contract violated")
    serialized = json.dumps(summary, allow_nan=False)
    if "192.168.56." in serialized or "fixture-uid" in serialized:
        raise ValueError("CI handoff leaked private flow details")


def _cli(command: list[str], *, succeed: bool) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/verify_red_blue_offline_handoff.py"), *command],
        capture_output=True, text=True, check=False, timeout=90,
    )
    if (result.returncode == 0) != succeed:
        raise ValueError("CI Red/Blue handoff CLI unexpectedly accepted/refused evidence")
    return result


def run(root: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    if not root.is_dir() or root.is_relative_to(ROOT):
        raise ValueError("CI artifacts must be in an existing private runner directory")
    imported = root / "importer-real"
    paths = {
        "pcap": root / "benign_synthetic.pcap",
        "log": imported / "conn.log",
        "import": imported / "offline_import_report.json",
        "model": root / "ci_synthetic_model_not_for_use.json",
        "blue": imported / "ci_synthetic_predictions.json",
        "db": root / "ci_synthetic_manual_soc.sqlite3",
    }
    if not all(path.is_file() and not path.is_symlink() for path in paths.values()):
        raise ValueError("Expected real-Zeek importer, scoring and manual SOC CI artifacts")
    originals = {key: path.read_bytes() for key, path in paths.items()}
    pins = {key: _sha(data) for key, data in originals.items()}
    audit_path = root / "ci_pending_red_audit_not_executed.json"
    events = append_proposal(
        [], choose_scenario([]), seed=42,
        recorded_at_utc="2026-10-31T02:00:00+00:00",
    )
    audit_data = (
        json.dumps(export_planning_audit(events), sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    with audit_path.open("xb") as output:
        output.write(audit_data)
    audit_sha = _sha(audit_data)
    model = load_pinned_zeek_research_model(
        paths["model"], expected_sha256=pins["model"],
    )
    summary = verify_red_blue_offline_handoff(
        audit_data=audit_data,
        expected_audit_sha256=audit_sha,
        import_report_path=paths["import"],
        expected_import_report_sha256=pins["import"],
        pcap_path=paths["pcap"],
        conn_log_path=paths["log"],
        source_data=originals["log"],
        expected_log_sha256=pins["log"],
        model=model,
        model_sha256=pins["model"],
        blue_report_data=originals["blue"],
        expected_blue_report_sha256=pins["blue"],
        lab_cidrs=[CIDR],
        operator_confirmed_authorized=True,
        operator_confirmed_offline=True,
        operator_confirmed_fixture_reviewed=True,
    )
    expected = dict(
        log_sha=pins["log"], model_sha=pins["model"], blue_sha=pins["blue"],
        audit_sha=audit_sha, import_sha=pins["import"], pcap_sha=pins["pcap"],
    )
    validate_ci_handoff_summary(summary, **expected)

    command = [
        "--audit", str(audit_path), "--expected-audit-sha256", audit_sha,
        "--offline-import-report", str(paths["import"]),
        "--expected-offline-import-report-sha256", pins["import"],
        "--pcap", str(paths["pcap"]),
        "--log", str(paths["log"]), "--expected-log-sha256", pins["log"],
        "--model", str(paths["model"]), "--expected-model-sha256", pins["model"],
        "--blue-report", str(paths["blue"]),
        "--expected-blue-report-sha256", pins["blue"],
        "--cidr", CIDR,
    ]
    _cli(command, succeed=False)
    approved = command + [
        "--confirm-authorized", "--confirm-offline-only", "--confirm-fixture-reviewed",
    ]
    cli_summary = json.loads(_cli(approved, succeed=True).stdout)
    if cli_summary != summary:
        raise ValueError("CLI and library disagree on the same real Zeek source")
    _cli(
        [("0" * 64 if item == audit_sha else item) for item in approved],
        succeed=False,
    )

    # Even if a changed report is independently re-pinned, recomputation
    # must reject the altered research candidate count before any SOC write.
    tampered = json.loads(originals["blue"].decode("utf-8"))
    tampered["research_candidate_count"] = 1 - tampered["research_candidate_count"]
    tampered_path = imported / "ci_red_blue_changed_report_expected_rejection.json"
    tampered_bytes = json.dumps(tampered, allow_nan=False).encode("utf-8")
    with tampered_path.open("xb") as output:
        output.write(tampered_bytes)
    bad = approved.copy()
    bad[bad.index("--blue-report") + 1] = str(tampered_path)
    bad[bad.index("--expected-blue-report-sha256") + 1] = _sha(tampered_bytes)
    _cli(bad, succeed=False)

    if any(path.read_bytes() != originals[key] for key, path in paths.items()):
        raise ValueError("Read-only handoff modified existing Zeek/model/SOC evidence")
    if audit_path.read_bytes() != audit_data:
        raise ValueError("Red planning audit was modified during verification")
    result = {
        "source_kind": "synthetic_benign_udp_fixture_processed_by_real_zeek_in_ci",
        "execution": "offline_real_zeek_import_then_pinned_red_blue_research_handoff",
        "red_proposal_executed": False,
        "model_origin": "CI_only_synthetic_labels_not_for_research",
        "pins_independently_preregistered": False,
        "scenario_traffic_match_verified": False,
        "attack_ground_truth_verified": False,
        "vmware_capture_performed": False,
        "operational_alerts_created": False,
        "operational_soc_case_created": False,
        "red_blue_handoff_summary": summary,
        "missing_confirmation_rejected": True,
        "wrong_audit_pin_rejected": True,
        "tampered_re_pinned_blue_report_rejected": True,
        "existing_manual_soc_database_unchanged": True,
        "interpretation": (
            "Real Zeek parsed a synthetic benign PCAP in CI. Red proposal was "
            "non-executing; Blue scores used a synthetic-label model. Same-source "
            "provenance is verified, not scenario semantics, attack detection, "
            "student VMware isolation, independent labels or operational SOC."
        ),
    }
    with (root / "ci_real_zeek_red_blue_handoff_report.json").open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.root), indent=2, allow_nan=False))
