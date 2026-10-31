"""Documentation inventory regression; does not validate real-world lab claims."""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATUS = (ROOT / "docs" / "SENTINEL_LAB_IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")

# Keep the official current-state inventory aligned with actual entrypoints.
@pytest.mark.parametrize("path", [
    "app.py",
    "src/siem_ai/model.py",
    "src/siem_ai/core.py",
    "pages/1_Cyber_Lab.py",
    "pages/2_Red_Team_Lab.py",
    "pages/3_New_Log_Review.py",
    "src/blue_team_ai/zeek.py",
    "src/blue_team_ai/features.py",
    "src/blue_team_ai/labeled_dataset.py",
    "src/blue_team_ai/offline_baseline.py",
    "src/blue_team_ai/new_log_inference.py",
    "src/blue_team_ai/new_log_triage.py",
    "src/blue_team_ai/research_alerts.py",
    "src/red_team_ai/scenario_policy.py",
    "src/red_team_ai/planning_audit.py",
    "src/shared/offline_handoff.py",
    "scripts/evaluate_zeek_lab.py",
    "scripts/verify_red_blue_offline_handoff.py",
    "scripts/import_offline_pcap.py",
    "scripts/verify_pcap_zeek_tuple.py",
    "scripts/check_paired_network_preflight.py",
    "docs/FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md",
    "docs/WINDOWS_PAIRED_NETWORK_PREFLIGHT.md",
    "docs/ZEEK_OFFLINE_EXPERIMENT.md",
    "docs/ZEEK_NEW_LOG_BLUE_TEAM_UI.md",
])
def test_documented_component_exists(path):
    assert (ROOT / path).is_file(), path
    assert f"`{path}`" in STATUS, path


def test_document_explicitly_distinguishes_offline_and_real_lab():
    for phrase in (
        "Execution OFF", "Unclassified", "CI", "không chứng minh",
        "Không có packet capture trực tiếp", "Chưa có bằng chứng nghiệm thu",
    ):
        assert phrase in STATUS
