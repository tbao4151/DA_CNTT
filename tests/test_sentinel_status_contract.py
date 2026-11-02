"""Static architecture inventory guard; no VMware, network, AI fitting or SOC writes."""
from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
STATUS = ROOT / "docs" / "SENTINEL_LAB_IMPLEMENTATION_STATUS.md"

ENTRYPOINTS = (
    "app.py",
    "src/siem_ai/model.py",
    "src/blue_team_ai/zeek.py",
    "src/blue_team_ai/offline_baseline.py",
    "src/blue_team_ai/new_log_evaluation.py",
    "src/blue_team_ai/alert_burden.py",
    "src/blue_team_ai/protocol_error_analysis.py",
    "src/red_team_ai/scenario_policy.py",
    "src/shared/offline_handoff.py",
    "pages/1_Cyber_Lab.py",
    "pages/2_Red_Team_Lab.py",
    "pages/3_New_Log_Review.py",
    "scripts/verify_lab_evidence_chain.py",
    "docs/FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md",
)


def test_status_inventory_references_real_entrypoints():
    text = STATUS.read_text(encoding="utf-8")
    for path in ENTRYPOINTS:
        assert (ROOT / path).is_file(), path
        assert path in text, path


def test_status_inventory_preserves_scientific_and_safety_boundaries():
    text = STATUS.read_text(encoding="utf-8")
    for required in (
        "UNSW-NB15",
        "Dataset Mode",
        "Cyber Lab Mode",
        "offline",
        "Host-only",
        "PR #330",
        "Wilson",
        "Brier",
        "không",
        "synthetic",
        "runtime/soc_cases.sqlite3",
        "runtime/cyber_lab_cases.sqlite3",
        "FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md",
    ):
        assert required.lower() in text.lower(), required
    assert "operational live detection verified" not in text.lower()
    assert "red team execution enabled" not in text.lower()


def test_status_inventory_table_has_distinct_markdown_rows():
    text = STATUS.read_text(encoding="utf-8")
    section = text.split("## Những thành phần đã có trong repository", 1)[1]
    table = section.split("Các trang Streamlit nằm", 1)[0]
    rows = [line for line in table.splitlines() if line.strip().startswith("|")]
    assert len(rows) >= 10  # header, separator and at least eight implemented modules
    for row in rows:
        assert row.endswith("|"), row
        assert row.count("|") == 4, row  # exactly three Markdown columns
        assert r"\n|" not in row, row  # literal escape must not join two rows


def test_scientific_acceptance_matrix_is_explicit_and_has_real_contracts():
    text = STATUS.read_text(encoding="utf-8")
    matrix = text.split("## Ma trận cổng nghiệm thu khoa học", 1)[1].split(
        "## ", 1
    )[0]
    rows = [line for line in matrix.splitlines() if line.startswith("|")]
    assert len(rows) == 10  # header + separator + G1..G8
    for row in rows:
        assert row.endswith("|"), row
        assert row.count("|") == 5, row
    for gate in range(1, 9):
        matching = [row for row in rows if row.startswith(f"| G{gate} ")]
        assert len(matching) == 1, gate
        assert "CODE_PRESENT; PENDING_STUDENT_EVIDENCE" in matching[0]
    for path in (
        "scripts/check_linux_guest_combined_preflight.py",
        "scripts/import_offline_pcap.py",
        "scripts/verify_zeek_soc_case_link.py",
        "scripts/evaluate_zeek_lab.py",
        "src/blue_team_ai/new_log_evaluation.py",
        "src/blue_team_ai/research_alerts.py",
        "scripts/benchmark_zeek_new_log_runtime.py",
        "src/red_team_ai/scenario_policy.py",
    ):
        assert (ROOT / path).is_file(), path
        assert f"`{path}`" in matrix, path


def test_current_status_does_not_equate_ci_with_vmware_evidence():
    text = STATUS.read_text(encoding="utf-8")
    current = text.split("## Trạng thái kiểm chứng hiện tại", 1)[1].split(
        "## Ma trận", 1
    )[0]
    # Require an explicit GitHub snapshot without pinning this contract to a
    # particular historical PR/commit (future reconciliations must stay possible).
    assert re.search(r"`main` tại `[0-9a-f]{40}`", current)
    assert re.search(r"PR #\\d+", current)
    assert len(re.findall(r"actions/runs/\\d+", current)) >= 3
    assert "Ubuntu" in current and "Windows" in current
    assert "post-merge" in current and "SUCCESS" in current
    assert "CANCELLED" in current  # cancelled jobs must not be accepted as green
    assert "PENDING_STUDENT_EVIDENCE" in current
    assert "không" in current.lower()
    assert "VMware" in current
    assert "packet-to-flow" in current


def test_candidate_burden_is_not_misrepresented_as_operational_soc():
    text = STATUS.read_text(encoding="utf-8")
    assert "`src/blue_team_ai/alert_burden.py`" in text
    assert "research_candidate_burden" in text
    assert "không" in text.lower()
    assert "thời gian" in text.lower()
