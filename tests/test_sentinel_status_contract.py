"""Static architecture inventory guard; no VMware, network, AI fitting or SOC writes."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATUS = ROOT / "docs" / "SENTINEL_LAB_IMPLEMENTATION_STATUS.md"

ENTRYPOINTS = (
    "app.py",
    "src/siem_ai/model.py",
    "src/blue_team_ai/zeek.py",
    "src/blue_team_ai/offline_baseline.py",
    "src/blue_team_ai/new_log_evaluation.py",
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
