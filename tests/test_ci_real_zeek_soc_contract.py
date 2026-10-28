"""CI-only synthetic SOC export contract; no live traffic or model claims."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_real_zeek_scoring import validate_ci_synthetic_case


def _case():
    return {
        "report_type": "DA005 educational SOC case",
        "integrity_notice": "Local SQLite snapshot; not signed.",
        "case": {
            "case_id": 1,
            "verdict": "Unclassified",
            "confidence": None,
            "state": "New",
            "analyst_note": (
                "NOT a verified attack or operational AI alert. "
                "source_sha256=" + "a" * 64 + "; "
                "model_sha256=" + "b" * 64 + "; "
                "import_report_sha256=" + "c" * 64 + "; "
                "Authorization, Host-only isolation and ground truth are unverified."
            ),
        },
        "flow_evidence": {"source_sha256": "a" * 64, "uid": "fixture-uid"},
        "case_events": [{"case_id": 1, "new_state": "New"}],
    }


def _verify(report):
    validate_ci_synthetic_case(
        report, log_sha="a" * 64, model_sha="b" * 64, import_sha="c" * 64,
    )


def test_ci_synthetic_manual_soc_contract_accepts_unclassified_case():
    _verify(_case())


@pytest.mark.parametrize("path,value", [
    (("case", "verdict"), "Attack"),
    (("case", "confidence"), 0.95),
    (("case", "state"), "Resolved"),
    (("case", "analyst_note"), "Confirmed attack"),
    (("case", "case_id"), True),
    (("flow_evidence", "source_sha256"), "0" * 64),
    (("flow_evidence", "label"), 1),
    (("case_events", 0, "new_state"), "Escalated"),
    (("case_events", 0, "case_id"), 999),
])
def test_ci_synthetic_manual_soc_contract_rejects_invalid_claims(path, value):
    report = copy.deepcopy(_case())
    obj = report
    for key in path[:-1]:
        obj = obj[key]
    obj[path[-1]] = value
    with pytest.raises(ValueError, match="Synthetic SOC case"):
        _verify(report)
