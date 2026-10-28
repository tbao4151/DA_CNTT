"""Read-only, pinned NEW-log research review for the local Blue Team UI.

Recomputes all predictions against original bytes; never writes SOC records,
trains models, opens sockets, or labels a candidate as a confirmed attack.
"""
from __future__ import annotations

from pathlib import Path
from collections.abc import Sequence

from .new_log_inference import score_new_zeek_log
from .new_log_review import review_pinned_new_log_report
from .trusted_model import load_pinned_zeek_research_model

MAX_UI_ROWS = 500


def prepare_new_log_review(
    *,
    source_data: bytes,
    report_data: bytes,
    model_path: str | Path,
    expected_log_sha256: str,
    expected_model_sha256: str,
    lab_cidrs: Sequence[str],
) -> dict[str, object]:
    """Return only verified research candidates from the first 500 rows.

    The model hash must come from a separately preserved reference, not the
    model JSON or uploaded report. This does not prove model authorship,
    reserved TEST exclusion, capture authenticity, or Host-only isolation.
    """
    model = load_pinned_zeek_research_model(
        model_path, expected_sha256=expected_model_sha256,
    )
    review = review_pinned_new_log_report(
        source_data, model, report_data,
        expected_log_sha256=expected_log_sha256,
        lab_cidrs=lab_cidrs, model_sha256=expected_model_sha256,
    )
    # Recompute from verified bytes, never trust display fields from the
    # uploaded JSON (including scores, IPs, UIDs, and timestamps).
    result = score_new_zeek_log(
        source_data, model,
        expected_log_sha256=expected_log_sha256,
        lab_cidrs=lab_cidrs, model_sha256=expected_model_sha256,
    )
    candidates = [
        {
            "Zeek row": index + 1,
            "UID": prediction["uid"],
            "P(Attack) research": prediction["attack_probability"],
            "Zeek time UTC": prediction["event_time_utc"],
            "Source IP": prediction["src_ip"],
            "Destination IP": prediction["dst_ip"],
        }
        for index, prediction in enumerate(result["predictions"][:MAX_UI_ROWS])
        if prediction["research_candidate"] is True
    ]
    candidates.sort(key=lambda row: (-row["P(Attack) research"], row["Zeek row"]))
    return {
        "review": review,
        "candidate_rows": candidates,
        "visible_flow_count": min(MAX_UI_ROWS, result["flow_count"]),
        "validation_threshold": result["selected_validation_threshold"],
        "declared_scope_sha256": result["declared_scope_sha256"],
    }
