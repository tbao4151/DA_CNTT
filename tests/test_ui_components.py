"""Unit and AppTest checks for DA005 shared SOC UI primitives and page workflows."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from siem_ai.ui_components import (
    priority_band_from_probability,
    render_confusion_matrix_html,
    render_empty_state,
    render_flow_evidence_card,
    render_footer,
    render_mode_banner,
    render_provenance_strip,
)


@pytest.mark.parametrize(
    "prob,expected_code",
    [
        (0.95, "CRIT"),
        (0.90, "CRIT"),
        (0.85, "HIGH"),
        (0.70, "MED"),
        (0.55, "LOW"),
        (0.20, "INFO"),
        (None, "INFO"),
        (float("nan"), "INFO"),
    ],
)
def test_priority_band_mapping_is_deterministic_and_colorblind_safe(prob, expected_code):
    band = priority_band_from_probability(prob)
    assert band["code"] == expected_code
    assert f"[{expected_code}]" in str(band["label"])


def test_html_helpers_escape_untrusted_values():
    xss = "<script>alert(1)</script>"
    card = render_flow_evidence_card(
        {"flow_ref": xss, "proto": "tcp", "AI_attack_probability": 0.91},
        title=f"Flow {xss}",
        subtitle=xss,
        badge_text=xss,
    )
    assert "<script>" not in card
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in card
    assert "91.00%" in card

    banner = render_mode_banner(xss, xss, xss, variant="red")
    assert "<script>" not in banner
    assert "soc-mode-banner--red" in banner

    strip = render_provenance_strip([(xss, xss)])
    assert "<script>" not in strip

    empty = render_empty_state(xss, xss, xss)
    assert "<script>" not in empty


def test_confusion_matrix_html_displays_all_quadrants():
    html_out = render_confusion_matrix_html(
        [[28600, 8400], [865, 44467]],
        average_precision=0.9879,
        train_size=175341,
        test_size=82332,
    )
    for token in ("28,600", "8,400", "865", "44,467", "82,332", "0.9879"):
        assert token in html_out


def test_footer_renders_da005_attribution():
    footer = render_footer()
    assert "DA005" in footer
    assert "soc-footer" in footer


def test_red_team_page_synthetic_benchmark_runs_cleanly():
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(
        str(ROOT / "pages" / "2_Red_Team_Lab.py"), default_timeout=45
    ).run()
    assert not app.exception, [str(e.message) for e in app.exception]
    sim_buttons = [
        b for b in app.button if "Chạy so sánh mô phỏng" in b.label
    ]
    assert len(sim_buttons) == 1
    app = sim_buttons[0].click().run()
    assert not app.exception, [str(e.message) for e in app.exception]
    assert "red_team_synthetic_comparison" in app.session_state
