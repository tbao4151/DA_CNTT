"""Static design contract; browser regression verifies computed CSS on Windows."""
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_streamlit_theme_is_accessible_light_baseline():
    config = tomllib.loads((ROOT / ".streamlit/config.toml").read_text(encoding="utf-8"))
    theme = config["theme"]
    assert theme["base"] == "light"
    assert theme["backgroundColor"] == "#F3F6FB"
    assert theme["textColor"] == "#14253F"


def test_dashboard_uses_trusted_local_styles_with_responsive_focus_states():
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    css = (ROOT / "src/siem_ai/ui.css").read_text(encoding="utf-8")
    assert 'ROOT / "src/siem_ai/ui.css"' in app
    assert "soc-hero" in app and "soc-brand" in app
    assert "Tổng quan an ninh" in app and "SOC case management" in app
    assert "unsafe_allow_html=True" in app
    assert ":focus-visible" in css
    assert "prefers-reduced-motion" in css
    assert "@media(max-width:900px)" in css
    assert "#080f1d" not in css
    assert "[data-testid=\"stMetricValue\"]" in css
