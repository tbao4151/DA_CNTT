"""Headless Streamlit smoke test: validate the default offline dashboard starts.

This does not replace manual end-to-end testing on Windows with a trained model.
"""
from pathlib import Path

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]


def test_default_dashboard_loads_without_model():
    assert (ROOT / "data/raw/unsw_nb15/UNSW_NB15_testing-set.csv").is_file()
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    assert len(app.exception) == 0, [str(e.message) for e in app.exception]
    assert any("DA005" in title.value for title in app.title)
    assert len(app.tabs) == 5
    assert any("So sánh ngưỡng đã khóa" in header.value for header in app.subheader)
