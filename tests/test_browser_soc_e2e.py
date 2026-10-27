"""Opt-in real-browser Windows E2E with a freshly trained official UNSW model.

The official test split is used for inference only. Streamlit, SQLite, and
browser downloads run against a private temporary copy of the application.
This is an offline localhost smoke test, not a production security test.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "artifacts" / "unsw_binary_rf.joblib"
METRICS = ROOT / "artifacts" / "metrics.json"
TEST_CSV = ROOT / "data/raw/unsw_nb15/UNSW_NB15_testing-set.csv"


@pytest.mark.skipif(
    os.environ.get("DA005_BROWSER_SOC_E2E") != "1",
    reason="Opt-in: needs freshly fitted official UNSW model and Playwright Chromium",
)
def test_windows_browser_ai_alert_to_soc_json(tmp_path):
    from playwright.sync_api import sync_playwright

    assert sys.platform == "win32", "This browser gate is intended for Windows CI"
    assert MODEL.is_file() and METRICS.is_file() and TEST_CSV.is_file()
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    assert (metrics["train_size"], metrics["test_size"]) == (175341, 82332)

    # Never write to the real runtime directory, and never use test labels to train.
    sandbox = tmp_path / "browser_app"
    sandbox.mkdir()
    shutil.copy2(ROOT / "app.py", sandbox / "app.py")
    shutil.copytree(ROOT / "src", sandbox / "src")
    data_dir = sandbox / "data/raw/unsw_nb15"
    data_dir.mkdir(parents=True)
    sample = pd.read_csv(TEST_CSV, nrows=2500)
    assert len(sample) == 2500
    sample.to_csv(data_dir / TEST_CSV.name, index=False)
    artifacts = sandbox / "artifacts"
    artifacts.mkdir()
    shutil.copy2(MODEL, artifacts / MODEL.name)
    shutil.copy2(METRICS, artifacts / METRICS.name)

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    address = f"http://127.0.0.1:{port}"
    log_path = tmp_path / "streamlit.log"
    with log_path.open("wb") as log_file:
        server = subprocess.Popen(
            [
                sys.executable, "-m", "streamlit", "run", str(sandbox / "app.py"),
                "--server.headless=true",
                "--server.address=127.0.0.1",
                f"--server.port={port}",
                "--browser.gatherUsageStats=false",
            ],
            cwd=sandbox,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            # Health checks only establish readiness; Playwright verifies the UI.
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    pytest.fail(f"Streamlit exited early; log: {log_path.read_text(errors='replace')}")
                try:
                    with urlopen(f"{address}/_stcore/health", timeout=2) as response:
                        if response.status == 200:
                            break
                except (URLError, OSError, TimeoutError):
                    pass
                time.sleep(1)
            else:
                pytest.fail(f"Streamlit startup timed out; log: {log_path.read_text(errors='replace')}")

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    context = browser.new_context(accept_downloads=True)
                    page = context.new_page()
                    page.set_default_timeout(90000)
                    page.goto(address, wait_until="domcontentloaded", timeout=90000)
                    page.get_by_role("tab", name="Trung tâm cảnh báo").click()
                    page.get_by_role("button", name="Tạo SOC case từ flow đã chọn").click()
                    page.get_by_text("Đã lưu case #1 trong SQLite cục bộ.").wait_for()
                    page.get_by_role("tab", name="SOC case management").click()
                    with page.expect_download(timeout=90000) as download_info:
                        page.get_by_role("button", name="Xuất hồ sơ điều tra (JSON)").click()
                    download = download_info.value
                    assert download.suggested_filename == "da005_soc_case_1.json"
                    report = json.loads(Path(download.path()).read_text(encoding="utf-8"))
                finally:
                    browser.close()

            assert report["case"]["case_id"] == 1
            assert report["case"]["verdict"] == "Attack"
            assert report["case"]["state"] == "New"
            assert 0.8 <= report["case"]["confidence"] <= 1
            assert report["flow_evidence"]
            assert not {"label", "attack_cat", "id", "AI_verdict", "AI_attack_probability", "flow_ref"} & set(report["flow_evidence"])
            assert [event["new_state"] for event in report["case_events"]] == ["New"]
            # A real browser created only a sandboxed SQLite case.
            assert (sandbox / "runtime/soc_cases.sqlite3").is_file()
        finally:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)
