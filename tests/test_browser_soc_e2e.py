"""Opt-in real-browser Windows E2E with a freshly trained official UNSW model.

The official test split is used for inference only. Streamlit, SQLite, and
browser downloads run against a private temporary copy of the application.
This is an offline localhost smoke test, not a production security test.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
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
                    initial_report = json.loads(Path(download.path()).read_text(encoding="utf-8"))
                    assert initial_report["case"]["state"] == "New"

                    # Exercise a real analyst transition using browser widgets.
                    note = "Verified flow evidence; investigate suspicious activity."
                    # Streamlit's BaseWeb selectbox may re-render its popup
                    # while Chromium is waiting for an ARIA option. Drive the
                    # focused selectbox by keyboard instead of targeting the
                    # transient popup node (regression: main CI 40443531393).
                    state_picker = page.get_by_role("combobox", name="Trạng thái xử lý")
                    state_picker.click()
                    state_picker.press("Home")
                    state_picker.press("ArrowDown")
                    state_picker.press("Enter")
                    page.get_by_role("textbox", name="Ghi chú điều tra (bắt buộc)").fill(note)
                    page.get_by_role("button", name="Lưu diễn biến điều tra").click()

                    # Wait for the SQLite transaction before reloading. Reloading
                    # verifies that the transition survives a fresh UI session.
                    db = sandbox / "runtime/soc_cases.sqlite3"
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        with sqlite3.connect(db) as conn:
                            state_row = conn.execute(
                                "SELECT state, analyst_note FROM cases WHERE case_id=1"
                            ).fetchone()
                        if state_row == ("Investigating", note):
                            break
                        time.sleep(0.25)
                    else:
                        pytest.fail("Browser SOC state update was not persisted")

                    page.reload(wait_until="domcontentloaded")
                    page.get_by_role("tab", name="SOC case management").click()
                    with page.expect_download(timeout=90000) as updated_download_info:
                        page.get_by_role("button", name="Xuất hồ sơ điều tra (JSON)").click()
                    updated_download = updated_download_info.value
                    assert updated_download.suggested_filename == "da005_soc_case_1.json"
                    report = json.loads(
                        Path(updated_download.path()).read_text(encoding="utf-8")
                    )

                    # CSV import and Threat Hunting are exercised through a
                    # real browser, using only a few held-out flow features.
                    # Test labels are deliberately absent from the upload.
                    groups = [
                        (protocol, group.head(4))
                        for protocol, group in sample.groupby("proto", sort=False)
                        if len(group) >= 4
                    ]
                    assert len(groups) >= 2, "Need two protocols for a meaningful filter check"
                    selected_protocol = str(groups[0][0])
                    uploaded_flows = pd.concat(
                        [groups[0][1], groups[1][1]], ignore_index=True
                    ).drop(columns=["id", "label", "attack_cat"], errors="ignore")
                    assert len(uploaded_flows) == 8

                    page.get_by_role("radio", name="Tải lên CSV").check()
                    uploader = page.locator(
                        '[data-testid="stFileUploader"] input[type="file"]'
                    )
                    uploader.set_input_files({
                        "name": "valid_network_flows.csv",
                        "mimeType": "text/csv",
                        "buffer": uploaded_flows.to_csv(index=False).encode("utf-8"),
                    })
                    page.get_by_role("tab", name="Threat hunting").click()
                    page.get_by_text("Đang hiển thị 8/8 flow", exact=False).wait_for()

                    # One protocol occurs in exactly four of the eight rows.
                    # Drive the searchable multiselect by keyboard to avoid
                    # relying on a transient BaseWeb option DOM node.
                    protocol_input = page.get_by_role("combobox", name="Giao thức")
                    protocol_input.fill(selected_protocol)
                    protocol_input.press("Enter")
                    page.get_by_text("Đang hiển thị 4/8 flow", exact=False).wait_for()

                    # A malformed header must be rejected before any inference.
                    lines = uploaded_flows.to_csv(index=False).splitlines()
                    duplicate_header_csv = (
                        lines[0] + ",proto\\n" + lines[1] + ",tcp\\n"
                    ).replace("\\n", "\n").encode("utf-8")
                    uploader.set_input_files({
                        "name": "duplicate_header.csv",
                        "mimeType": "text/csv",
                        "buffer": duplicate_header_csv,
                    })
                    page.get_by_text(
                        "Duplicate CSV column names are not allowed", exact=False
                    ).wait_for()
                finally:
                    browser.close()

            assert report["case"]["case_id"] == 1
            assert report["case"]["verdict"] == "Attack"
            assert report["case"]["state"] == "Investigating"
            assert report["case"]["analyst_note"] == note
            assert report["case"]["flow_id"] == initial_report["case"]["flow_id"]
            assert report["case"]["verdict"] == initial_report["case"]["verdict"]
            assert 0.8 <= report["case"]["confidence"] <= 1
            assert report["flow_evidence"]
            assert not {"label", "attack_cat", "id", "AI_verdict", "AI_attack_probability", "flow_ref"} & set(report["flow_evidence"])
            assert report["flow_evidence"] == initial_report["flow_evidence"]
            assert [event["new_state"] for event in report["case_events"]] == [
                "New", "Investigating"
            ]
            assert report["case_events"][1]["old_state"] == "New"
            assert report["case_events"][1]["note"] == note
            # A real browser changed only the sandboxed SQLite case.
            assert (sandbox / "runtime/soc_cases.sqlite3").is_file()
        finally:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)
