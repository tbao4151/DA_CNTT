"""Cyber Lab offline preview: synthetic fixtures only, not live captures."""
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from blue_team_ai.preview import summarize_offline_flows
from blue_team_ai.zeek import parse_zeek_conn_log


def _sample_log():
    return (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "1630000002.0\tA\t192.168.56.2\t4444\t192.168.56.3\t80\ttcp\n"
        "1630000001.0\tB\t192.168.56.2\t4445\t192.168.56.4\t53\tudp\n"
    ).encode()


def test_summary_uses_zeek_timestamps_and_source_provenance():
    data = _sample_log()
    events = parse_zeek_conn_log(data)
    summary = summarize_offline_flows(events)
    assert summary["flow_count"] == 2
    assert summary["unique_sources"] == 1
    assert summary["unique_destinations"] == 2
    assert summary["protocol_counts"] == {"tcp": 1, "udp": 1}
    assert summary["source_sha256"] == hashlib.sha256(data).hexdigest()
    assert summary["first_event_utc"] == "2021-08-26T17:46:41+00:00"
    assert summary["last_event_utc"] == "2021-08-26T17:46:42+00:00"
    assert all("AI_verdict" not in event and "label" not in event for event in events)


def test_reject_non_offline_and_mixed_provenance():
    events = parse_zeek_conn_log(_sample_log())
    with pytest.raises(ValueError, match="No offline"):
        summarize_offline_flows([])
    with pytest.raises(ValueError, match="Only offline"):
        summarize_offline_flows([{**events[0], "origin": "live_capture"}])
    with pytest.raises(ValueError, match="Mixed"):
        summarize_offline_flows([events[0], {**events[1], "source_sha256": "other"}])


def test_streamlit_page_starts_without_uploaded_log():
    # AppTest does not supply a user-selected log. It must not create mock alerts.
    from streamlit.testing.v1 import AppTest

    page = Path(__file__).resolve().parents[1] / "pages/1_Cyber_Lab.py"
    app = AppTest.from_file(str(page), default_timeout=45).run()
    assert len(app.exception) == 0, [str(e.message) for e in app.exception]
    assert any("Cyber Lab" in title.value for title in app.title)
    assert any("Chưa có dữ liệu Cyber Lab" in h.value for h in app.markdown)
