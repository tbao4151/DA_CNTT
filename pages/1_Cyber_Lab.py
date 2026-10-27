"""Separate, offline-only Cyber Lab preview page for the Blue Team workspace.

Streamlit discovers this page alongside app.py without changing Dataset Mode.
No packet capture, traffic generation, model prediction, or SOC alert occurs here.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import streamlit as st

from blue_team_ai.preview import summarize_offline_flows
from blue_team_ai.zeek import MAX_LOG_BYTES, parse_zeek_conn_log

st.set_page_config(page_title="DA005 | Cyber Lab", page_icon=None, layout="wide")
st.markdown(
    "<style>" + (ROOT / "src/siem_ai/ui.css").read_text(encoding="utf-8") + "</style>",
    unsafe_allow_html=True,
)

st.sidebar.markdown("### SENTINEL LAB / BLUE TEAM")
st.sidebar.caption("Chuyển sang Dataset Mode bằng điều hướng trang Streamlit.")
st.sidebar.caption("Cyber Lab Mode · Offline preview")
st.sidebar.warning("Không thu thập mạng, không chạy kịch bản tấn công.")

st.title("Cyber Lab · Blue Team")
st.caption("DA005 / TDTU · Offline Zeek telemetry explorer")
st.info(
    "Chế độ đọc log ngoại tuyến. Các bản ghi chưa được AI phân loại; "
    "không có cảnh báo tấn công hay kết nối đến máy ảo. "
    "Dataset Mode và mô hình UNSW-NB15 hoạt động độc lập."
)

with st.expander("Nguồn dữ liệu và giới hạn", expanded=False):
    st.markdown(
        "Chỉ chấp nhận Zeek ASCII conn.log từ môi trường được phép kiểm thử. "
        "Giới hạn 15 MiB và 10.000 flow, hiển thị tối đa 500 dòng. "
        "IP và timestamp là thông tin có trong tệp, không phải bằng chứng giám sát trực tiếp. "
        "Không tải log nhạy cảm lên kho GitHub công khai."
    )

uploaded = st.file_uploader(
    "Nạp Zeek conn.log ngoại tuyến", type=["log"],
    help="Chỉ đọc trên phiên Streamlit đang chạy cục bộ; không phát lưu lượng mạng.",
)
if uploaded is None:
    st.markdown("### Chưa có dữ liệu Cyber Lab")
    st.write("Chọn một tệp conn.log để xem thống kê và dấu vết nguồn. Không dùng dữ liệu demo giả làm live.")
elif uploaded.size > MAX_LOG_BYTES:
    st.error("Tệp Zeek vượt quá giới hạn 15 MiB. Không đọc hoặc phân tích tệp này.")
else:
    try:
        events = parse_zeek_conn_log(uploaded.getvalue())
        summary = summarize_offline_flows(events)
    except (ValueError, TypeError, UnicodeDecodeError, OverflowError) as exc:
        st.error(f"Không thể đọc Zeek conn.log: {exc}")
    else:
        st.success("Đã xác thực cấu trúc Zeek ASCII; đây là dữ liệu ngoại tuyến, chưa có AI inference.")
        cols = st.columns(3)
        cols[0].metric("Flow hợp lệ", f"{summary['flow_count']:,}")
        cols[1].metric("IP nguồn duy nhất", summary["unique_sources"])
        cols[2].metric("IP đích duy nhất", summary["unique_destinations"])
        st.markdown("### Dấu vết dữ liệu")
        st.code(summary["source_sha256"], language=None)
        st.caption(
            "SHA-256 của toàn bộ tệp đầu vào. "
            f"Khoảng thời gian ghi trong Zeek: {summary['first_event_utc']} — "
            f"{summary['last_event_utc']} (UTC)."
        )
        st.markdown("### Phân bố giao thức")
        st.bar_chart(pd.DataFrame(
            {"Giao thức": list(summary["protocol_counts"]),
             "Số flow": list(summary["protocol_counts"].values())}
        ).set_index("Giao thức"))
        st.markdown("### Bản ghi Zeek (tối đa 500)")
        columns = [
            "event_time_utc", "uid", "src_ip", "src_port", "dst_ip", "dst_port",
            "proto", "service", "duration_s", "orig_bytes", "resp_bytes",
            "orig_pkts", "resp_pkts",
        ]
        st.dataframe(pd.DataFrame(events[:500])[columns], use_container_width=True, hide_index=True)
        st.caption(
            "Không có nhãn Normal/Attack, xác suất AI, cảnh báo hoặc SOC Case trên trang này. "
            "Cần mô hình riêng tương thích schema Zeek và dữ liệu lab có nhãn để đánh giá phát hiện."
        )
