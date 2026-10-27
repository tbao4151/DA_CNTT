"""Separate, offline-only Cyber Lab preview page for the Blue Team workspace.

Streamlit discovers this page alongside app.py without changing Dataset Mode.
No packet capture, traffic generation, model prediction, or AI alert occurs here.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import streamlit as st

from blue_team_ai.preview import summarize_offline_flows
from blue_team_ai.triage import create_offline_review_case
from blue_team_ai.verified_report import export_verified_offline_case
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
    "không có cảnh báo AI hay kết nối đến máy ảo. "
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
            "Không có nhãn Normal/Attack, xác suất AI hoặc cảnh báo AI trên trang này. "
            "Cần mô hình riêng tương thích schema Zeek và dữ liệu lab có nhãn để đánh giá phát hiện."
        )

        st.divider()
        st.markdown("### Hồ sơ điều tra thủ công (không phải cảnh báo AI)")
        st.caption(
            "Chọn một flow để lưu hồ sơ Unclassified vào SQLite Cyber Lab riêng. "
            "Hồ sơ là yêu cầu analyst xem xét, không xác nhận có tấn công. "
            "Chỉ ghi dữ liệu khi nhấn nút và xác nhận; không tự tạo khi upload."
        )
        selected_index = st.selectbox(
            "Flow cần xem xét (trong 500 dòng hiển thị)",
            options=range(min(500, len(events))),
            format_func=lambda i: (
                f"Dòng {i + 1} · {events[i]['uid']} · "
                f"{events[i]['src_ip']} → {events[i]['dst_ip']}"
            ),
            key=f"cyber_select_{summary['source_sha256']}",
        )
        consent = st.checkbox(
            "Tôi xác nhận đây là log được phép xử lý và muốn tạo hồ sơ thủ công.",
            key=f"cyber_consent_{summary['source_sha256']}",
        )
        cyber_db = ROOT / "runtime" / "cyber_lab_cases.sqlite3"
        if st.button(
            "Tạo hồ sơ Unclassified",
            disabled=not consent,
            key=f"cyber_create_{summary['source_sha256']}",
        ):
            try:
                case_id = create_offline_review_case(
                    cyber_db,
                    source_data=uploaded.getvalue(),
                    record_index=selected_index,
                )
            except (ValueError, TypeError, OSError, sqlite3.Error) as exc:
                st.error(f"Không thể lưu hồ sơ: {exc}")
            else:
                st.session_state["cyber_last_manual_case"] = {
                    "source_sha256": summary["source_sha256"],
                    "case_id": case_id,
                    "record_index": selected_index,
                }
                st.success(f"Đã tạo hồ sơ điều tra thủ công #{case_id} (Unclassified).")

        last_case = st.session_state.get("cyber_last_manual_case")
        if last_case and last_case["source_sha256"] == summary["source_sha256"]:
            try:
                report_bytes = export_verified_offline_case(
                    cyber_db,
                    case_id=last_case["case_id"],
                    source_data=uploaded.getvalue(),
                    record_index=last_case["record_index"],
                )
            except (ValueError, OSError, sqlite3.Error) as exc:
                st.warning(f"Chưa thể xuất hồ sơ đã tạo: {exc}")
            else:
                st.download_button(
                    "Tải JSON đã đối chiếu log gốc (typed Zeek + audit)",
                    data=report_bytes,
                    file_name=f"cyber_lab_case_{last_case['case_id']}.json",
                    mime="application/json",
                    key=f"cyber_export_{last_case['case_id']}",
                )
                st.caption(
                    "JSON chứa trường Zeek đúng kiểu số/null, được đối chiếu với bytes log đang nạp. "
                    "Không phải bằng chứng chống sửa đổi hoặc kết quả AI; lưu riêng conn.log gốc."
                )
