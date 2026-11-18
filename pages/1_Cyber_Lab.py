"""Separate, offline-only Cyber Lab preview page for the Blue Team workspace.

Streamlit discovers this page alongside app.py without changing Dataset Mode.
No packet capture, traffic generation, model prediction, or AI alert occurs here.
"""
from __future__ import annotations

import hashlib
import html
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import plotly.express as px
import streamlit as st

from blue_team_ai.preview import summarize_offline_flows
from blue_team_ai.research_triage import create_research_candidate_case
from blue_team_ai.triage import create_offline_review_case
from blue_team_ai.trace_review import MAX_PRIVATE_TRACE_BYTES, review_private_zeek_trace
from blue_team_ai.verified_report import export_verified_offline_case
from blue_team_ai.zeek import MAX_LOG_BYTES, parse_zeek_conn_log
from siem_ai.ui_components import (
    priority_band_from_probability,
    render_empty_state,
    render_flow_evidence_card,
    render_footer,
    render_mode_banner,
    render_provenance_strip,
    render_sidebar_brand,
    style_chart,
)

st.set_page_config(page_title="DA005 | Cyber Lab", page_icon=None, layout="wide")
st.markdown(
    "<style>" + (ROOT / "src/siem_ai/ui.css").read_text(encoding="utf-8") + "</style>",
    unsafe_allow_html=True,
)

render_sidebar_brand(
    workspace_title="Blue Team · Telemetry",
    workspace_mode="Offline Zeek Preview",
    mode_variant="blue",
)
st.sidebar.markdown("### Trạng thái Cyber Lab")
st.sidebar.markdown(
    '<div class="soc-sidebar-flag soc-sidebar-flag--ready">'
    '<strong>Chế độ chỉ đọc ngoại tuyến</strong><br>'
    'Đọc Zeek ASCII conn.log cục bộ; không bắt gói tin hay chạy AI tự động.'
    '</div>',
    unsafe_allow_html=True,
)
st.sidebar.warning("Không thu thập mạng, không chạy kịch bản tấn công.")
st.sidebar.caption("Chuyển sang Dataset Mode hoặc New Log Review bằng thanh điều hướng trang phía trên.")

st.title("Cyber Lab · Blue Team")
st.markdown(
    '<section class="soc-hero soc-hero--blue">'
    '<div class="soc-hero__eyebrow">TDTU / DA005 · Blue Team Detection Lab · Offline Zeek Telemetry</div>'
    '<h2>Trình khám phá nhật ký Zeek ngoại tuyến</h2>'
    '<div class="soc-hero__description">Kiểm tra cấu trúc tệp Zeek ASCII conn.log từ môi trường lab được phép, '
    'xác minh dấu vết SHA-256, đối chiếu trace nghiên cứu held-out và mở hồ sơ điều tra thủ công (Unclassified).</div>'
    '<div class="soc-hero__meta">'
    '<span class="soc-pill soc-pill--blue">Luồng: Blue Team · Telemetry &amp; Review</span>'
    '<span class="soc-pill">Nguồn: Zeek conn.log cục bộ</span>'
    '<span class="soc-pill">Trạng thái: Offline · Không kết nối VMware</span>'
    '</div></section>',
    unsafe_allow_html=True,
)
st.markdown(
    render_mode_banner(
        "BLUE TEAM · OFFLINE ZEEK",
        "Phân tách hoàn toàn với Dataset Mode & Red Team Simulation",
        "Các bản ghi Zeek chưa được AI phân loại khi vừa nạp; không phát cảnh báo AI tự động hay tạo lưu lượng mạng. "
        "Dataset Mode (UNSW-NB15) hoạt động độc lập.",
        variant="blue",
    ),
    unsafe_allow_html=True,
)

with st.expander("Nguồn dữ liệu và giới hạn kỹ thuật", expanded=False):
    st.markdown(
        "Chỉ chấp nhận Zeek ASCII `conn.log` từ môi trường được phép kiểm thử. "
        "Giới hạn **15 MiB** và **10.000 flow**, hiển thị tối đa **500 dòng**. "
        "IP và timestamp là thông tin có trong tệp, không phải bằng chứng giám sát trực tiếp. "
        "Không tải log nhạy cảm lên kho GitHub công khai."
    )

uploaded = st.file_uploader(
    "Nạp Zeek conn.log ngoại tuyến", type=["log"],
    help="Chỉ đọc trên phiên Streamlit đang chạy cục bộ; không phát lưu lượng mạng.",
)
if uploaded is None:
    st.markdown("### Chưa có dữ liệu Cyber Lab")
    st.markdown(
        render_empty_state(
            "Chờ nạp tệp Zeek conn.log ngoại tuyến",
            "Không dùng dữ liệu demo giả làm dữ liệu thu thập thực tế. Chọn một tệp conn.log để xem thống kê giao thức, khoảng thời gian UTC và dấu vết SHA-256.",
            "Quy trình 3 bước: (1) Nạp conn.log → (2) Đối chiếu trace nghiên cứu JSON (tùy chọn) → (3) Mở hồ sơ điều tra thủ công Unclassified.",
        ),
        unsafe_allow_html=True,
    )
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

        st.markdown(
            render_provenance_strip([
                ("Tệp nguồn", uploaded.name),
                ("Bản ghi đầu (UTC)", str(summary["first_event_utc"])),
                ("Bản ghi cuối (UTC)", str(summary["last_event_utc"])),
                ("Giới hạn bảng xem trước", f"{min(500, len(events)):,} / {len(events):,} flows"),
            ]),
            unsafe_allow_html=True,
        )
        st.markdown("### Dấu vết dữ liệu (Source SHA-256)")
        st.markdown(
            f'<div class="soc-hash-box">{html.escape(summary["source_sha256"])}</div>',
            unsafe_allow_html=True,
        )
        st.caption(
            "SHA-256 của toàn bộ tệp đầu vào. "
            f"Khoảng thời gian ghi trong Zeek: {summary['first_event_utc']} — "
            f"{summary['last_event_utc']} (UTC)."
        )

        st.markdown("### Phân bố giao thức")
        proto_df = pd.DataFrame(
            {
                "Giao thức": list(summary["protocol_counts"].keys()),
                "Số flow": list(summary["protocol_counts"].values()),
            }
        )
        fig = px.bar(
            proto_df,
            x="Giao thức",
            y="Số flow",
            color_discrete_sequence=["#0d9488"],
        )
        st.plotly_chart(style_chart(fig, height=290), use_container_width=True)

        st.markdown("### Bản ghi Zeek (tối đa 500 dòng đầu)")
        columns = [
            "event_time_utc", "uid", "src_ip", "src_port", "dst_ip", "dst_port",
            "proto", "service", "duration_s", "orig_bytes", "resp_bytes",
            "orig_pkts", "resp_pkts",
        ]
        preview_df = pd.DataFrame(events[:500])[columns]
        q_col1, q_col2 = st.columns([1.2, 2])
        proto_options = sorted(preview_df["proto"].dropna().astype(str).unique().tolist())
        picked_protos = q_col1.multiselect(
            "Lọc nhanh giao thức (chỉ trong 500 dòng preview)",
            proto_options,
            key=f"cyber_preview_proto_{summary['source_sha256']}",
        )
        ip_uid_query = q_col2.text_input(
            "Tìm nhanh theo UID / IP nguồn / IP đích (chỉ trong 500 dòng preview)",
            placeholder="Ví dụ: 192.168.56. hoặc C...",
            key=f"cyber_preview_search_{summary['source_sha256']}",
        ).strip().lower()

        display_df = preview_df
        if picked_protos:
            display_df = display_df[display_df["proto"].astype(str).isin(picked_protos)]
        if ip_uid_query:
            mask = (
                display_df["uid"].astype(str).str.lower().str.contains(ip_uid_query, regex=False)
                | display_df["src_ip"].astype(str).str.lower().str.contains(ip_uid_query, regex=False)
                | display_df["dst_ip"].astype(str).str.lower().str.contains(ip_uid_query, regex=False)
            )
            display_df = display_df[mask]

        if display_df.empty:
            st.markdown(
                render_empty_state(
                    "Không có dòng Zeek nào khớp bộ lọc xem trước",
                    "Bộ lọc chỉ tìm trong 500 bản ghi đầu tiên; xóa điều kiện tìm kiếm để xem lại toàn bộ bản xem trước.",
                ),
                unsafe_allow_html=True,
            )
        else:
            st.caption(f"Hiển thị {len(display_df):,}/{len(preview_df):,} bản ghi trong cửa sổ xem trước.")
            st.dataframe(display_df, use_container_width=True, hide_index=True, height=380)
        st.caption(
            "Bảng Zeek gốc không có nhãn hoặc dự đoán AI. "
            "Cần mô hình riêng tương thích schema Zeek và dữ liệu lab có nhãn để đánh giá phát hiện."
        )

        st.divider()
        st.markdown("### Đối chiếu dự đoán AI nghiên cứu (chỉ đọc)")
        st.caption(
            "Tùy chọn nạp JSON private --trace-output được tạo từ thực nghiệm Zeek ngoại tuyến. "
            "Đối chiếu SHA-256 và toàn bộ UID của conn.log đang mở, xác minh xác suất/ngưỡng "
            "và số liệu nhất quán. Không huấn luyện AI, không phát cảnh báo hoặc tạo case tự động."
        )
        trace_upload = st.file_uploader(
            "Tệp JSON private held-out prediction trace",
            type=["json"],
            key=f"cyber_trace_{summary['source_sha256']}",
            help="Chỉ dùng file riêng tư do nhóm tự tạo; không tải lên GitHub.",
        )
        if trace_upload is not None:
            if trace_upload.size > MAX_PRIVATE_TRACE_BYTES:
                st.error("Trace JSON vượt giới hạn 16 MiB; từ chối xử lý.")
            else:
                try:
                    trace_review = review_private_zeek_trace(
                        uploaded.getvalue(), trace_upload.getvalue(),
                    )
                except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
                    st.error(f"Không thể đối chiếu trace nghiên cứu: {exc}")
                else:
                    st.warning(
                        "Đã đối chiếu nội bộ log/trace; KHÔNG xác thực nguồn gốc mô hình, "
                        "nhãn tấn công hoặc cô lập VMware. Đây là dự đoán held-out nghiên cứu, "
                        "không phải phát hiện live hoặc cảnh báo SOC."
                    )
                    c1, c2 = st.columns(2)
                    c1.metric("Flow khớp nguồn", trace_review["flow_count"])
                    c2.metric("Ứng viên AI Attack (nghiên cứu)", trace_review["candidate_count"])
                    st.caption(f"Ngưỡng validation đã khóa trong trace: {trace_review['selected_threshold']:.2f}")
                    candidates = [
                        {
                            "Dòng Zeek": row["record_index"] + 1,
                            "UID": row["uid"],
                            "P(Attack) nghiên cứu": row["attack_probability"],
                            "Mức ưu tiên": priority_band_from_probability(row["attack_probability"])["label"],
                            "Thời gian Zeek UTC": events[row["record_index"]]["event_time_utc"],
                            "IP nguồn": events[row["record_index"]]["src_ip"],
                            "IP đích": events[row["record_index"]]["dst_ip"],
                        }
                        for row in trace_review["rows"] if row["predicted_attack"]
                    ]
                    if candidates:
                        candidates.sort(key=lambda row: row["P(Attack) nghiên cứu"], reverse=True)
                        st.dataframe(
                            pd.DataFrame(candidates[:500]), use_container_width=True, hide_index=True,
                        )
                        st.caption("Tối đa 500 ứng viên; nhãn ground truth không được đưa vào bảng.")
                        visible_candidates = [
                            row for row in trace_review["rows"]
                            if row["predicted_attack"] and row["record_index"] < 500
                        ]
                        if visible_candidates:
                            st.markdown("#### Chuyển ứng viên nghiên cứu sang điều tra thủ công")
                            st.caption(
                                "Chỉ các flow trong 500 dòng Zeek đầu được chọn. "
                                "Hồ sơ vẫn Unclassified, confidence rỗng; xác suất nghiên cứu "
                                "chỉ nằm trong ghi chú audit, không phải cảnh báo AI vận hành."
                            )
                            trace_digest = hashlib.sha256(trace_upload.getvalue()).hexdigest()
                            selection = st.selectbox(
                                "Ứng viên cần điều tra",
                                options=[row["record_index"] for row in visible_candidates],
                                format_func=lambda i: (
                                    f"Dòng {i + 1} · {events[i]['uid']} · "
                                    f"P(Attack)={trace_review['rows'][i]['attack_probability']:.3f}"
                                ),
                                key=f"research_select_{summary['source_sha256']}_{trace_digest}",
                            )
                            st.markdown(
                                render_flow_evidence_card(
                                    events[selection],
                                    title=f"Bằng chứng dòng Zeek #{selection + 1} ({events[selection]['uid']})",
                                    subtitle="Kiểm tra endpoint, giao thức và dung lượng trước khi mở hồ sơ Unclassified.",
                                    badge_text=str(priority_band_from_probability(trace_review["rows"][selection]["attack_probability"])["label"]),
                                    badge_class=str(priority_band_from_probability(trace_review["rows"][selection]["attack_probability"])["badge_class"]),
                                ),
                                unsafe_allow_html=True,
                            )
                            approved = st.checkbox(
                                "Tôi đã xem bằng chứng và chủ động mở hồ sơ nghiên cứu; "
                                "không coi đây là tấn công đã xác nhận.",
                                key=f"research_consent_{summary['source_sha256']}_{trace_digest}",
                            )
                            if st.button(
                                "Mở hồ sơ nghiên cứu Unclassified",
                                disabled=not approved,
                                key=f"research_create_{summary['source_sha256']}_{trace_digest}",
                            ):
                                try:
                                    case_id = create_research_candidate_case(
                                        ROOT / "runtime" / "cyber_lab_cases.sqlite3",
                                        source_data=uploaded.getvalue(),
                                        trace_data=trace_upload.getvalue(),
                                        record_index=selection,
                                        analyst_confirmed=approved,
                                    )
                                except (ValueError, TypeError, OSError, sqlite3.Error) as exc:
                                    st.error(f"Không thể mở hồ sơ nghiên cứu: {exc}")
                                else:
                                    st.session_state["cyber_last_manual_case"] = {
                                        "source_sha256": summary["source_sha256"],
                                        "case_id": case_id,
                                        "record_index": selection,
                                    }
                                    st.success(
                                        f"Hồ sơ nghiên cứu #{case_id} (Unclassified) đã được ghi nhận. "
                                        "Nếu flow nguồn/UID này đã được mở trước đó, hệ thống "
                                        "tái sử dụng hồ sơ và audit gốc, không tạo bản trùng."
                                    )
                    else:
                        st.markdown(
                            render_empty_state(
                                "Không có ứng viên Attack theo ngưỡng nghiên cứu",
                                "Trace đối chiếu hợp lệ nhưng không có bản ghi nào vượt ngưỡng trong tệp log này.",
                            ),
                            unsafe_allow_html=True,
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
        st.markdown(
            render_flow_evidence_card(
                events[selected_index],
                title=f"Xem trước Flow Zeek dòng #{selected_index + 1}",
                subtitle="Trích xuất nguyên bản từ conn.log đã xác thực.",
                badge_text="Unclassified (Thủ công)",
                badge_class="soc-badge--blue",
            ),
            unsafe_allow_html=True,
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

st.markdown(render_footer(), unsafe_allow_html=True)
