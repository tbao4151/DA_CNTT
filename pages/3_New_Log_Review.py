"""Local, read-only review of independently pinned NEW Zeek log predictions.

Separate from held-out research trace review and Dataset Mode. This page does
not create SOC cases or claim live detection, lab isolation, or label truth.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import streamlit as st

from blue_team_ai.new_log_workspace import prepare_new_log_review
from blue_team_ai.new_log_review import MAX_NEW_LOG_REPORT_BYTES
from blue_team_ai.zeek import MAX_LOG_BYTES

st.set_page_config(page_title="DA005 | New-log Review", page_icon=None, layout="wide")
st.markdown(
    "<style>" + (ROOT / "src/siem_ai/ui.css").read_text(encoding="utf-8") + "</style>",
    unsafe_allow_html=True,
)
st.sidebar.markdown("### SENTINEL LAB / BLUE TEAM")
st.sidebar.caption("Cyber Lab / NEW-log / Read-only")
st.sidebar.warning("Không kết nối mạng, không tạo cảnh báo hoặc SOC case.")
st.title("Cyber Lab · NEW-log AI Review")
st.caption("DA005 / TDTU · Verified offline inference · Analyst workspace")
st.warning(
    "Chỉ kiểm tra dự đoán nghiên cứu từ một conn.log MỚI. "
    "Không phải phát hiện live hoặc tấn công đã xác nhận. "
    "SHA-256 không chứng minh nguồn gốc mô hình, tính đúng nhãn hay cô lập VMware."
)
st.info(
    "Giữ model JSON và SHA-256 được ghi độc lập trong thư mục riêng trên máy. "
    "Dữ liệu TRAIN/VALIDATION/TEST phải được đối chiếu độc lập bằng "
    "scripts/check_zeek_partition_exclusion.py trước khi sử dụng báo cáo này."
)

with st.form("pinned_new_log_review"):
    st.markdown("#### 1. Nguồn và dấu vết độc lập")
    log_file = st.file_uploader(
        "NEW Zeek ASCII conn.log (tối đa 15 MiB)", type=["log"],
        help="Tệp log cục bộ, không tải lên GitHub.",
    )
    report_file = st.file_uploader(
        "NEW-log prediction JSON (tối đa 16 MiB)", type=["json"],
        help="Báo cáo gốc từ scripts/score_zeek_new_log.py.",
    )
    model_path = st.text_input(
        "Đường dẫn tuyệt đối đến model JSON riêng tư trên máy",
        placeholder="C:/DA005-private/zeek-experiment/zeek-research-model.json",
    )
    col1, col2 = st.columns(2)
    expected_model_sha256 = col1.text_input(
        "Model SHA-256 đã ghi độc lập (64 ký tự hex thường)", max_chars=64,
    )
    expected_log_sha256 = col2.text_input(
        "NEW-log SHA-256 đã ghi độc lập (64 ký tự hex thường)", max_chars=64,
    )
    cidr_input = st.text_input(
        "CIDR Host-only được phép (1–4 dải, ngăn cách bằng dấu phẩy)",
        placeholder="192.168.56.0/24",
    )
    verified = st.form_submit_button("Xác minh và xem ứng viên nghiên cứu")

if verified:
    if log_file is None or report_file is None or not model_path.strip():
        st.error("Cần đủ log gốc, báo cáo JSON và đường dẫn model riêng tư.")
    elif log_file.size > MAX_LOG_BYTES or report_file.size > MAX_NEW_LOG_REPORT_BYTES:
        st.error("Tệp vượt giới hạn kích thước; không xử lý.")
    else:
        cidrs = [part.strip() for part in cidr_input.split(",") if part.strip()]
        if not 1 <= len(cidrs) <= 4:
            st.error("Phải khai báo từ 1 đến 4 CIDR được phép.")
        else:
            try:
                with st.spinner("Đang đối chiếu toàn bộ dự đoán với model và log gốc..."):
                    verified_result = prepare_new_log_review(
                        source_data=log_file.getvalue(),
                        report_data=report_file.getvalue(),
                        model_path=model_path.strip(),
                        expected_log_sha256=expected_log_sha256.strip(),
                        expected_model_sha256=expected_model_sha256.strip(),
                        lab_cidrs=cidrs,
                    )
            except (ValueError, TypeError, OSError, UnicodeError, OverflowError, RecursionError) as exc:
                st.error(f"Từ chối xác minh: {exc}")
            else:
                review = verified_result["review"]
                st.success("Báo cáo khớp toàn bộ dự đoán được tính lại từ model và log đã ghim.")
                a, b, c = st.columns(3)
                a.metric("Flow đã xác minh", review["flow_count"])
                b.metric("Ứng viên nghiên cứu", review["research_candidate_count"])
                c.metric("Flow trong cửa sổ hiển thị", verified_result["visible_flow_count"])
                st.caption(
                    f"Ngưỡng validation: {verified_result['validation_threshold']:.4f} · "
                    f"SHA-256 báo cáo: {review['report_sha256']} · "
                    f"SHA-256 phạm vi CIDR: {verified_result['declared_scope_sha256']}"
                )
                st.markdown("#### 2. Ứng viên AI để nhà phân tích xem xét")
                rows = verified_result["candidate_rows"]
                if rows:
                    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
                else:
                    st.info("Không có ứng viên trong 500 dòng Zeek đầu.")
                st.caption(
                    "Chỉ hiển thị ứng viên thuộc 500 dòng đầu, sắp xếp theo xác suất. "
                    "Không hiển thị ground truth; không ghi SQLite hoặc tạo alert."
                )
                st.markdown("#### 3. Giới hạn bằng chứng")
                st.warning(
                    "TRAIN/VALIDATION/TEST exclusion: CHƯA xác minh trên trang này. "
                    "Host-only isolation, model authorship, ground truth, attack detection: CHƯA xác minh. "
                    "Muốn tạo hồ sơ Unclassified có xác nhận thủ công, dùng "
                    "scripts/triage_zeek_new_log.py cùng manifest được ghim độc lập."
                )
