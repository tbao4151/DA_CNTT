"""Offline pinned NEW-log review with optional explicit manual SOC triage.

No live detection, automatic alerts, lab isolation or ground-truth claim.
"""
from __future__ import annotations

import sys
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import pandas as pd
import streamlit as st

from blue_team_ai.new_log_workspace import prepare_new_log_review
from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from evaluate_zeek_lab import MAX_MANIFEST_BYTES, load_experiment_manifest
from blue_team_ai.new_log_review import MAX_NEW_LOG_REPORT_BYTES
from blue_team_ai.zeek import MAX_LOG_BYTES
from triage_zeek_new_log import create_ui_candidate_case

st.set_page_config(page_title="DA005 | New-log Review", page_icon=None, layout="wide")
st.markdown(
    "<style>" + (ROOT / "src/siem_ai/ui.css").read_text(encoding="utf-8") + "</style>",
    unsafe_allow_html=True,
)
st.sidebar.markdown("### SENTINEL LAB / BLUE TEAM")
st.sidebar.caption("Cyber Lab / NEW-log / Pinned partitions / Manual SOC")
st.sidebar.warning("Offline; chỉ tạo SOC case Unclassified khi nhà phân tích xác nhận.")
st.title("Cyber Lab · NEW-log AI Review")
st.caption("DA005 / TDTU · Verified offline inference · Analyst workspace")
st.warning(
    "Chỉ kiểm tra dự đoán nghiên cứu từ một conn.log MỚI. "
    "Không phải phát hiện live hoặc tấn công đã xác nhận. "
    "SHA-256 không chứng minh nguồn gốc mô hình, tính đúng nhãn hay cô lập VMware."
)
st.info(
    "Giữ model JSON và SHA-256 được ghi độc lập trong thư mục riêng trên máy. "
    "Trang này bắt buộc đối chiếu manifest đã ghim SHA-256 với toàn bộ "
    "TRAIN/VALIDATION/TEST gốc, gồm kiểm tra trùng flow theo UID/thời gian/5-tuple. "
    "Đây không phải xác thực lịch sử thu thập hay nguồn gốc nhãn."
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
    manifest_path = st.text_input(
        "Đường dẫn tuyệt đối đến manifest TRAIN/VALIDATION/TEST riêng tư",
        placeholder="C:/DA005-private/zeek-experiment/manifest.json",
    )
    expected_manifest_sha256 = st.text_input(
        "Manifest SHA-256 đã ghi độc lập (64 ký tự hex thường)", max_chars=64,
    )
    cidr_input = st.text_input(
        "CIDR Host-only được phép (1–4 dải, ngăn cách bằng dấu phẩy)",
        placeholder="192.168.56.0/24",
    )
    verified = st.form_submit_button("Xác minh và xem ứng viên nghiên cứu")

if verified:
    st.session_state["new_log_verified"] = True

if st.session_state.get("new_log_verified", False):
    if (log_file is None or report_file is None or not model_path.strip()
            or not manifest_path.strip() or not expected_manifest_sha256.strip()):
        st.session_state["new_log_verified"] = False
        st.error("Cần đủ log, báo cáo, model và manifest kèm SHA-256 độc lập.")
    elif log_file.size > MAX_LOG_BYTES or report_file.size > MAX_NEW_LOG_REPORT_BYTES:
        st.session_state["new_log_verified"] = False
        st.error("Tệp vượt giới hạn kích thước; không xử lý.")
    else:
        cidrs = [part.strip() for part in cidr_input.split(",") if part.strip()]
        if not 1 <= len(cidrs) <= 4:
            st.session_state["new_log_verified"] = False
            st.error("Phải khai báo từ 1 đến 4 CIDR được phép.")
        else:
            try:
                with st.spinner("Đang xác minh manifest, phân vùng và dự đoán AI..."):
                    manifest = Path(manifest_path.strip())
                    if manifest.is_symlink():
                        raise ValueError("Manifest symlink refused")
                    manifest = manifest.resolve(strict=True)
                    if not manifest.is_file() or manifest.is_relative_to(ROOT):
                        raise ValueError("Manifest must be a private regular file outside Git")
                    with manifest.open("rb") as stream:
                        manifest_bytes = stream.read(MAX_MANIFEST_BYTES + 1)
                    expected_manifest = expected_manifest_sha256.strip()
                    if (not 0 < len(manifest_bytes) <= MAX_MANIFEST_BYTES
                            or len(expected_manifest) != 64
                            or any(ch not in "0123456789abcdef" for ch in expected_manifest)
                            or hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest):
                        raise ValueError("Pinned manifest SHA-256 mismatch")
                    captures, loaded_manifest_sha = load_experiment_manifest(
                        manifest, lab_cidrs=cidrs,
                    )
                    if loaded_manifest_sha != expected_manifest:
                        raise ValueError("Manifest changed during validation")
                    dataset = build_labeled_lab_dataset(captures)
                    verified_result = prepare_new_log_review(
                        source_data=log_file.getvalue(),
                        report_data=report_file.getvalue(),
                        model_path=model_path.strip(),
                        expected_log_sha256=expected_log_sha256.strip(),
                        expected_model_sha256=expected_model_sha256.strip(),
                        lab_cidrs=cidrs,
                        declared_dataset=dataset,
                        declared_manifest_sha256=expected_manifest,
                        declared_captures=captures,
                    )
            except (ValueError, TypeError, OSError, UnicodeError, OverflowError, RecursionError):
                st.session_state["new_log_verified"] = False
                st.error("Từ chối xác minh. Kiểm tra tệp và SHA-256 riêng tư trên máy; không hiển thị dữ liệu nhạy cảm.")
            else:
                review = verified_result["review"]
                st.success("Đã đối chiếu phân vùng khai báo và tính lại toàn bộ dự đoán từ model/log đã ghim.")
                a, b, c = st.columns(3)
                a.metric("Flow đã xác minh", review["flow_count"])
                b.metric("Ứng viên nghiên cứu", review["research_candidate_count"])
                c.metric("Flow trong cửa sổ hiển thị", verified_result["visible_flow_count"])
                st.caption(
                    f"Manifest SHA-256: {verified_result['declared_partition_check']['manifest_sha256']} · "
                    "Đã kiểm tra trùng byte và UID/thời gian/5-tuple với nguồn khai báo. "
                    "Không chứng minh lịch sử độc lập. "
                )
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
                    "Không hiển thị ground truth; không tự tạo alert."
                )
                st.markdown("#### 3. Tạo hồ sơ SOC thủ công (tùy chọn)")
                st.caption(
                    "Chỉ ứng viên trong 500 dòng đầu; Zeek row là vị trí gốc, "
                    "không phải thứ tự bảng sau khi sắp xếp. "
                    "Khi ghi, hệ thống tải lại model/manifest gốc và xác minh "
                    "toàn bộ phân vùng, CIDR, báo cáo trước SQLite."
                )
                if rows:
                    with st.form("manual_new_log_soc_case"):
                        labels = [
                            f"Zeek row {row['Zeek row']} · P(Attack) {row['P(Attack) research']:.4f}"
                            for row in rows
                        ]
                        selected = st.selectbox("Chọn ứng viên đã xem xét", labels)
                        db_path = st.text_input(
                            "SQLite SOC riêng tư ngoài Git (.sqlite3)",
                            placeholder="C:/DA005-private/soc/cyber_lab_cases.sqlite3",
                        )
                        analyst_confirmed = st.checkbox(
                            "Tôi đã xem log gốc và bằng chứng của flow này."
                        )
                        operator_confirmed_authorized = st.checkbox(
                            "Tôi xác nhận có quyền sử dụng dữ liệu và phạm vi lab."
                        )
                        operator_confirmed_new_capture = st.checkbox(
                            "Tôi xác nhận NEW log không thuộc TRAIN/VALIDATION/TEST đã đăng ký."
                        )
                        submitted = st.form_submit_button(
                            "Tạo hoặc tái sử dụng hồ sơ Unclassified"
                        )
                    if submitted:
                        try:
                            case_id = create_ui_candidate_case(
                                db_path=db_path.strip(),
                                model_path=model_path.strip(),
                                manifest_path=manifest_path.strip(),
                                expected_manifest_sha256=expected_manifest_sha256.strip(),
                                source_data=log_file.getvalue(),
                                report_data=report_file.getvalue(),
                                expected_log_sha256=expected_log_sha256.strip(),
                                expected_model_sha256=expected_model_sha256.strip(),
                                lab_cidrs=cidrs,
                                record_index=rows[labels.index(selected)]["Zeek row"] - 1,
                                analyst_confirmed=analyst_confirmed,
                                operator_confirmed_authorized=operator_confirmed_authorized,
                                operator_confirmed_new_capture=operator_confirmed_new_capture,
                            )
                        except (ValueError, TypeError, OSError, UnicodeError, OverflowError, RecursionError):
                            st.error(
                                "Từ chối ghi SOC. Kiểm tra lại xác nhận, model, manifest, "
                                "log, CIDR và đường dẫn SQLite riêng tư; không có kết luận tấn công."
                            )
                        else:
                            st.success(
                                f"SOC case #{case_id} (Unclassified). "
                                "Có thể là hồ sơ đã tồn tại; không xác nhận tấn công."
                            )
                else:
                    st.info("Không có ứng viên đủ điều kiện tạo hồ sơ trong 500 dòng đầu.")
                st.markdown("#### 4. Giới hạn bằng chứng")
                st.warning(
                    "Chỉ kiểm tra dữ liệu trong manifest do người vận hành khai báo. "
                    "Lịch sử phân vùng độc lập, cô lập VMware, nguồn gốc model, "
                    "ground truth và phát hiện tấn công thực tế: CHƯA xác minh. "
                    "Hồ sơ SOC là nghiên cứu thủ công, không phải operational alert."
                )
