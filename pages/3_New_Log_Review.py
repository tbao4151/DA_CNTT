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
from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import
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
    st.markdown("##### Tùy chọn: đối chiếu PCAP gốc đã import offline")
    offline_import_report_path = st.text_input(
        "Đường dẫn offline_import_report.json riêng tư",
        placeholder="C:/DA005-private/capture/zeek-run/offline_import_report.json",
    )
    offline_import_report_sha256 = st.text_input(
        "SHA-256 báo cáo import đã ghi độc lập (64 ký tự hex thường)", max_chars=64,
    )
    offline_import_pcap_path = st.text_input(
        "Đường dẫn PCAP gốc riêng tư",
        placeholder="C:/DA005-private/capture/original.pcap",
    )
    st.caption("Để trống cả ba trường nếu không có PCAP gốc. Khi sử dụng phải điền đủ; "
               "cả lúc xem và lúc ghi SOC đều xác minh lại PCAP/conn.log.")
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
                    pcap_options = (
                        offline_import_report_path.strip(),
                        offline_import_report_sha256.strip(),
                        offline_import_pcap_path.strip(),
                    )
                    if any(pcap_options) and not all(pcap_options):
                        raise ValueError("All three pinned PCAP fields are required")
                    pinned_pcap = None
                    if all(pcap_options):
                        import_report = Path(pcap_options[0])
                        pinned_pcap = verify_offline_pcap_import(
                            import_report,
                            expected_report_sha256=pcap_options[1],
                            pcap_path=Path(pcap_options[2]),
                            log_path=import_report.parent / "conn.log",
                            lab_cidrs=cidrs,
                        )
                        if (pinned_pcap["zeek_conn_sha256"] != expected_log_sha256.strip()
                                or hashlib.sha256(log_file.getvalue()).hexdigest()
                                != pinned_pcap["zeek_conn_sha256"]):
                            raise ValueError("Uploaded Zeek log differs from pinned PCAP import")
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
                if pinned_pcap is not None:
                    st.caption("PCAP gốc/Zeek/import report: SHA-256 và CIDR đã kiểm tra lại. "
                               "Không chứng minh nguồn thu thập hoặc cô lập VMware.")
                else:
                    st.caption("PCAP gốc: chưa xác minh (không khai báo provenance).")
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
                        st.caption(
                            "Tùy chọn: liên kết research queue JSON đã xuất vào audit tạo case. "
                            "Điền đủ ba trường hoặc để trống cả ba; không tự tạo queue."
                        )
                        research_queue_path = st.text_input(
                            "Research queue JSON riêng tư (tùy chọn)",
                            placeholder="C:/DA005-private/new-capture/research-alerts.json",
                        )
                        research_queue_sha = st.text_input(
                            "Research queue SHA-256 ghi độc lập (tùy chọn)", max_chars=64,
                        )
                        research_queue_ref = st.text_input(
                            "Research alert reference từ queue đã xuất (tùy chọn)",
                            max_chars=64,
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
                                offline_import_report_path=(pcap_options[0] or None),
                                offline_import_report_sha256=(pcap_options[1] or None),
                                offline_import_pcap_path=(pcap_options[2] or None),
                                research_alert_bundle_path=(research_queue_path.strip() or None),
                                expected_research_alert_bundle_sha256=(research_queue_sha.strip() or None),
                                research_alert_ref=(research_queue_ref.strip() or None),
                            )
                        except (ValueError, TypeError, OSError, UnicodeError, OverflowError, RecursionError):
                            st.error(
                                "Từ chối ghi SOC. Kiểm tra lại xác nhận, model, manifest, "
                                "log, CIDR, research queue và SQLite riêng tư; không có kết luận tấn công."
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


# Independent read-only SOC history browser: works without re-uploading the
# model or original Zeek capture. No state transition or case creation here.
import json
import sqlite3
from blue_team_ai.case_workspace import list_private_zeek_cases, read_private_zeek_case

st.markdown("#### 5. Hồ sơ SOC nghiên cứu đã lưu (chỉ đọc)")
with st.expander("Xem bằng chứng và lịch sử điều tra từ SQLite riêng tư"):
    st.caption(
        "Chỉ đọc hồ sơ Zeek Unclassified trong cơ sở dữ liệu cục bộ ngoài Git. "
        "Không chỉnh sửa trạng thái, không xác thực tấn công và không tạo alert. "
        "Chỉ mở Streamlit trên máy tin cậy: hồ sơ có thể chứa IP và ghi chú riêng tư."
    )
    viewer_db = st.text_input(
        "Đường dẫn tuyệt đối tới SQLite SOC riêng tư (.sqlite3)",
        placeholder="C:/DA005-private/soc/cyber_lab_cases.sqlite3",
        key="zeek_soc_viewer_db_input",
    )
    if st.button("Đọc danh sách hồ sơ đã lưu", key="zeek_soc_viewer_load"):
        st.session_state["zeek_soc_viewer_active_db"] = viewer_db.strip()
    active_db = st.session_state.get("zeek_soc_viewer_active_db")
    if active_db:
        try:
            case_index = list_private_zeek_cases(active_db)
            if not case_index["cases"]:
                st.info("Không có hồ sơ Zeek Unclassified phù hợp trong phạm vi đọc.")
            else:
                st.dataframe(
                    pd.DataFrame(case_index["cases"]),
                    hide_index=True, use_container_width=True,
                )
                if case_index["limited"]:
                    st.caption(
                        "Danh sách giới hạn 100 hồ sơ Zeek gần nhất, "
                        "quét tối đa 500 hồ sơ Unclassified; không phải toàn bộ DB."
                    )
                case_ids = [item["case_id"] for item in case_index["cases"]]
                selected_case_id = st.selectbox(
                    "Chọn hồ sơ để xem bằng chứng và audit",
                    case_ids, format_func=lambda value: f"SOC case #{value}",
                    key="zeek_soc_viewer_case_id",
                )
                snapshot = read_private_zeek_case(active_db, selected_case_id)
                st.caption(
                    f"Case #{selected_case_id} · "
                    f"Trạng thái: {snapshot['case']['state']} · "
                    "Unclassified (chưa xác minh tấn công)"
                )
                st.markdown("**Bằng chứng network flow lưu trong case**")
                st.json(snapshot["flow_evidence"])
                st.markdown("**Lịch sử audit (theo event ID)**")
                if snapshot["case_events"]:
                    st.dataframe(
                        pd.DataFrame(snapshot["case_events"]),
                        hide_index=True, use_container_width=True,
                    )
                else:
                    st.info("Hồ sơ này chưa có sự kiện audit.")
                if snapshot["history_truncated"]:
                    st.warning("Chỉ hiển thị 200 sự kiện audit mới nhất.")
                st.caption(
                    "Bản xuất JSON chỉ là snapshot SQLite có thể sửa đổi, "
                    "không có chữ ký số hoặc bảo đảm pháp chứng."
                )
                st.download_button(
                    "Tải JSON hồ sơ nghiên cứu (riêng tư)",
                    data=(json.dumps(
                        snapshot, indent=2, ensure_ascii=False, allow_nan=False,
                    ) + "\n").encode("utf-8"),
                    file_name=f"zeek-research-case-{selected_case_id}.json",
                    mime="application/json",
                    key="zeek_soc_viewer_download",
                )
        except (ValueError, OSError, sqlite3.DatabaseError, TypeError):
            st.error(
                "Không thể đọc hồ sơ SOC riêng tư. Kiểm tra tệp SQLite hiện có, "
                "quyền truy cập và định dạng; hệ thống không tạo database mới."
            )
