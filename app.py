"""DA005 SOC Console — educational, offline, explainable SIEM prototype."""
from __future__ import annotations

import html
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import plotly.express as px
import streamlit as st

from siem_ai.core import (
    CASE_STATES, create_case, list_cases, update_case, validate_flows, assess_signal, flow_id,
    case_evidence, case_history
)
from siem_ai.model import load_local_model, model_artifact_signature, predict_batch
from siem_ai.export import safe_csv_bytes
from siem_ai.thresholds import threshold_diagnostics
from siem_ai.explain import global_feature_importance
from siem_ai.official_comparison import load_official_comparison
from siem_ai.case_report import export_case_report
from siem_ai.hunting import filter_hunting_flows
from siem_ai.upload import read_uploaded_flows
from siem_ai.ui_components import (
    priority_band_from_probability,
    render_confusion_matrix_html,
    render_empty_state,
    render_flow_evidence_card,
    render_footer,
    render_mode_banner,
    render_provenance_strip,
    render_sidebar_brand,
    style_chart,
)

st.set_page_config(
    page_title="DA005 | Sentinel Lab", page_icon=None,
    layout="wide", initial_sidebar_state="expanded"
)

# Styling is isolated from inference and case-management logic.
# All injected HTML/CSS is trusted static project code (no uploaded flow values).
st.markdown("<style>" + (ROOT / "src/siem_ai/ui.css").read_text(encoding="utf-8") + "</style>",
            unsafe_allow_html=True)

DB = ROOT / "runtime" / "soc_cases.sqlite3"
DATA = ROOT / "data/raw/unsw_nb15"
ARTIFACT = ROOT / "artifacts/unsw_binary_rf.joblib"
METRICS = ROOT / "artifacts/metrics.json"
OFFICIAL_METRICS = ROOT / "reports/official_baseline_metrics.json"
OFFICIAL_COMPARISON = ROOT / "reports/official_locked_threshold_comparison.json"


@st.cache_data(show_spinner=False)
def load_official(path: str, limit: int) -> pd.DataFrame:
    return pd.read_csv(path, nrows=limit)


@st.cache_resource(show_spinner="Đang tải mô hình AI...")
def cached_model(path: str, artifact_signature: tuple[int, int]):
    # Streamlit includes artifact_signature in the cache key, so replacing a
    # locally trained model at the same path invalidates the cached instance.
    return load_local_model(path)


# Uses .soc-brand and .soc-hero design tokens from src/siem_ai/ui.css
render_sidebar_brand(
    workspace_title="Dataset Mode",
    workspace_mode="UNSW-NB15 Offline",
    mode_variant="dataset",
)

st.sidebar.markdown("### 01 · Dữ liệu đầu vào")
mode = st.sidebar.radio("Nguồn phân tích", ["UNSW-NB15 test", "Tải lên CSV"], index=0,
                        help="UNSW-NB15 test là dữ liệu lịch sử để đánh giá; CSV là tệp bạn tự chọn.")
sample_size = st.sidebar.slider("Số bản ghi phân tích", 100, 10000, 2500, step=100,
                                help="Chỉ đọc N dòng đầu để dashboard phản hồi nhanh; không phải toàn bộ test.")
st.sidebar.caption("Phân tích ngoại tuyến · Không thu thập gói tin trực tiếp.")
st.sidebar.divider()
st.sidebar.markdown("### 02 · Trạng thái phân tích")
trained = ARTIFACT.is_file()
if trained:
    st.sidebar.markdown(
        '<div class="soc-sidebar-flag soc-sidebar-flag--ready">'
        '<strong>AI sẵn sàng</strong><br>Mô hình Random Forest đã có trên máy, có thể dự đoán.'
        '</div>', unsafe_allow_html=True,
    )
else:
    st.sidebar.markdown(
        '<div class="soc-sidebar-flag"><strong>Chế độ khám phá</strong><br>'
        'Chưa có mô hình AI cục bộ. Chỉ hiển thị dữ liệu gốc.</div>',
        unsafe_allow_html=True,
    )
    st.sidebar.caption("Huấn luyện: python scripts/train_siem.py")
with st.sidebar.expander("Hướng dẫn sử dụng nhanh"):
    st.markdown(
        "**1. Tổng quan:** xem số lượng và phân bố network flow.\n\n"
        "**2. Threat hunting:** lọc giao thức, dịch vụ, trạng thái.\n\n"
        "**3. AI & đánh giá:** xem dự đoán, ma trận nhầm lẫn và giới hạn mô hình.\n\n"
        "**4. Trung tâm cảnh báo:** chọn flow nghi vấn để lập hồ sơ.\n\n"
        "**5. SOC case:** đối chiếu bằng chứng và cập nhật hồ sơ điều tra."
    )

st.markdown(
    '<section class="soc-hero">'
    '<div class="soc-hero__eyebrow">TDTU / DA005 · Dataset Mode · Security Operations Console</div>'
    '<h1>Security Operations Center</h1>'
    '<div class="soc-hero__description">Khám phá nhật ký lưu lượng mạng lịch sử, '
    'đánh giá kết quả phát hiện AI và thực hành quy trình điều tra cảnh báo SOC trong một giao diện thống nhất.</div>'
    '<div class="soc-hero__meta">'
    '<span class="soc-pill">Dữ liệu: UNSW-NB15 · Ngoại tuyến</span>'
    '<span class="soc-pill ' + ('soc-pill--ready' if trained else 'soc-pill--pending') + '">'
    + ('AI đã có mô hình (Random Forest)' if trained else 'AI chưa huấn luyện (Khám phá)') + '</span>'
    '<span class="soc-pill">Phạm vi nghiên cứu · Không giám sát trực tiếp</span>'
    '</div></section>', unsafe_allow_html=True,
)
st.markdown(
    render_mode_banner(
        "DATASET BENCHMARK · OFFLINE",
        "Phạm vi dữ liệu lịch sử (UNSW-NB15)",
        "Tập train/test UNSW-NB15 không chứa IP và timestamp sự kiện gốc; thứ tự dòng không phải chuỗi thời gian thực. "
        "Các phân hệ Zeek Lab (Blue Team) và Scenario Planner (Red Team · Execution OFF) nằm riêng trong thanh điều hướng bên trái.",
        variant="dataset",
    ),
    unsafe_allow_html=True,
)
with st.expander("Mới bắt đầu? Đọc cách sử dụng và thuật ngữ SOC", expanded=False):
    st.markdown(
        "**Flow:** bản ghi tóm tắt một luồng giao tiếp mạng, không phải một gói tin.\n\n"
        "**Attack (nhãn gốc):** đáp án đã gán sẵn trong bộ dữ liệu; không đồng nghĩa AI dự đoán đúng.\n\n"
        "**AI dự đoán Attack:** mô hình coi flow có dấu hiệu tấn công; vẫn có thể báo nhầm (False Positive).\n\n"
        "**SOC case:** hồ sơ điều tra tạo từ một cảnh báo, có bằng chứng snapshot và lịch sử xử lý trong SQLite.\n\n"
        "**Quy trình đề xuất:** Tổng quan → Threat hunting → AI & đánh giá → Trung tâm cảnh báo → SOC case management."
    )

source_display = "UNSW-NB15 testing-set.csv"
if mode == "UNSW-NB15 test":
    source = DATA / "UNSW_NB15_testing-set.csv"
    if not source.exists():
        st.error("Chưa có dataset. Chạy python scripts/download_unsw_nb15.py")
        st.stop()
    frame = load_official(str(source), sample_size)
else:
    uploaded = st.sidebar.file_uploader("Tải CSV có cấu trúc UNSW-NB15", type=["csv"])
    if uploaded is None:
        st.markdown(
            render_empty_state(
                "Chưa chọn tệp CSV đầu vào",
                "Chế độ Tải lên CSV đang hoạt động. Hệ thống chỉ xử lý sau khi bạn nạp một tệp CSV hợp lệ có cấu trúc đặc trưng UNSW-NB15 (tối đa 15 MiB).",
                "Chọn tệp CSV ở thanh bên trái để bắt đầu hoặc chuyển về nguồn UNSW-NB15 test.",
            ),
            unsafe_allow_html=True,
        )
        st.info("Chọn tệp CSV để bắt đầu. Không tải lên dữ liệu nhạy cảm.")
        st.stop()
    if uploaded.size > 15 * 1024 * 1024:
        st.error("Giới hạn mỗi tệp 15 MB cho bản demo.")
        st.stop()
    try:
        frame = read_uploaded_flows(uploaded.getvalue(), limit=sample_size)
    except (ValueError, TypeError) as exc:
        st.error(f"Tệp CSV không hợp lệ: {exc}")
        st.stop()
    source_display = f"CSV tải lên: {uploaded.name}"

try:
    frame = validate_flows(frame)
except (ValueError, TypeError) as exc:
    st.error(str(exc))
    st.stop()

model = None
if trained:
    try:
        model = cached_model(str(ARTIFACT), model_artifact_signature(ARTIFACT))
    except Exception as exc:
        st.error(f"Không thể tải mô hình tin cậy cục bộ: {exc}")

try:
    predictions = predict_batch(model, frame) if model is not None else None
except (ValueError, KeyError) as exc:
    st.error(f"Dữ liệu chưa tương thích với mô hình: {exc}")
    predictions = None

results = frame.reset_index(drop=True).copy()
if predictions is not None:
    results["AI_verdict"] = predictions["verdict"].to_numpy()
    results["AI_attack_probability"] = predictions["attack_probability"].to_numpy()
results["flow_ref"] = [flow_id(row) for row in results.to_dict("records")]

tabs = st.tabs(["Tổng quan an ninh", "Threat hunting", "AI & đánh giá", "Trung tâm cảnh báo", "SOC case management"])
with tabs[0]:
    st.subheader("Tổng quan lưu lượng mạng")
    st.markdown('<p class="soc-intro">Các con số dưới đây phản ánh mẫu dữ liệu lịch sử đang nạp; '
                'không phải số liệu giám sát mạng thời gian thực.</p>', unsafe_allow_html=True)
    st.markdown(
        render_provenance_strip([
            ("Nguồn dữ liệu", source_display),
            ("Phạm vi mẫu", f"{len(results):,} flows đầu (limit {sample_size:,})"),
            ("Mô hình AI", "Random Forest cục bộ" if predictions is not None else "Chưa tải / Chế độ khám phá"),
            ("Chế độ thu thập", "Offline · Không có live sensor"),
        ]),
        unsafe_allow_html=True,
    )
    attack_observed = int((results["label"] == 1).sum()) if "label" in results else None
    ai_attack = int((results["AI_verdict"] == "Attack").sum()) if predictions is not None else None
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Flows đã đọc", f"{len(results):,}")
    col2.metric("Attack trong nhãn gốc", f"{attack_observed:,}" if attack_observed is not None else "Không có nhãn")
    col3.metric("AI dự đoán Attack", f"{ai_attack:,}" if ai_attack is not None else "Chưa huấn luyện")
    col4.metric("Hồ sơ SOC", f"{len(list_cases(DB)):,}")
    st.caption("Nhãn gốc là đáp án trong dataset; AI dự đoán là kết quả mô hình. Hai số không nhất thiết giống nhau.")

    if predictions is not None:
        probs = results["AI_attack_probability"]
        crit_n = int((probs >= 0.90).sum())
        high_n = int(((probs >= 0.80) & (probs < 0.90)).sum())
        med_n = int(((probs >= 0.65) & (probs < 0.80)).sum())
        low_n = int(((probs >= 0.50) & (probs < 0.65)).sum())
        norm_n = int((probs < 0.50).sum())
        st.markdown(
            '<div class="soc-card">'
            '<div class="soc-card__header">'
            '<div><div class="soc-card__title">Phân tầng ưu tiên điều tra theo xác suất AI (Mẫu đang xem)</div>'
            '<div class="soc-card__sub">Phân nhóm theo xác suất P(Attack) của mô hình để hỗ trợ sắp thứ tự kiểm tra, không phải mức độ sự cố xác nhận.</div></div>'
            '</div>'
            '<div style="display:flex;flex-wrap:wrap;gap:8px;">'
            f'<span class="soc-badge soc-badge--critical">[CRIT] &ge; 0.90: {crit_n:,}</span>'
            f'<span class="soc-badge soc-badge--high">[HIGH] 0.80–0.89: {high_n:,}</span>'
            f'<span class="soc-badge soc-badge--medium">[MED] 0.65–0.79: {med_n:,}</span>'
            f'<span class="soc-badge soc-badge--low">[LOW] 0.50–0.64: {low_n:,}</span>'
            f'<span class="soc-badge soc-badge--info">[INFO] Normal &lt; 0.50: {norm_n:,}</span>'
            '</div></div>',
            unsafe_allow_html=True,
        )

    left, right = st.columns(2)
    with left:
        st.subheader("Phân bố giao thức")
        fig = px.bar(
            results["proto"].value_counts().head(10).reset_index(),
            x="proto", y="count", labels={"proto": "Giao thức", "count": "Số flow"},
            color_discrete_sequence=["#245eea"],
        )
        st.plotly_chart(style_chart(fig), use_container_width=True)
    with right:
        st.subheader("Loại tấn công được gán nhãn (ground truth)")
        if "attack_cat" in results:
            counts = results["attack_cat"].fillna("Normal").value_counts().head(10).reset_index()
            fig = px.bar(counts, x="attack_cat", y="count",
                         labels={"attack_cat": "Loại tấn công", "count": "Số flow"},
                         color_discrete_sequence=["#0d9488"])
            st.plotly_chart(style_chart(fig), use_container_width=True)
        else:
            st.markdown(
                render_empty_state(
                    "Không có cột nhãn tấn công (attack_cat)",
                    "Tệp CSV đang tải không chứa nhãn ground truth. Hệ thống vẫn hiển thị đặc trưng lưu lượng và dự đoán AI (nếu có mô hình).",
                ),
                unsafe_allow_html=True,
            )
    st.caption("Dữ liệu được hiển thị theo thứ tự gốc của tập kiểm thử, không phải chuỗi thời gian sự kiện.")

with tabs[1]:
    st.subheader("Threat hunting · Tìm dấu hiệu bất thường")
    st.caption("Thu hẹp dữ liệu bằng giao thức, dịch vụ và trạng thái kết nối. Lọc không làm thay đổi kết quả AI.")
    f1, f2, f3 = st.columns(3)
    filter_proto = f1.multiselect("Giao thức", sorted(results["proto"].dropna().astype(str).unique().tolist()))
    filter_service = f2.multiselect("Dịch vụ", sorted(results["service"].dropna().astype(str).unique().tolist()))
    filter_state = f3.multiselect("Trạng thái kết nối", sorted(results["state"].dropna().astype(str).unique().tolist()))
    only_attack = False
    min_probability = None
    if predictions is not None:
        a1, a2, a3 = st.columns([1.2, 1.3, 1.5])
        only_attack = a1.checkbox("Chỉ những flow AI dự đoán Attack")
        use_min_prob = a2.checkbox("Lọc theo xác suất Attack tối thiểu")
        if use_min_prob:
            min_probability = a3.slider("Xác suất Attack tối thiểu", 0.0, 1.0, 0.8, 0.05)
    filtered = filter_hunting_flows(
        results, protocols=filter_proto, services=filter_service,
        states=filter_state, only_ai_attacks=only_attack,
        min_attack_probability=min_probability,
    )
    st.caption(f"Đang hiển thị {len(filtered):,}/{len(results):,} flow của mẫu đã tải; bộ lọc không áp dụng cho toàn bộ tập dữ liệu.")
    fields = [c for c in ["flow_ref", "proto", "service", "state", "dur", "sbytes", "dbytes", "rate",
                           "AI_verdict", "AI_attack_probability", "label", "attack_cat"] if c in filtered]
    if filtered.empty:
        st.markdown(
            render_empty_state(
                "Không có flow nào khớp bộ lọc hiện tại",
                "0 dòng kết quả chỉ phản ánh phạm vi điều kiện lọc trên mẫu đang tải, KHÔNG có nghĩa là tập dữ liệu an toàn.",
                "Hãy xóa bớt điều kiện Giao thức / Dịch vụ / Trạng thái hoặc giảm ngưỡng xác suất tối thiểu.",
            ),
            unsafe_allow_html=True,
        )
    else:
        display_df = filtered[fields].copy()
        if "AI_attack_probability" in display_df:
            display_df.insert(
                display_df.columns.get_loc("AI_attack_probability") + 1,
                "AI_priority",
                [priority_band_from_probability(p)["label"] for p in display_df["AI_attack_probability"]],
            )
        st.dataframe(display_df, use_container_width=True, hide_index=True, height=430)
    st.download_button("Xuất kết quả lọc (CSV)", data=safe_csv_bytes(filtered[fields]),
        file_name="da005_hunting_results.csv", mime="text/csv")

with tabs[2]:
    st.subheader("AI & đánh giá · Mô hình có đáng tin không?")
    st.caption("Precision: cảnh báo Attack đúng bao nhiêu. Recall: phát hiện được bao nhiêu Attack thật. F1: cân bằng cả hai.")
    if not trained:
        st.info("Máy chưa có mô hình để dự đoán. Có thể xem benchmark đã chạy trên GitHub Actions.")
        st.code("pip install -r requirements-app.txt\npython scripts/train_siem.py\nstreamlit run app.py")
    if METRICS.exists() or OFFICIAL_METRICS.exists():
        report_file = METRICS if METRICS.exists() else OFFICIAL_METRICS
        metrics = json.loads(report_file.read_text(encoding="utf-8"))
        st.caption(f"Benchmark đã đo trên tập test chính thức ({report_file.name}); các điểm này KHÔNG phải kết quả của vài dòng CSV đang xem.")
        report = metrics["classification_report"]
        a, b, c = st.columns(3)
        a.metric("Attack precision", f"{report['1']['precision']:.1%}")
        b.metric("Attack recall", f"{report['1']['recall']:.1%}")
        c.metric("Attack F1", f"{report['1']['f1-score']:.1%}")

        cm_col, note_col = st.columns([1.35, 1])
        with cm_col:
            st.markdown(
                render_confusion_matrix_html(
                    metrics["confusion_matrix_0_1"],
                    average_precision=metrics.get("average_precision_attack"),
                    train_size=metrics.get("train_size"),
                    test_size=metrics.get("test_size"),
                ),
                unsafe_allow_html=True,
            )
        with note_col:
            cm_vals = metrics["confusion_matrix_0_1"]
            fp_count = int(cm_vals[0][1])
            fn_count = int(cm_vals[1][0])
            st.markdown(
                '<div class="soc-card">'
                '<div class="soc-card__header"><div class="soc-card__title">Ý nghĩa vận hành SOC (Baseline 0,50)</div></div>'
                f'<p style="font-size:0.88rem;margin:0 0 8px;"><strong>Gánh nặng cảnh báo nhầm (FP):</strong> {fp_count:,} flows bình thường bị gắn nhãn Attack, '
                'đòi hỏi chuyên viên SOC tốn thời gian sàng lọc nếu dùng trực tiếp ngưỡng 0,50.</p>'
                f'<p style="font-size:0.88rem;margin:0 0 8px;"><strong>Rủi ro bỏ sót (FN):</strong> {fn_count:,} flows tấn công không bị gắn nhãn ở ngưỡng 0,50.</p>'
                '<p style="font-size:0.84rem;color:#52637b;margin:0;">Cơ chế: Random Forest học từ tập train, kiểm thử trên tập test độc lập; '
                'các cột nhãn (label, attack_cat, id) bị loại khỏi đầu vào.</p>'
                '</div>',
                unsafe_allow_html=True,
            )
            with st.expander("Xem JSON metrics gốc", expanded=False):
                st.json({
                    "confusion_matrix_normal_attack": metrics["confusion_matrix_0_1"],
                    "average_precision_attack": metrics["average_precision_attack"],
                    "train_size": metrics["train_size"],
                    "test_size": metrics["test_size"],
                })
    else:
        st.warning("Có mô hình nhưng thiếu số liệu đánh giá đi kèm.")

    st.divider()
    st.subheader("So sánh ngưỡng đã khóa · official UNSW-NB15 test")
    st.caption(
        "Kết quả thực nghiệm trên toàn bộ tập test chính thức, đọc từ báo cáo đã lưu; "
        "KHÔNG phải phân tích các dòng đang xem và KHÔNG cần tải mô hình cục bộ."
    )
    if OFFICIAL_COMPARISON.exists():
        try:
            comparison = load_official_comparison(OFFICIAL_COMPARISON)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            st.warning(f"Báo cáo so sánh ngưỡng không hợp lệ: {exc}")
        else:
            rows = []
            for title, result in [("Baseline 0,50", comparison["baseline"]),
                                  ("Validation-locked 0,55", comparison["candidate"])]:
                rows.append({
                    "Ngưỡng": title, "TP": result["true_positive"],
                    "FP": result["false_positive"], "TN": result["true_negative"],
                    "FN": result["false_negative"],
                    "Precision": f'{result["precision_attack"]:.2%}',
                    "Recall": f'{result["recall_attack"]:.2%}',
                    "F1": f'{result["f1_attack"]:.2%}',
                })
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
            fp_col, fn_col = st.columns(2)
            fp_col.metric("Thay đổi cảnh báo nhầm (FP)", f'{comparison["delta_false_positive_candidate_minus_baseline"]:+,}')
            fn_col.metric("Thay đổi tấn công bỏ sót (FN)", f'{comparison["delta_false_negative_candidate_minus_baseline"]:+,}')
            st.caption(
                f'Nguồn: reports/official_locked_threshold_comparison.json · '
                f'{comparison["test_rows"]:,} flows · '
                f'Validation run #{comparison["validation_selection_run_id"]} · '
                f'Test run #{comparison["evaluation_run_id"]}. '
                "Dấu âm là giảm; không điều chỉnh ngưỡng theo kết quả test."
            )
            st.warning(
                "Đánh đổi: giảm false positives có thể làm tăng false negatives. "
                "Đây là kết quả trên dữ liệu nghiên cứu, không phải hiệu năng thực tế. "
                "Ngưỡng Alert Queue không bị thay đổi tự động."
            )
    else:
        st.info("Chưa có báo cáo so sánh ngưỡng official test trong repository.")

    st.divider()
    st.subheader("AI Explainability · mức độ quan trọng đặc trưng")
    if model is None:
        st.info("Cần mô hình Random Forest tin cậy đã huấn luyện để xem feature importance.")
    else:
        try:
            importance = global_feature_importance(model)
        except (ValueError, KeyError, AttributeError) as exc:
            st.warning(f"Không thể phân tích feature importance cho mô hình này: {exc}")
        else:
            st.caption(
                "Đây là mức độ giảm độ hỗn tạp (MDI / Gini importance) của Random Forest "
                "trên mô hình đã huấn luyện; các cột one-hot được cộng lại theo đặc trưng đầu vào. "
                "Không phải giải thích riêng cho một flow, không chứng minh quan hệ nhân quả. "
                "MDI có thể thiên lệch đối với biến nhiều giá trị."
            )
            top_features = importance.head(12).sort_values("importance", ascending=True)
            st.plotly_chart(
                style_chart(px.bar(top_features, x="importance_percent", y="feature", orientation="h",
                       labels={"importance_percent": "Mức quan trọng MDI (%)",
                               "feature": "Đặc trưng mạng"},
                       color_discrete_sequence=["#245eea"]), height=405),
                use_container_width=True,
            )
            with st.expander("Bảng chi tiết toàn bộ đặc trưng MDI", expanded=False):
                st.dataframe(
                    importance.rename(columns={
                        "feature": "Đặc trưng", "importance": "MDI",
                        "importance_percent": "MDI (%)", "encoded_dimensions": "Số chiều sau mã hóa",
                    }),
                    hide_index=True, use_container_width=True,
                )
            st.download_button(
                "Xuất bảng MDI (CSV)", data=safe_csv_bytes(importance),
                file_name="da005_global_feature_importance.csv", mime="text/csv",
            )

    st.divider()
    st.subheader("Phân tích ngưỡng cảnh báo · tập dữ liệu đang xem")
    st.caption(
        "Chỉ là phân tích chẩn đoán trên các flow đang tải (thường là N dòng đầu), "
        "KHÔNG phải benchmark chính thức, không đại diện toàn bộ test set. "
        "Không chọn ngưỡng tối ưu dựa trên tập test."
    )
    if predictions is None:
        st.info("Cần mô hình AI đã huấn luyện để phân tích ngưỡng.")
    elif "label" not in results:
        st.info("CSV không có nhãn gốc 0/1; chỉ có thể xem số cảnh báo, không thể tính Precision/Recall.")
        counts = pd.DataFrame({
            "Ngưỡng": [0.5, 0.6, 0.7, 0.8, 0.9],
            "Số cảnh báo": [
                int((results["AI_attack_probability"] >= t).sum())
                for t in [0.5, 0.6, 0.7, 0.8, 0.9]
            ],
        })
        st.dataframe(counts, hide_index=True, use_container_width=True)
    elif results["label"].isna().any() or not results["label"].isin([0, 1]).all():
        st.warning("Nhãn gốc phải đầy đủ và chỉ gồm 0/1; bỏ qua đánh giá theo ngưỡng.")
    else:
        diagnostic = threshold_diagnostics(
            results["label"].to_numpy(),
            results["AI_attack_probability"].to_numpy(),
        )
        st.dataframe(
            diagnostic.rename(columns={
                "threshold": "Ngưỡng", "true_positive": "TP", "false_positive": "FP",
                "true_negative": "TN", "false_negative": "FN",
                "precision_attack": "Precision", "recall_attack": "Recall",
                "f1_attack": "F1", "false_positive_rate": "FPR", "alerts": "Cảnh báo",
            }),
            hide_index=True, use_container_width=True,
        )
        curves = diagnostic.melt(
            id_vars="threshold",
            value_vars=["precision_attack", "recall_attack", "false_positive_rate"],
            var_name="metric", value_name="value",
        )
        st.plotly_chart(
            style_chart(px.line(
                curves, x="threshold", y="value", color="metric", markers=True,
                labels={"threshold": "Ngưỡng", "value": "Tỷ lệ", "metric": "Chỉ số"},
                color_discrete_sequence=["#245eea", "#0d9488", "#d97706"],
            ), height=335, legend=True),
            use_container_width=True,
        )

with tabs[3]:
    st.subheader("Trung tâm cảnh báo · Các flow AI nghi vấn")
    st.caption("Chọn ngưỡng xác suất để xem danh sách flow cần điều tra. Tăng ngưỡng có thể giảm báo nhầm nhưng bỏ sót tấn công.")
    if predictions is None:
        st.markdown(
            render_empty_state(
                "Chưa thể tạo hàng đợi cảnh báo AI",
                "Chưa có mô hình AI cục bộ để chấm điểm xác suất Attack trên tập dữ liệu đang nạp.",
                "Chạy `python scripts/train_siem.py` hoặc nạp artifact mô hình hợp lệ vào thư mục `artifacts/`.",
            ),
            unsafe_allow_html=True,
        )
        st.info("Không tạo cảnh báo AI khi chưa có mô hình. Hãy huấn luyện trước.")
    else:
        t_left, t_right = st.columns([2, 1])
        threshold = t_left.slider("Ngưỡng xác suất Attack", 0.5, 0.99, 0.8, 0.01)
        alerts = results[results["AI_attack_probability"] >= threshold].sort_values(
            "AI_attack_probability", ascending=False)
        t_right.metric("Cảnh báo ở ngưỡng hiện tại", len(alerts))

        if len(alerts) == 0:
            st.markdown(
                render_empty_state(
                    "Không có cảnh báo nào vượt ngưỡng xác suất đã chọn",
                    f"Ở ngưỡng P(Attack) >= {threshold:.2f}, không có flow nào trong {len(results):,} flow đang tải bị gắn cờ. "
                    "Điều này KHÔNG đồng nghĩa không có lưu lượng tấn công ở dưới ngưỡng.",
                    "Hãy hạ thanh trượt Ngưỡng xác suất Attack hoặc dùng tab Threat hunting để kiểm tra các flow theo giao thức/dịch vụ.",
                ),
                unsafe_allow_html=True,
            )
        else:
            p_series = alerts["AI_attack_probability"]
            a_crit = int((p_series >= 0.90).sum())
            a_high = int(((p_series >= 0.80) & (p_series < 0.90)).sum())
            a_other = int((p_series < 0.80).sum())
            st.markdown(
                '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px;">'
                f'<span class="soc-badge soc-badge--critical">[CRIT] &ge; 0.90: {a_crit:,}</span>'
                f'<span class="soc-badge soc-badge--high">[HIGH] 0.80–0.89: {a_high:,}</span>'
                f'<span class="soc-badge soc-badge--medium">[MED/LOW] &lt; 0.80: {a_other:,}</span>'
                '<span class="soc-badge soc-badge--info">Hiển thị tối đa 300 flow điểm cao nhất</span>'
                '</div>',
                unsafe_allow_html=True,
            )
            preview = [c for c in ["flow_ref", "proto", "service", "state", "AI_attack_probability", "sbytes", "dbytes"] if c in alerts]
            alert_display = alerts[preview].head(300).copy()
            alert_display.insert(
                alert_display.columns.get_loc("AI_attack_probability") + 1,
                "Mức ưu tiên",
                [priority_band_from_probability(p)["label"] for p in alert_display["AI_attack_probability"]],
            )
            st.dataframe(alert_display, hide_index=True, use_container_width=True, height=340)

            choices = alerts.index.tolist()[:300]
            selected = st.selectbox("Chọn flow để lập hồ sơ điều tra", choices,
                                    format_func=lambda i: f"Flow {results.loc[i, 'flow_ref']} · p={results.loc[i, 'AI_attack_probability']:.1%}")
            row = results.loc[selected].to_dict()
            band = priority_band_from_probability(row.get("AI_attack_probability"))
            risk, reasons = assess_signal(row)
            st.markdown(
                render_flow_evidence_card(
                    row,
                    title=f"Kiểm tra nhanh Flow {row.get('flow_ref', '')}",
                    subtitle="Thông số kỹ thuật trích trực tiếp từ mẫu đang nạp trước khi tạo hồ sơ SOC.",
                    badge_text=str(band["label"]),
                    badge_class=str(band["badge_class"]),
                ),
                unsafe_allow_html=True,
            )
            rule_summary = "; ".join(reasons) if reasons else "Không kích hoạt quy tắc mẫu bổ sung"
            st.markdown(
                '<div class="soc-card">'
                f'<div class="soc-card__title" style="font-size:0.88rem;">Tín hiệu quy tắc phụ trợ (không phải kết luận tấn công) · Điểm heuristic: {risk}/100</div>'
                f'<div class="soc-card__sub" style="margin-top:4px;color:#14253f;">{html.escape(rule_summary)}</div>'
                '</div>',
                unsafe_allow_html=True,
            )
            if st.button("Tạo SOC case từ flow đã chọn", type="primary"):
                case_id = create_case(DB, row=row, verdict=row["AI_verdict"],
                    confidence=float(row["AI_attack_probability"]))
                st.success(f"Đã lưu case #{case_id} trong SQLite cục bộ.")

with tabs[4]:
    st.subheader("SOC case · Hồ sơ và lịch sử điều tra")
    st.caption("Mỗi case lưu một flow nghi vấn, kết quả AI, bằng chứng và diễn biến xử lý trong SQLite cục bộ.")
    cases = list_cases(DB)
    if cases.empty:
        st.markdown(
            render_empty_state(
                "Chưa có hồ sơ SOC nào trong cơ sở dữ liệu cục bộ",
                "Cơ sở dữ liệu SQLite (`runtime/soc_cases.sqlite3`) hiện đang trống.",
                "Chuyển sang tab Trung tâm cảnh báo, chọn một flow vượt ngưỡng và nhấn 'Tạo SOC case từ flow đã chọn'.",
            ),
            unsafe_allow_html=True,
        )
        st.info("Chưa có hồ sơ điều tra. Tạo case từ tab Trung tâm cảnh báo sau khi có mô hình AI.")
    else:
        st.dataframe(cases, hide_index=True, use_container_width=True, height=250)
        picked = st.selectbox("Chọn hồ sơ", cases["case_id"].tolist(),
            format_func=lambda x: f"Case #{x}")
        current = cases.loc[cases["case_id"] == picked].iloc[0]
        evidence = case_evidence(DB, picked)
        conf_val = current["confidence"]
        conf_text = f"{float(conf_val):.2%}" if pd.notna(conf_val) else "N/A"
        band = priority_band_from_probability(float(conf_val)) if pd.notna(conf_val) else priority_band_from_probability(None)

        detail_left, detail_right = st.columns([1.15, 1])
        with detail_left:
            st.markdown(
                render_provenance_strip([
                    ("Case ID", f"#{int(picked)}"),
                    ("AI Verdict", str(current["verdict"])),
                    ("Confidence", conf_text),
                    ("Trạng thái hiện tại", str(current["state"])),
                ]),
                unsafe_allow_html=True,
            )
            st.markdown(
                render_flow_evidence_card(
                    evidence,
                    title=f"Bằng chứng lưu khi mở Case #{int(picked)}",
                    subtitle=f"Flow ID: {current['flow_id']} · Cập nhật: {current['updated_at']}",
                    badge_text=str(band["label"]),
                    badge_class=str(band["badge_class"]),
                ),
                unsafe_allow_html=True,
            )
            with st.expander("Xem toàn bộ snapshot JSON gốc (flow_evidence)", expanded=False):
                st.json(evidence)
            try:
                report_json = export_case_report(DB, int(picked))
            except (ValueError, OSError, sqlite3.DatabaseError) as exc:
                st.warning(f"Không thể xuất hồ sơ: {exc}")
            else:
                st.download_button(
                    "Xuất hồ sơ điều tra (JSON)",
                    data=report_json,
                    file_name=f"da005_soc_case_{picked}.json",
                    mime="application/json",
                )
                st.caption("Bản xuất từ SQLite cục bộ; có thể chứa ghi chú nhạy cảm, không có chữ ký chống sửa đổi.")

        with detail_right:
            st.markdown("**Lịch sử điều tra (audit trail)**")
            history = case_history(DB, picked)
            if history.empty:
                st.caption("Hồ sơ được tạo trước khi có audit trail nên chưa có lịch sử.")
            else:
                st.dataframe(history, hide_index=True, use_container_width=True, height=210)
            st.markdown("**Cập nhật diễn biến xử lý**")
            state = st.selectbox("Trạng thái xử lý", CASE_STATES,
                index=CASE_STATES.index(current["state"]))
            note = st.text_area("Ghi chú điều tra (bắt buộc)", value=str(current["analyst_note"]),
                max_chars=2000, help="Ghi lại bằng chứng, đánh giá và hướng xử lý.")
            if st.button("Lưu diễn biến điều tra", type="primary"):
                try:
                    update_case(DB, picked, state, note)
                    st.success("Đã cập nhật hồ sơ.")
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))

st.markdown(render_footer(), unsafe_allow_html=True)
