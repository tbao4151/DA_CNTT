"""DA005 SOC Console — educational, offline, explainable SIEM prototype."""
from __future__ import annotations

import json
import os
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
from siem_ai.model import load_local_model, predict_batch
from siem_ai.export import safe_csv_bytes
from siem_ai.thresholds import threshold_diagnostics

st.set_page_config(
    page_title="DA005 | Sentinel Lab", page_icon=None,
    layout="wide", initial_sidebar_state="expanded"
)

st.markdown("""
<style>
[data-testid="stAppViewContainer"] {background: #080f1d; color: #e4edf8;}
[data-testid="stSidebar"] {background: #0e192a;}
[data-testid="stHeader"] {background: transparent;}
h1,h2,h3 {letter-spacing: -.025em;}
div[data-testid="stMetric"] {background:#14243a; border:1px solid #27405b; padding:18px; border-radius:12px;}
div[data-testid="stAlert"] {border-radius:10px;}
.stButton>button {border-radius:9px;}
.block-container {padding-top:2.2rem;}
</style>
""", unsafe_allow_html=True)

DB = ROOT / "runtime" / "soc_cases.sqlite3"
DATA = ROOT / "data/raw/unsw_nb15"
ARTIFACT = ROOT / "artifacts/unsw_binary_rf.joblib"
METRICS = ROOT / "artifacts/metrics.json"
OFFICIAL_METRICS = ROOT / "reports/official_baseline_metrics.json"


@st.cache_data(show_spinner=False)
def load_official(path: str, limit: int) -> pd.DataFrame:
    return pd.read_csv(path, nrows=limit)


@st.cache_resource(show_spinner="Đang tải mô hình AI...")
def cached_model(path: str):
    return load_local_model(path)


st.sidebar.markdown("## DA005 / SENTINEL LAB")
st.sidebar.caption("TDTU · Mini-SIEM + AI · SOC workflow")
st.sidebar.divider()
mode = st.sidebar.radio("Nguồn phân tích", ["UNSW-NB15 test", "Tải lên CSV"], index=0)
sample_size = st.sidebar.slider("Số bản ghi phân tích", 100, 10000, 2500, step=100)
st.sidebar.caption("Chạy trên dữ liệu lịch sử; không thu thập mạng thời gian thực.")
st.sidebar.divider()
st.sidebar.markdown("**Trạng thái mô hình**")
trained = ARTIFACT.exists()
st.sidebar.write("Đã huấn luyện / có thể dự đoán" if trained else "Chưa có mô hình · chỉ khám phá dữ liệu")
st.sidebar.caption("Để huấn luyện: python scripts/train_siem.py")

st.title("DA005 · Network Security Operations")
st.caption("Bảng điều khiển Mini-SIEM giáo dục | Dự án CNTT | Dữ liệu UNSW-NB15")
st.warning("MÔ PHỎNG: Không phải SIEM triển khai thật; không có IP và timestamp gốc trong bản train/test UNSW-NB15.")

if mode == "UNSW-NB15 test":
    source = DATA / "UNSW_NB15_testing-set.csv"
    if not source.exists():
        st.error("Chưa có dataset. Chạy python scripts/download_unsw_nb15.py")
        st.stop()
    frame = load_official(str(source), sample_size)
else:
    uploaded = st.sidebar.file_uploader("Tải CSV có cấu trúc UNSW-NB15", type=["csv"])
    if uploaded is None:
        st.info("Chọn tệp CSV để bắt đầu. Không tải lên dữ liệu nhạy cảm.")
        st.stop()
    if uploaded.size > 15 * 1024 * 1024:
        st.error("Giới hạn mỗi tệp 15 MB cho bản demo.")
        st.stop()
    try:
        frame = pd.read_csv(uploaded, nrows=sample_size)
    except (ValueError, UnicodeDecodeError, pd.errors.ParserError) as exc:
        st.error(f"Tệp không đọc được: {exc}")
        st.stop()

try:
    frame = validate_flows(frame)
except (ValueError, TypeError) as exc:
    st.error(str(exc))
    st.stop()

model = None
if trained:
    try:
        model = cached_model(str(ARTIFACT))
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
    attack_observed = int((results["label"] == 1).sum()) if "label" in results else None
    ai_attack = int((results["AI_verdict"] == "Attack").sum()) if predictions is not None else None
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Flows đã đọc", f"{len(results):,}")
    col2.metric("Attack trong nhãn gốc", f"{attack_observed:,}" if attack_observed is not None else "Không có nhãn")
    col3.metric("AI dự đoán Attack", f"{ai_attack:,}" if ai_attack is not None else "Chưa huấn luyện")
    col4.metric("Hồ sơ SOC", f"{len(list_cases(DB)):,}")
    left, right = st.columns(2)
    with left:
        st.subheader("Phân bố giao thức")
        st.plotly_chart(px.bar(results["proto"].value_counts().head(10).reset_index(),
            x="proto", y="count", labels={"proto":"Protocol","count":"Flows"}), use_container_width=True)
    with right:
        st.subheader("Loại tấn công được gán nhãn (ground truth)")
        if "attack_cat" in results:
            counts = results["attack_cat"].fillna("Normal").value_counts().head(10).reset_index()
            st.plotly_chart(px.bar(counts, x="attack_cat", y="count",
                labels={"attack_cat":"Nhãn gốc","count":"Flows"}), use_container_width=True)
        else:
            st.info("Không có nhãn, không thể hiển thị ground truth.")
    st.caption("Dữ liệu được hiển thị theo thứ tự gốc của tập kiểm thử, không phải chuỗi thời gian sự kiện.")
with tabs[1]:
    st.subheader("Truy vấn và phân tích flow")
    filter_proto = st.multiselect("Giao thức", sorted(results["proto"].dropna().astype(str).unique().tolist()))
    filtered = results[results["proto"].astype(str).isin(filter_proto)] if filter_proto else results
    if predictions is not None:
        only_attack = st.checkbox("Chỉ những flow AI dự đoán Attack")
        if only_attack:
            filtered = filtered[filtered["AI_verdict"] == "Attack"]
    fields = [c for c in ["flow_ref","proto","service","state","dur","sbytes","dbytes","rate",
                           "AI_verdict","AI_attack_probability","label","attack_cat"] if c in filtered]
    st.dataframe(filtered[fields], use_container_width=True, hide_index=True, height=420)
    st.download_button("Xuất kết quả lọc (CSV)", data=safe_csv_bytes(filtered[fields]),
        file_name="da005_hunting_results.csv", mime="text/csv")
with tabs[2]:
    st.subheader("Kiểm tra mô hình AI")
    if not trained:
        st.info("Máy chưa có mô hình để dự đoán. Có thể xem benchmark đã chạy trên GitHub Actions.")
        st.code("pip install -r requirements-app.txt\npython scripts/train_siem.py\nstreamlit run app.py")
    if METRICS.exists() or OFFICIAL_METRICS.exists():
        report_file = METRICS if METRICS.exists() else OFFICIAL_METRICS
        metrics = json.loads(report_file.read_text(encoding="utf-8"))
        st.caption("Benchmark đã đo trên tập test chính thức; các điểm này KHÔNG phải kết quả của CSV đang xem.")
        report = metrics["classification_report"]
        a, b, c = st.columns(3)
        a.metric("Attack precision", f"{report['1']['precision']:.1%}")
        b.metric("Attack recall", f"{report['1']['recall']:.1%}")
        c.metric("Attack F1", f"{report['1']['f1-score']:.1%}")
        st.json({"confusion_matrix_normal_attack":metrics["confusion_matrix_0_1"],
                 "average_precision_attack":metrics["average_precision_attack"],
                 "train_size":metrics["train_size"],"test_size":metrics["test_size"]})
    else:
        st.warning("Có mô hình nhưng thiếu số liệu đánh giá đi kèm.")
    st.markdown("**Cơ chế:** Random Forest học từ tập train, kiểm thử trên tập test độc lập. Cột nhãn không được đưa vào đầu vào.")

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
            px.line(curves, x="threshold", y="value", color="metric", markers=True,
                    labels={"threshold": "Ngưỡng", "value": "Tỷ lệ", "metric": "Chỉ số"},
                    title="Đánh đổi giữa Precision, Recall và False Positive Rate"),
            use_container_width=True,
        )

with tabs[3]:
    st.subheader("Alert Queue · chỉ từ dự đoán mô hình")
    if predictions is None:
        st.info("Không tạo cảnh báo AI khi chưa có mô hình. Hãy huấn luyện trước.")
    else:
        threshold = st.slider("Ngưỡng xác suất Attack", 0.5, 0.99, 0.8, 0.01)
        alerts = results[results["AI_attack_probability"] >= threshold].sort_values(
            "AI_attack_probability", ascending=False)
        st.metric("Cảnh báo ở ngưỡng hiện tại", len(alerts))
        preview = [c for c in ["flow_ref","proto","service","state","AI_attack_probability","sbytes","dbytes"] if c in alerts]
        st.dataframe(alerts[preview].head(300), hide_index=True, use_container_width=True)
        if len(alerts):
            choices = alerts.index.tolist()[:300]
            selected = st.selectbox("Chọn flow để lập hồ sơ điều tra", choices,
                                    format_func=lambda i: f"Flow {results.loc[i, 'flow_ref']} · p={results.loc[i, 'AI_attack_probability']:.1%}")
            row = results.loc[selected].to_dict()
            risk, reasons = assess_signal(row)
            st.write("Tín hiệu quy tắc (phụ trợ, không phải kết luận):", "; ".join(reasons) if reasons else "Không có tín hiệu theo quy tắc mẫu")
            if st.button("Tạo SOC case từ flow đã chọn", type="primary"):
                case_id = create_case(DB, row=row, verdict=row["AI_verdict"],
                    confidence=float(row["AI_attack_probability"]))
                st.success(f"Đã lưu case #{case_id} trong SQLite cục bộ.")
with tabs[4]:
    st.subheader("SOC Investigation Workspace")
    cases = list_cases(DB)
    if cases.empty:
        st.info("Chưa có hồ sơ điều tra. Tạo case từ tab Trung tâm cảnh báo sau khi có mô hình AI.")
    else:
        st.dataframe(cases, hide_index=True, use_container_width=True, height=280)
        picked = st.selectbox("Chọn hồ sơ", cases["case_id"].tolist(),
            format_func=lambda x: f"Case #{x}")
        current = cases.loc[cases["case_id"] == picked].iloc[0]
        st.markdown("**Bằng chứng lưu khi tạo hồ sơ (flow snapshot)**")
        st.json(case_evidence(DB, picked))
        st.markdown("**Lịch sử điều tra (audit trail)**")
        history = case_history(DB, picked)
        if history.empty:
            st.caption("Hồ sơ được tạo trước khi có audit trail nên chưa có lịch sử.")
        else:
            st.dataframe(history, hide_index=True, use_container_width=True)
        state = st.selectbox("Trạng thái xử lý", CASE_STATES,
            index=CASE_STATES.index(current["state"]))
        note = st.text_area("Ghi chú điều tra (bắt buộc)", value=str(current["analyst_note"]),
            max_chars=2000, help="Ghi lại bằng chứng, đánh giá và hướng xử lý.")
        if st.button("Lưu diễn biến điều tra"):
            try:
                update_case(DB, picked, state, note)
                st.success("Đã cập nhật hồ sơ.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
st.divider()
st.caption("DA005 · Nguyễn Văn Thiên Bảo / Đặng Triệu Vỹ · GVHD: Trương Đình Tú · Chỉ dùng cho nghiên cứu/học tập.")
