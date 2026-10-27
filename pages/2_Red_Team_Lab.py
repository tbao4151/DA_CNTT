"""Non-executing Red Team scenario-planning UI; no live attack capability."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import streamlit as st

from red_team_ai.scenario_policy import MAX_FEEDBACK, SCENARIOS, choose_scenario, summarize_feedback
from red_team_ai.synthetic_benchmark import compare_synthetic_policies

st.set_page_config(page_title="DA005 | Red Team Lab", page_icon=None, layout="wide")
st.markdown(
    "<style>" + (ROOT / "src/siem_ai/ui.css").read_text(encoding="utf-8") + "</style>",
    unsafe_allow_html=True,
)
st.sidebar.markdown("### SENTINEL LAB / RED TEAM")
st.sidebar.caption("Offline scenario planner · research preview")
st.sidebar.error("EXECUTION OFF · Không gửi lưu lượng mạng")
st.sidebar.caption("Chuyển sang Cyber Lab để xem log Zeek hoặc Dataset Mode để đánh giá UNSW.")

st.title("Red Team Lab · Scenario Planner")
st.caption("DA005 / TDTU · UCB1 versus seeded random · offline-only")
st.warning(
    "Trang này CHỈ chọn nhãn kịch bản trong danh mục cố định. Không phát traffic, "
    "không điều khiển VMware, không khai thác mục tiêu và không kết nối Blue Team. "
    "Phản hồi do người dùng nhập chưa được xác minh bằng log hoặc bằng chứng SOC."
)

if "red_team_feedback" not in st.session_state:
    st.session_state["red_team_feedback"] = []

feedback = st.session_state["red_team_feedback"]
summary = summarize_feedback(feedback)
col1, col2, col3 = st.columns(3)
col1.metric("Kịch bản offline", len(SCENARIOS))
col2.metric("Phản hồi thủ công", summary["total"])
col3.metric("Kết nối mạng", "TẮT")

st.markdown("### Danh mục kiểm thử được định nghĩa sẵn")
st.dataframe(
    pd.DataFrame([{
        "ID": s.scenario_id, "Kịch bản": s.title,
        "Mục tiêu phân tích": s.objective, "Loại": s.category,
    } for s in SCENARIOS]),
    hide_index=True,
    use_container_width=True,
)
st.caption("Danh mục chỉ chứa mô tả; không chứa IP, lệnh, payload hoặc tệp thực thi.")

st.markdown("### Tác nhân lựa chọn kịch bản")
strategy = st.radio(
    "Chiến lược lựa chọn", ["ucb1", "random"], horizontal=True,
    format_func=lambda v: "UCB1 (exploration/exploitation)" if v == "ucb1" else "Random baseline",
)
seed = st.number_input("Seed của random baseline", min_value=0, max_value=1_000_000, value=42, disabled=strategy != "random")
if st.button("Đề xuất kịch bản (không thực thi)", type="primary"):
    st.session_state["red_team_last_plan"] = choose_scenario(feedback, strategy=strategy, seed=int(seed))

plan = st.session_state.get("red_team_last_plan")
if plan is not None:
    st.success(f"Đề xuất: {plan['title']} ({plan['scenario_id']})")
    st.caption(plan["rationale"])
    st.json(plan)
    st.download_button(
        "Xuất kế hoạch JSON (không có lệnh thực thi)",
        data=json.dumps(plan, ensure_ascii=False, indent=2),
        file_name="red_team_offline_plan.json", mime="application/json",
    )

st.divider()
st.markdown("### Phản hồi giả lập do người vận hành nhập")
st.caption(
    "Chỉ dùng để minh họa cách UCB1 cập nhật lựa chọn. Không nhập kết quả giả làm đo lường thực nghiệm. "
    "Không tự động đánh giá Blue Team; không lưu xuống đĩa."
)
with st.form("manual_red_team_feedback", clear_on_submit=True):
    chosen_id = st.selectbox("Kịch bản đã được xem xét ngoại tuyến", [s.scenario_id for s in SCENARIOS])
    blue_flagged = st.radio("Trong quan sát thủ công, Blue Team có đánh dấu?", [True, False],
                            format_func=lambda v: "Có (flagged)" if v else "Không (unflagged)")
    confirm = st.checkbox("Tôi xác nhận đây là phản hồi thủ công, chưa được kiểm chứng.")
    submitted = st.form_submit_button("Thêm phản hồi", disabled=not confirm or len(feedback) >= MAX_FEEDBACK)
if submitted:
    st.session_state["red_team_feedback"] = [*feedback, {"scenario_id": chosen_id, "blue_flagged": blue_flagged}]
    st.session_state.pop("red_team_last_plan", None)
    st.rerun()

if summary["total"]:
    st.dataframe(pd.DataFrame(summary["scenarios"]), hide_index=True, use_container_width=True)
    st.caption("Unflagged fraction là phản hồi tự nhập, không phải attack success rate hoặc AI recall.")

if st.button("Dừng phiên lập kế hoạch và xóa phản hồi", type="secondary"):
    st.session_state["red_team_feedback"] = []
    st.session_state.pop("red_team_last_plan", None)
    st.rerun()

st.info("Không có tiến trình tấn công để dừng. Tính năng kill switch cho traffic thật chưa được triển khai.")

st.divider()
st.markdown("### So sánh UCB1 và Random trên dữ liệu TỔNG HỢP")
st.warning(
    "Đây là thí nghiệm mô phỏng Bernoulli có xác suất được đặt trước, KHÔNG có "
    "Blue Team AI thật, log VMware hay hoạt động tấn công. Kết quả KHÔNG phải "
    "tỷ lệ phát hiện hoặc thành công ngoài thực tế."
)
with st.form("synthetic_policy_comparison"):
    sim_col1, sim_col2, sim_col3 = st.columns(3)
    sim_rounds = sim_col1.number_input("Lượt chọn / lần thử", min_value=3, max_value=500, value=120, step=1)
    sim_trials = sim_col2.number_input("Số lần thử độc lập", min_value=2, max_value=40, value=12, step=1)
    sim_seed = sim_col3.number_input("Seed mô phỏng", min_value=0, max_value=1_000_000, value=42, step=1)
    simulate = st.form_submit_button("Chạy so sánh mô phỏng (không thực thi mạng)")
if simulate:
    st.session_state["red_team_synthetic_comparison"] = compare_synthetic_policies(
        rounds=int(sim_rounds), trials=int(sim_trials), seed=int(sim_seed)
    )
simulation = st.session_state.get("red_team_synthetic_comparison")
if simulation:
    comparison_rows = [
        {
            "Chiến lược": strategy.upper(),
            "Tỷ lệ unflagged mô phỏng (trung bình)": round(
                details["mean_synthetic_unflagged_fraction"], 4
            ),
            "Expected pseudo-regret (trung bình)": round(
                details["mean_expected_pseudo_regret"], 4
            ),
            "Tổng lượt chọn": sum(details["selection_counts"].values()),
        }
        for strategy, details in simulation["policies"].items()
    ]
    st.dataframe(pd.DataFrame(comparison_rows), hide_index=True, use_container_width=True)
    st.caption(
        "Hai thuật toán dùng cùng các kết quả Bernoulli tiềm năng cho mỗi kịch bản/lượt. "
        "Pseudo-regret dựa trên xác suất giả định, không phải độ trễ phát hiện hay số lần tấn công thật."
    )
    st.download_button(
        "Xuất báo cáo mô phỏng JSON",
        data=json.dumps(simulation, ensure_ascii=False, indent=2, allow_nan=False),
        file_name="red_team_synthetic_policy_comparison.json",
        mime="application/json",
    )
