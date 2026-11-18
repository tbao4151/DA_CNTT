# Kế hoạch Thiết kế Lại & Chuẩn hóa UI/UX (Redesign Plan) — DA005 Sentinel Lab

## 1. Định hướng Thị giác & Nguyên tắc Thiết kế

Xây dựng **Sentinel Lab** thành một **Security Operations Console** hiện đại, nghiêm túc, giàu mật độ thông tin hữu ích nhưng có trật tự rõ ràng, giữ nền sáng chuẩn mực để đọc dữ liệu bảng biểu và nhật ký dài liên tục (đồng thời giữ vững hợp đồng kiểm thử `#F3F6FB` / `#FFFFFF` / `#14253F` trong `.streamlit/config.toml` và `tests/test_ui_theme.py`), kết hợp với Sidebar xanh navy đậm (`#111C30`) tạo neo thị giác chuyên nghiệp.

- **Không dùng emoji làm icon trang trí:** Mọi badge và trạng thái sử dụng tiền tố văn bản kỹ thuật chuẩn (`[CRIT]`, `[HIGH]`, `[MED]`, `[LOW]`, `[EXECUTION OFF]`, `[OFFLINE]`) kết hợp typography và mã màu semantic.
- **Không sao chép giao diện mẫu sinh viên:** Loại bỏ các khối JSON thô chắn tầm mắt, thay bằng thẻ tóm tắt thông số kỹ thuật monospace, ma trận nhầm lẫn 2x2 chuẩn mực, toolbar lọc đa chiều và bố cục Master-Detail 2 cột.
- **Phân tách luồng Detection vs Simulation rõ ràng ngay ở tầng thị giác:**
  - **Dataset Benchmark Mode (`app.py`):** Accent **Navy / Cobalt Blue (`#245EEA`)** — Nhãn `HISTORICAL BENCHMARK · UNSW-NB15`.
  - **Blue Team Detection Lab (`pages/1_Cyber_Lab.py`, `pages/3_New_Log_Review.py`):** Accent **Deep Teal (`#0F766E`)** — Nhãn `OFFLINE ZEEK LAB · READ-ONLY / MANUAL TRIAGE`.
  - **Red Team Simulation Planner (`pages/2_Red_Team_Lab.py`):** Accent **Crimson Slate (`#B91C1C`)** — Nhãn `ATTACK SIMULATION PLANNER · EXECUTION OFF`.

---

## 2. Hệ thống Design Tokens (`src/siem_ai/ui.css`)

### 2.1. Bảng màu & Surfaces
- `--soc-bg: #f3f6fb` (Nền ứng dụng chính — giữ nguyên hợp đồng `rgb(243, 246, 251)`)
- `--soc-panel: #ffffff` (Nền thẻ KPI, card, biểu đồ, bảng — giữ nguyên hợp đồng `rgb(255, 255, 255)`)
- `--soc-surface-subtle: #f8fafd` (Nền phụ cho ô metadata, đầu bảng)
- `--soc-ink: #14253f` (Văn bản chính — tương phản > 13:1 trên nền trắng)
- `--soc-muted: #52637b` (Nhãn phụ, caption — tương phản AA > 5.7:1)
- `--soc-border: #dbe4ee` / `--soc-border-strong: #c4d2e4`
- `--soc-primary: #245eea` / `--soc-focus: #65a4ff`
- `--soc-sidebar: #111c30` / `--soc-sidebar-text: #f1f5ff`

### 2.2. Severity & Priority Semantics (AI Score Priority — Không phải Incident Severity xác nhận)
| Mức độ | Ký hiệu | Màu chữ | Màu nền | Màu viền | Quy ước áp dụng (AI Probability) |
| --- | --- | --- | --- | --- | --- |
| **Critical** | `[CRIT]` | `#991b1b` | `#fef2f2` | `#fca5a5` | `P(Attack) >= 0.90` |
| **High** | `[HIGH]` | `#9a3412` | `#fff7ed` | `#fdba74` | `0.80 <= P(Attack) < 0.90` |
| **Medium** | `[MED]` | `#854d0e` | `#fefce8` | `#fde047` | `0.65 <= P(Attack) < 0.80` |
| **Low** | `[LOW]` | `#1e40af` | `#eff6ff` | `#93c5fd` | `0.50 <= P(Attack) < 0.65` |
| **Normal** | `[INFO]` | `#334155` | `#f1f5f9` | `#cbd5e1` | `P(Attack) < 0.50` |

### 2.3. Typography & Spacing Scale
- **Sans-serif:** `--soc-font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;`
- **Monospace:** `--soc-font-mono: 'JetBrains Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace;` dùng cho IP, Port, `uid`, `flow_ref`, SHA-256, metrics bảng, JSON keys và timestamps UTC.
- **Số liệu:** `font-variant-numeric: tabular-nums` trên toàn bộ KPI metric, bảng confusion matrix, bảng logs.
- **Spacing Scale:** Bội số `4px` (`4 / 8 / 12 / 16 / 20 / 24 / 32px`), chiều cao chuẩn button `>= 39px`, bo góc thẻ `12px–16px`.

---

## 3. Kiến trúc Component Dùng Chung (`src/siem_ai/ui_components.py`)

Tạo module `src/siem_ai/ui_components.py` (nằm trong `src/siem_ai/` để các bài test sandbox chỉ copy `app.py` và `src/` vẫn chạy đầy đủ):

1. `style_chart(fig, *, height: int = 310, legend: bool = False)` — Chuẩn hóa mọi biểu đồ Plotly (font, grid, margin, hoverlabel).
2. `render_sidebar_brand(*, workspace_title: str, workspace_mode: str, mode_variant: str = "dataset")` — Header thương hiệu `SENTINEL LAB` thống nhất trên cả 4 trang kèm thẻ chỉ dẫn 4 phân hệ.
3. `priority_band_from_probability(prob: float)` — Trả về label, code (`CRIT/HIGH/MED/LOW/INFO`) và CSS badge class tương ứng.
4. `render_provenance_strip(items: list[tuple[str, str]], *, variant: str = "dataset")` — Thanh hiển thị nguồn dữ liệu, trạng thái mạng (`OFFLINE`), trạng thái AI và phạm vi bản ghi.
5. `render_confusion_matrix_html(cm, ap, train_size, test_size)` — Bảng 2x2 trực quan thay cho `st.json` thô.
6. `render_flow_evidence_card(row, *, title, subtitle)` — Lưới key-value monospace hiển thị thông tin cốt lõi của 1 flow (IP/Port hoặc Flow features UNSW-NB15) an toàn với `html.escape`.
7. `render_empty_state(title, description, hint)` — Khung trạng thái rỗng có hướng dẫn nghiệp vụ rõ ràng.
8. `render_footer()` — Footer đồng nhất cho tất cả các trang.

---

## 4. Lộ Trình Nâng Cấp Theo Từng Màn Hình

| Thứ tự | File mục tiêu | Hạng mục nâng cấp chính | Bảo toàn hợp đồng test |
| :---: | --- | --- | --- |
| 1 | `src/siem_ai/ui.css` | Mở rộng design tokens, badge semantics, hero variants (`--blue`, `--red`), mode banner, kv-grid, cm-table, empty-state, step-header, responsive breakpoints (`1280`, `900`, `768`, `480`). | Giữ `--soc-bg: #f3f6fb`, `--soc-panel: #ffffff`, `:focus-visible`, `prefers-reduced-motion`, `@media(max-width:900px)`, `[data-testid="stMetricValue"]`, không có `#080f1d`. |
| 2 | `src/siem_ai/ui_components.py` | Tách toàn bộ UI primitives & formatters dùng chung, escape HTML chặt chẽ. | Đặt trong `src/siem_ai/` để sandbox test copy tự động nhận diện. |
| 3 | `app.py` | - Sidebar có bản đồ phân hệ.<br>- Tab 0: Thêm Provenance Strip + thống kê phân bố mức ưu tiên AI (khi đã train).<br>- Tab 1: Filter Toolbar 3 cột + Priority Band + Empty State.<br>- Tab 2: Confusion Matrix 2x2 HTML + diễn giải SOC.<br>- Tab 3: Dải đếm ưu tiên + Flow Evidence Card trước khi tạo case + Empty State.<br>- Tab 4: Master-Detail 2 cột (Flow Evidence Card + Expander JSON gốc bên trái, Audit Trail + Form cập nhật bên phải). | Giữ nguyên toàn bộ `st.tabs`, nhãn `st.metric`, nhãn `st.subheader("So sánh ngưỡng đã khóa...")`, nhãn button/selectbox/textarea, đường dẫn `ROOT / "src/siem_ai/ui.css"`. |
| 4 | `pages/1_Cyber_Lab.py` | - Sidebar brand + Hero Blue Team + Mode Banner `OFFLINE ZEEK TELEMETRY`.<br>- Thay `st.bar_chart` bằng Plotly `style_chart`.<br>- Thêm bộ lọc nhanh theo giao thức / tìm IP-UID trong 500 dòng preview.<br>- Thêm `render_flow_evidence_card` cho flow chọn xem xét thủ công + `render_footer()`. | Giữ `st.title("Cyber Lab · Blue Team")` và `st.markdown("### Chưa có dữ liệu Cyber Lab")`. |
| 5 | `pages/2_Red_Team_Lab.py` | - Sidebar brand + Hero Red Team + Mode Banner `ATTACK SIMULATION PLANNER · EXECUTION OFF`.<br>- Thẻ tóm tắt kế hoạch kịch bản + Expander JSON.<br>- Biểu đồ Plotly cho kết quả so sánh Bernoulli UCB1 vs Random.<br>- Thêm `render_footer()`. | Giữ `st.title("Red Team Lab · Scenario Planner")`, metric `"TẮT"`, button `"Đề xuất kịch bản..."`, **tuyệt đối không thêm `st.selectbox` phía trước form `manual_red_team_feedback`**. |
| 6 | `pages/3_New_Log_Review.py` | - Sidebar brand + Hero Blue Team + Mode Banner `PINNED NEW-LOG AI REVIEW`.<br>- Tổ chức form 11 trường thành 4 bước rõ ràng với `.soc-step-header` và `st.columns(2)`.<br>- Thẻ Provenance SHA-256 wrap sạch sẽ + cột Priority Band trong bảng ứng viên.<br>- Master-Detail 2 cột cho Mục 5 (SQLite chỉ đọc) + `render_footer()`. | Giữ `st.title("Cyber Lab · NEW-log AI Review")`, **không gọi `st.success()` khi chưa submit xác minh**, giữ nguyên mọi nhãn `st.text_input` bắt buộc. |
| 7 | `docs/USING_DASHBOARD.md` & `docs/ui-audit/UI_REDESIGN_REPORT.md` | Cập nhật tài liệu hướng dẫn và viết báo cáo nghiệm thu before/after. | Không sửa `docs/SENTINEL_LAB_IMPLEMENTATION_STATUS.md` để giữ nguyên contract tests. |
