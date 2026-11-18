# Ma trận Tương đương Tính năng (Feature Parity Matrix) — DA005 Sentinel Lab

> Theo dõi tiến độ chuyển đổi toàn bộ tính năng từ Streamlit (`app.py`, `pages/*.py`) sang FastAPI (`src/api/`) và Next.js (`frontend/src/`).  
> Quy ước trạng thái: `PLANNED` → `IN_PROGRESS` → `IMPLEMENTED` → `VERIFIED`.

---

## 1. System & Provenance

| Tính năng | Original Streamlit | Backend API (`/api/v1/...`) | Next.js UI | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| Kiểm tra trạng thái backend, dataset, model cục bộ & SQLite | Kiểm tra trực tiếp trong `app.py` (`ARTIFACT.is_file()`, `source.exists()`) | `GET /api/v1/health`, `GET /api/v1/system/status` | Header/Sidebar status chip trong `AppShell.tsx` + nút retry khi mất kết nối | `tests/test_api_v1.py` | `PLANNED` |
| Phân biệt 4 phân hệ & chế độ vận hành | `render_sidebar_brand`, `.soc-mode-banner` | `GET /api/v1/system/status` trả cờ an toàn (`live_capture_enabled=false`, `red_team_execution_enabled=false`) | Collapsible Sidebar phân nhóm Blue Team Detection vs Red Team (`EXECUTION OFF`) | Visual QA (Gate C) | `PLANNED` |

---

## 2. Module 1 — Dataset SOC (`app.py` → `/`)

| Tính năng | Original Streamlit | Backend API (`/api/v1/...`) | Next.js UI | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| Chọn nguồn `UNSW-NB15 test` & số bản ghi (`100..10.000`) | `load_official`, `validate_flows`, `predict_batch` | `GET /api/v1/dataset/overview?source=official&sample_size=2500` | Thanh Data Source Control & slider/selector số bản ghi ở `frontend/src/app/page.tsx` | `tests/test_api_v1.py` | `PLANNED` |
| Tải lên CSV có kiểm tra UTF-8, NUL, cột trùng, schema | `read_uploaded_flows`, `validate_flows` | `POST /api/v1/dataset/upload-csv` (trả `upload_id` phiên trong RAM) | Panel Upload CSV kèm cảnh báo kích thước (`<= 15 MiB`) & thông báo lỗi chi tiết | `tests/test_api_v1.py` | `PLANNED` |
| Tổng quan an ninh: 4 KPI, phân bố ưu tiên AI, biểu đồ giao thức & attack_cat | Tab 0 trong `app.py` | `GET /api/v1/dataset/overview` | Tab `Tổng quan` với KPI cards tabular-nums, thanh phân bố ưu tiên, 2 biểu đồ cột + case gần nhất | Visual QA & API test | `PLANNED` |
| Threat hunting: lọc đa chiều, tìm kiếm, sắp xếp, phân trang, xuất CSV | `filter_hunting_flows`, `safe_csv_bytes` (Tab 1) | `GET /api/v1/dataset/hunting`, `GET /api/v1/dataset/hunting/export-csv` | Tab `Threat hunting`: Filter toolbar, active filter chips, sortable/paginated table, nút Export CSV, `FlowInspectorDrawer` | `tests/test_api_v1.py` | `PLANNED` |
| AI & đánh giá: Benchmark metrics, Confusion Matrix 2x2, So sánh ngưỡng 0.50 vs 0.55, MDI Feature Importance, Chẩn đoán ngưỡng | Tab 2 trong `app.py`, `load_official_comparison`, `global_feature_importance`, `threshold_diagnostics` | `GET /api/v1/dataset/evaluation` | Tab `AI & đánh giá`: Ma trận nhầm lẫn 2x2 kèm diễn giải FP/FN, bảng so sánh ngưỡng đã khóa, biểu đồ MDI top 12 + bảng 42 đặc trưng, bảng & đường cong ngưỡng | `tests/test_api_v1.py` | `PLANNED` |
| Trung tâm cảnh báo: thanh trượt ngưỡng (`0.50..0.99`), phân tầng ưu tiên, heuristic `assess_signal`, tạo SOC case | Tab 3 trong `app.py`, `assess_signal`, `create_case` | `GET /api/v1/dataset/alerts`, `POST /api/v1/soc/cases` | Tab `Trung tâm cảnh báo`: Slider ngưỡng, dải đếm ưu tiên, bảng cảnh báo, panel điều tra nhanh + nút `Tạo SOC case` | `tests/test_api_v1.py` | `PLANNED` |
| Quản lý hồ sơ SOC: danh sách case, lọc trạng thái, snapshot bằng chứng, audit trail, cập nhật trạng thái & xuất JSON | Tab 4 trong `app.py`, `list_cases`, `case_evidence`, `case_history`, `update_case`, `export_case_report` | `GET /api/v1/soc/cases`, `GET /api/v1/soc/cases/{id}`, `PATCH /api/v1/soc/cases/{id}`, `GET /api/v1/soc/cases/{id}/export` | Tab `SOC case management`: Bố cục Master-Detail 2 cột, lọc theo `CASE_STATES`, Timeline Audit, Form cập nhật trạng thái/ghi chú & tải JSON | `tests/test_api_v1.py` | `PLANNED` |

---

## 3. Module 2 — Cyber Lab / Offline Zeek (`pages/1_Cyber_Lab.py` → `/cyber-lab`)

| Tính năng | Original Streamlit | Backend API (`/api/v1/...`) | Next.js UI | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| Đọc & xác thực `conn.log` ngoại tuyến (<= 15 MiB, <= 10.000 flows) | `parse_zeek_conn_log`, `summarize_offline_flows` | `POST /api/v1/cyber-lab/parse-log` | Khu vực Upload `conn.log` (kèm tùy chọn nạp synthetic fixture được gắn nhãn rõ để kiểm thử UI) | `tests/test_api_v1.py` | `PLANNED` |
| Thống kê provenance (SHA-256, khung UTC), phân bố giao thức & bảng 500 dòng có lọc proto/IP/UID | `pages/1_Cyber_Lab.py` | Dữ liệu trả về từ `parse-log` (500 dòng đầu + summary) | Thẻ SHA-256 đầy đủ có nút copy, 3 KPI, biểu đồ giao thức, bảng Zeek lọc nhanh + `FlowInspectorDrawer` | Visual QA | `PLANNED` |
| Đối chiếu JSON `held-out prediction trace` (chỉ đọc) | `review_private_zeek_trace` | `POST /api/v1/cyber-lab/review-trace` | Panel nạp trace JSON, hiện bảng ứng viên nghiên cứu không lộ nhãn thật | `tests/test_api_v1.py` | `PLANNED` |
| Mở hồ sơ thủ công hoặc từ ứng viên nghiên cứu (`Unclassified`) & xuất JSON đã đối chiếu | `create_offline_review_case`, `create_research_candidate_case`, `export_verified_offline_case` | `POST /api/v1/cyber-lab/manual-case`, `POST /api/v1/cyber-lab/research-candidate-case` | Khối xác nhận điều tra viên (checkbox bắt buộc) + tải JSON verified | `tests/test_api_v1.py` | `PLANNED` |

---

## 4. Module 3 — Red Team Lab (`pages/2_Red_Team_Lab.py` → `/red-team-lab`)

| Tính năng | Original Streamlit | Backend API (`/api/v1/...`) | Next.js UI | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| Hiển thị trạng thái `EXECUTION OFF`, danh mục kịch bản & timeline audit | `SCENARIOS`, `export_planning_audit`, `summarize_feedback` | `GET /api/v1/red-team/state` | Banner đỏ `EXECUTION OFF`, 3 KPI, bảng danh mục kịch bản & timeline phiên | `tests/test_api_v1.py` | `PLANNED` |
| Đề xuất kịch bản theo `UCB1` / `Random (seed)` & xuất JSON kế hoạch | `choose_scenario`, `append_proposal` | `POST /api/v1/red-team/propose` | Panel chọn chiến lược/seed, thẻ kế hoạch đang chờ phản hồi & nút xuất JSON | `tests/test_api_v1.py` | `PLANNED` |
| Nhập phản hồi quan sát thủ công (yêu cầu checkbox xác nhận) & reset phiên | `append_manual_feedback` | `POST /api/v1/red-team/feedback`, `POST /api/v1/red-team/reset` | Form phản hồi gắn đúng `pending_proposal_id`, bảng tổng hợp tỷ lệ unflagged | `tests/test_api_v1.py` | `PLANNED` |
| Benchmark tổng hợp Bernoulli (`UCB1` vs `Random`) | `compare_synthetic_policies` | `POST /api/v1/red-team/synthetic-benchmark` | Form cấu hình rounds/trials/seed, bảng kết quả & 2 biểu đồ so sánh gắn nhãn `SYNTHETIC` | `tests/test_api_v1.py` | `PLANNED` |

---

## 5. Module 4 — New Log Review (`pages/3_New_Log_Review.py` → `/new-log-review`)

| Tính năng | Original Streamlit | Backend API (`/api/v1/...`) | Next.js UI | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| Cổng xác minh đa tầng: `conn.log` + `prediction JSON` + `model JSON` + `manifest TRAIN/VAL/TEST` + SHA-256 + CIDR + tùy chọn PCAP gốc | `load_experiment_manifest`, `build_labeled_lab_dataset`, `verify_offline_pcap_import`, `prepare_new_log_review` | `POST /api/v1/new-log-review/verify` | Wizard 4 bước gọn gàng (`1A → 1D`), chỉ báo trạng thái 4 cổng xác minh & bảng ứng viên AI | `tests/test_api_v1.py` | `PLANNED` |
| Tạo/tái sử dụng hồ sơ `Unclassified` có 3 cam kết bắt buộc & liên kết Research Queue tùy chọn | `create_ui_candidate_case` | `POST /api/v1/new-log-review/create-case` | Form xác nhận 3 checkbox + tùy chọn Research Alert Queue | `tests/test_api_v1.py` | `PLANNED` |
| Trình đọc hồ sơ SOC riêng tư ở chế độ chỉ đọc (`mode=ro`) | `list_private_zeek_cases`, `read_private_zeek_case` | `POST /api/v1/new-log-review/private-cases/list`, `POST /api/v1/new-log-review/private-cases/detail` | Tab `Hồ sơ SOC riêng tư (Chỉ đọc)` dạng Master-Detail 2 cột + tải JSON snapshot | `tests/test_api_v1.py` | `PLANNED` |
