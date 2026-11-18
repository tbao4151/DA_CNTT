# Kiến trúc Di chuyển Frontend: Next.js + FastAPI — DA005 Sentinel Lab

**Nhánh làm việc:** `feature/nextjs-fastapi-soc-ui` (tách từ `main` tại `b4e38e9`)  
**Phương án dự phòng (Fallback):** Ứng dụng Streamlit hiện tại (`app.py`, `pages/*.py`) trên `main` và trên nhánh này vẫn được giữ nguyên 100%, không xóa hoặc phá vỡ hợp đồng kiểm thử cũ.

---

## 1. Sơ đồ Kiến trúc Đích

```text
+-------------------------------------------------------------------+
|  Next.js Frontend (frontend/, App Router, TypeScript, Tailwind)   |
|  Port: http://127.0.0.1:3000                                      |
|  - /                 -> Dataset SOC (UNSW-NB15 / CSV)             |
|  - /cyber-lab        -> Blue Team Offline Zeek Explorer           |
|  - /red-team-lab     -> Red Team Scenario Planner (EXECUTION OFF) |
|  - /new-log-review   -> Pinned NEW-Log AI Review + RO SQLite      |
+---------------------------------+---------------------------------+
                                  | HTTP REST JSON (/api/v1/...)
                                  | CORS: localhost:3000 / 127.0.0.1:3000
+---------------------------------v---------------------------------+
|  FastAPI Adapter Layer (src/api/main.py, src/api/schemas.py)      |
|  Port: http://127.0.0.1:8000 (OpenAPI: /docs)                     |
|  - Stateless adapter & bounded in-memory session cache            |
|  - Validates uploads, file sizes, paths, and error mapping        |
+---------------------------------+---------------------------------+
                                  | Direct Python calls (NO rewrites)
+---------------------------------v---------------------------------+
|  Existing Tested Domain Services                                  |
|  - src/siem_ai/         (model.py, core.py, hunting.py, upload.py,|
|                          thresholds.py, explain.py, case_report.py|
|                          official_comparison.py, ui_components.py)|
|  - src/blue_team_ai/    (zeek.py, preview.py, trace_review.py,    |
|                          triage.py, research_triage.py,           |
|                          verified_report.py, new_log_workspace.py,|
|                          case_workspace.py, offline_pcap_verify.py|
|                          labeled_dataset.py)                      |
|  - src/red_team_ai/     (scenario_policy.py, planning_audit.py,   |
|                          synthetic_benchmark.py)                  |
|  - scripts/             (triage_zeek_new_log.py, evaluate_zeek_lab)|
+-------------------------------------------------------------------+
```

---

## 2. Thành phần Giữ nguyên vs Thay đổi

### Giữ nguyên hoàn toàn
- Toàn bộ thuật toán ML, tiền xử lý, kiểm tra nhãn, tính `flow_id`, `assess_signal`, kiểm thử ngưỡng (`src/siem_ai/*`).
- Toàn bộ đường ống phân tích Zeek ASCII, kiểm tra SHA-256 phân vùng `TRAIN/VALIDATION/TEST`, đối chiếu PCAP và read-only SQLite reader (`src/blue_team_ai/*`, `scripts/*`).
- Toàn bộ chính sách Red Team phi thực thi (`src/red_team_ai/*`, `EXECUTION OFF`).
- Schema SQLite trong `runtime/soc_cases.sqlite3` và `runtime/cyber_lab_cases.sqlite3`.
- Toàn bộ ứng dụng Streamlit (`app.py`, `pages/1_Cyber_Lab.py`, `pages/2_Red_Team_Lab.py`, `pages/3_New_Log_Review.py`) dùng làm rollback/fallback tại cổng `8501`.

### Bổ sung mới
- `src/api/`: Lớp adapter FastAPI có schema Pydantic rõ ràng, không tạo side-effect khi import module.
- `frontend/`: Ứng dụng Next.js (App Router + TypeScript strict + Tailwind CSS) với Dark SOC Design System thống nhất, bảng mật độ cao hỗ trợ lọc/sắp xếp/phân trang, ngăn kéo chi tiết `FlowInspectorDrawer`, biểu đồ ECharts/SVG tương tác, xử lý trạng thái lỗi/ngắt kết nối/thiếu model trung thực.
- `start_backend.ps1` và `start_frontend.ps1`: Script khởi chạy độc lập cục bộ trên Windows 11.

---

## 3. Chiến lược Cổng, Bảo mật & Dòng dữ liệu (Data Lineage)

1. **Local Ports:**
   - FastAPI Backend: `127.0.0.1:8000` (API base `/api/v1`, OpenAPI `/docs`).
   - Next.js Frontend: `127.0.0.1:3000` (biến môi trường `NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000/api/v1`).
   - Streamlit Rollback: `127.0.0.1:8501` (không chạy xung đột với `:3000` và `:8000`).
2. **Bảo mật & Chống rò rỉ:**
   - Không lưu khóa bí mật, model weights (`.joblib`), cơ sở dữ liệu `.sqlite3`, hoặc tệp log nhạy cảm trong `frontend/`.
   - Mọi truy cập hệ thống tệp cục bộ (`data/raw/unsw_nb15/`, `artifacts/`, `runtime/`, hoặc đường dẫn riêng tư trong `New Log Review`) đều thực thi hoàn toàn tại backend Python với đầy đủ kiểm tra symlink/traversal sẵn có.
   - Mọi phản hồi CSV export sử dụng `safe_csv_bytes` chống formula injection.
   - Mọi chế độ dữ liệu đều mang nhãn provenance rõ ràng (`HISTORICAL DATASET · UNSW-NB15`, `OFFLINE ZEEK · NOT LIVE`, `SIMULATION PLANNER · EXECUTION OFF`) để không gây hiểu lầm là SIEM thời gian thực.
