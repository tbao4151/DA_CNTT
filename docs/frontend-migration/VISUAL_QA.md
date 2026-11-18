# DA005 Sentinel Lab — Visual QA & Browser Verification Report

Tài liệu này ghi nhận kết quả kiểm thử trình duyệt thật (headless Google Chrome qua `playwright-core`) trên bản production build của Next.js (`127.0.0.1:3000`) kết nối trực tiếp tới FastAPI backend (`127.0.0.1:8000`).

---

## 1. Môi trường kiểm thử

- **Trình duyệt:** Google Chrome (`C:\Program Files\Google\Chrome\Application\chrome.exe`) điều khiển bằng `playwright-core@1.50.1`.
- **Frontend:** Next.js `14.2.28` (`npm.cmd run build` + `npm.cmd run start` tại `http://127.0.0.1:3000`).
- **Backend:** FastAPI (`uvicorn api.main:app --host 127.0.0.1 --port 8000`) chạy trên `E:\DA_CNTT\.venv`, với local UNSW-NB15 model trong `artifacts/` (gitignored) để kiểm chứng chế độ full model và đầy đủ các luồng API.
- **Kích thước màn hình kiểm tra:** `1920x1080`, `1440x900`, `1280x800`, `768x1024`, `390x844`.

---

## 2. Lỗi phát hiện & khắc phục sau Visual QA Pass 1

1. **`AlertsAndCasesTabs.tsx` — Mất thông báo phản hồi sau khi cập nhật SOC Case:**
   - *Nguyên nhân:* `useEffect` reset state `msg` chạy theo dependency của `caseDetail` mỗi lần dữ liệu case tải lại sau khi lưu diễn biến.
   - *Khắc phục:* Tách riêng `useEffect` reset thông báo theo `detailCaseId`, giữ nguyên thông báo `"Đã lưu diễn biến điều tra."` sau khi cập nhật trạng thái thành công.
2. **`OverviewTab.tsx` — Nhãn trục X của cột thứ 4 (`Reconnaissance`) bị Recharts tự ẩn ở độ rộng vừa:**
   - *Nguyên nhân:* Cấu hình mặc định của `XAxis` bỏ qua tick khi khoảng cách hẹp.
   - *Khắc phục:* Thiết lập `interval={0}`, `angle={-18}`, `textAnchor="end"`, `height={44}` để mọi nhãn phân bố attack category hiển thị đầy đủ, không cắt chữ.
3. **`OverviewTab.tsx`, `EvaluationTab.tsx`, `AlertsAndCasesTabs.tsx`, `cyber-lab/page.tsx` — Ký tự backtick markdown thô trong JSX:**
   - *Nguyên nhân:* Một số nhãn/gợi ý dùng dấu backtick `` `...` `` trong chuỗi JSX thay vì thẻ `<code>`.
   - *Khắc phục:* Chuyển toàn bộ về thẻ `<code>` theo thiết kế monospace của giao diện.
4. **`new-log-review/page.tsx` — Nút chọn tệp `<input type="file">` hiển thị màu mặc định của trình duyệt:**
   - *Khắc phục:* Style lại bằng Tailwind `file:` utility classes để đồng bộ nền tối và đường viền slate.
5. **`icon.svg` — Lỗi console 404 thiếu favicon (`/favicon.ico`):**
   - *Khắc phục:* Bổ sung `frontend/src/app/icon.svg` cho Next.js App Router.

---

## 3. Kết quả Visual QA Pass 2 (Sau khi sửa lỗi & rebuild)

Tổng cộng **16/16 kịch bản kiểm tra** đều đạt:
- `consoleErrors`: `[]` (0 lỗi console)
- `pageErrors`: `[]` (0 uncaught page error)
- `failedApi`: `[]` (0 request `/api/v1/*` thất bại)
- `overflowPx`: `0` trên toàn bộ 16 khung hình (`scrollWidth === viewportWidth`)

| # | Route / Kịch bản | Viewport | Trạng thái | Overflow (px) | Ảnh chụp minh chứng |
|---:|---|---|---|---:|---|
| 1 | `/` — Dataset SOC Overview | `1920x1080` | PASS (DOM telemetry) | `0` (`scrollWidth=1920`) | [dataset_overview_1920x1080.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/dataset_overview_1920x1080.png) |
| 2 | `/` — Dataset SOC Overview | `1440x900` | PASS (visually inspected) | `0` (`scrollWidth=1440`) | [dataset_overview_1440x900.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/dataset_overview_1440x900.png) |
| 3 | `/` — Dataset SOC Overview | `1280x800` | PASS (visually inspected) | `0` (`scrollWidth=1280`) | [dataset_overview_1280x800.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/dataset_overview_1280x800.png) |
| 4 | `/` — Dataset SOC Overview | `768x1024` | PASS (visually inspected) | `0` (`scrollWidth=768`) | [dataset_overview_768x1024.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/dataset_overview_768x1024.png) |
| 5 | `/` — Dataset SOC Overview (Mobile drawer nav) | `390x844` | PASS (visually inspected) | `0` (`scrollWidth=390`) | [dataset_overview_390x844.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/dataset_overview_390x844.png) |
| 6 | `/` — Threat Hunting + mở `FlowInspectorDrawer` | `1440x900` | PASS (visually inspected) | `0` (`scrollWidth=1440`) | [dataset_hunting_drawer_1440x900.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/dataset_hunting_drawer_1440x900.png) |
| 7 | `/` — AI & Evaluation (PR-AUC / ROC / F1 / Thresholds) | `1440x900` | PASS (visually inspected) | `0` (`scrollWidth=1440`) | [dataset_evaluation_1440x900.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/dataset_evaluation_1440x900.png) |
| 8 | `/` — Alerts Queue | `1440x900` | PASS (visually inspected) | `0` (`scrollWidth=1440`) | [dataset_alerts_1440x900.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/dataset_alerts_1440x900.png) |
| 9 | `/` — SOC Case Management (tạo case & đổi `New -> Investigating`) | `1440x900` | PASS (visually inspected) | `0` (`scrollWidth=1440`) | [dataset_cases_1440x900.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/dataset_cases_1440x900.png) |
| 10 | `/cyber-lab` — Tải Zeek synthetic sample & biểu đồ giao thức | `1440x900` | PASS (visually inspected) | `0` (`scrollWidth=1440`) | [cyber_lab_loaded_1440x900.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/cyber_lab_loaded_1440x900.png) |
| 11 | `/cyber-lab` — Responsive Mobile | `390x844` | PASS (visually inspected) | `0` (`scrollWidth=390`) | [cyber_lab_loaded_390x844.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/cyber_lab_loaded_390x844.png) |
| 12 | `/red-team-lab` — Proposal + Synthetic Bernoulli benchmark | `1440x900` | PASS (visually inspected) | `0` (`scrollWidth=1440`) | [red_team_lab_1440x900.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/red_team_lab_1440x900.png) |
| 13 | `/red-team-lab` — Responsive Mobile | `390x844` | PASS (visually inspected) | `0` (`scrollWidth=390`) | [red_team_lab_390x844.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/red_team_lab_390x844.png) |
| 14 | `/new-log-review` — 4-Step Verification Gate & Triage | `1440x900` | PASS (visually inspected) | `0` (`scrollWidth=1440`) | [new_log_review_1440x900.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/new_log_review_1440x900.png) |
| 15 | `/new-log-review` — Responsive Mobile | `390x844` | PASS (visually inspected) | `0` (`scrollWidth=390`) | [new_log_review_390x844.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/new_log_review_390x844.png) |
| 16 | `/new-log-review` — Private Case Viewer (SQLite `mode=ro`) | `1440x900` | PASS (visually inspected) | `0` (`scrollWidth=1440`) | [new_log_readonly_1440x900.png](file:///e:/DA_CNTT/DA_CNTT/docs/frontend-migration/screenshots/new_log_readonly_1440x900.png) |

---

## 4. Ghi chú phạm vi kiểm chứng

- Chế độ offline không có model trên `/` và kịch bản nộp form với file private thật trên `/new-log-review` được kiểm chứng qua `tests/test_api_v1.py` (`httpx` / `TestClient` mock & temp workspace), chưa chụp riêng trên trình duyệt ngoài môi trường có artifact/sandboxed test.
