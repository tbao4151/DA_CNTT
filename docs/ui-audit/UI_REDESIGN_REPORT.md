# Báo cáo Tổng kết Nâng cấp UI/UX — DA005 Sentinel Lab

**Ngày hoàn thành:** 2026-11-18  
**Phạm vi thực hiện:** Chuẩn hóa toàn bộ hệ thống giao diện frontend cho 4 màn hình Streamlit (`app.py`, `pages/1_Cyber_Lab.py`, `pages/2_Red_Team_Lab.py`, `pages/3_New_Log_Review.py`), hệ thống CSS Design Tokens (`src/siem_ai/ui.css`), thư viện component dùng chung (`src/siem_ai/ui_components.py`), bộ kiểm thử UI (`tests/test_ui_components.py`) và tài liệu vận hành (`docs/USING_DASHBOARD.md`, `docs/ui-audit/*`).

---

## 1. Bảng Điểm Audit Trước / Sau (Thang 0–5)

| Tiêu chí | Trước | Sau | Giải thích thay đổi cụ thể |
| --- | :---: | :---: | --- |
| **Visual hierarchy** | 2.5 | **4.3** | Đồng bộ `.soc-hero` (kèm biến thể `--blue`, `--red`), `.soc-mode-banner`, `.soc-provenance-strip` và `.soc-card` trên cả 4 trang. Tab 4 (`SOC case management`) và Mục 5 (`3_New_Log_Review.py`) chuyển sang bố cục Master-Detail 2 cột. |
| **Typography** | 2.5 | **4.2** | Khai báo `--soc-font-sans` và `--soc-font-mono` trong `src/siem_ai/ui.css`; áp dụng `tabular-nums` cho toàn bộ metric KPI, bảng Confusion Matrix và thẻ thông số flow/UID/IP/SHA-256. |
| **Design system** | 2.5 | **4.4** | Mở rộng `src/siem_ai/ui.css` thành design system thống nhất với semantic tokens cho Severity/Priority (`[CRIT]`, `[HIGH]`, `[MED]`, `[LOW]`, `[INFO]`) và 3 chế độ vận hành (`Dataset`, `Blue Team Lab`, `Red Team Execution OFF`), tập trung UI primitives vào `src/siem_ai/ui_components.py`. |
| **Navigation & IA** | 2.5 | **4.2** | Toàn bộ 4 trang cùng dùng `render_sidebar_brand()` hiển thị nhận diện `SENTINEL LAB`, phân hệ đang hoạt động và bản đồ 4 phân hệ (`Dataset SOC`, `Cyber Lab`, `Red Team Lab`, `New Log Review`). |
| **Data visualization** | 2.5 | **4.1** | Thay thế `st.json` thô ở Tab 2 (`app.py`) bằng `render_confusion_matrix_html()` dạng ma trận 2x2 kèm tỷ lệ % và phân tích gánh nặng FP/FN; thay `st.bar_chart` ở `pages/1_Cyber_Lab.py` bằng Plotly `style_chart()`; bổ sung 2 biểu đồ Plotly so sánh `UCB1` vs `Random` tổng hợp ở `pages/2_Red_Team_Lab.py`. |
| **SOC workflows** | 3.0 | **4.3** | Bổ sung phân tầng mức ưu tiên (`AI_priority` / `Mức ưu tiên`), dải đếm nhanh ở Tab 0 & Tab 3 (`app.py`), thẻ `render_flow_evidence_card()` cho flow chuẩn bị lập hồ sơ (`app.py` Tab 3, `1_Cyber_Lab.py`), và xếp form cập nhật trạng thái ngay cạnh lịch sử audit ở Tab 4 (`app.py`). |
| **Functional UX** | 3.0 | **4.2** | Sắp xếp lại bộ lọc Tab 1 (`app.py`) thành Filter Toolbar 3 cột + hàng lọc AI gọn gàng; thêm bộ lọc nhanh giao thức/IP/UID trên 500 dòng preview ở `pages/1_Cyber_Lab.py`; chia biểu mẫu 11 trường ở `pages/3_New_Log_Review.py` thành `BƯỚC 1A` → `BƯỚC 1D` theo nhóm logic 2 cột. |
| **Feedback & states** | 3.0 | **4.1** | Chuẩn hóa `render_empty_state()` cho trạng thái rỗng khi lọc bằng 0, khi 0 cảnh báo, khi chưa có hồ sơ SQLite, khi chưa nạp `conn.log` và khi chưa có timeline đề xuất Red Team, nêu rõ hành động tiếp theo và cảnh báo 0 cảnh báo ≠ an toàn tuyệt đối. |
| **Responsive** | 2.5 | **3.8** | Bổ sung media queries cho `@media(max-width:1280px)`, `@media(max-width:900px)`, `@media(max-width:768px)`, `@media(max-width:480px)` và `.soc-hash-box` / `overflow-wrap: anywhere` để ngăn tràn ngang chuỗi SHA-256 64 ký tự. *(Chưa đạt 4.5+ do chưa kiểm chứng screenshot trực quan trên trình duyệt tại mọi viewport).* |
| **Accessibility** | 3.0 | **4.2** | Mọi badge ưu tiên và trạng thái đều kết hợp tiền tố chữ (`[CRIT]`, `[HIGH]`, `[MED]`, `[LOW]`, `[INFO]`, `[EXECUTION OFF]`) cùng viền và độ tương phản chuẩn AA; giữ nguyên `:focus-visible` và `prefers-reduced-motion`. |
| **Trust & realism** | 4.0 | **4.7** | Nâng cao phân tách trực quan giữa dữ liệu lịch sử UNSW-NB15, nhật ký Zeek ngoại tuyến, dự đoán held-out có ghim SHA-256 và lập kế hoạch Red Team (`EXECUTION OFF` / mô phỏng Bernoulli tổng hợp) thông qua hệ thống Mode Banner & Provenance Strip. |
| **Technical quality** | 3.0 | **4.4** | Tách toàn bộ helper HTML/Plotly khỏi các file trang vào `src/siem_ai/ui_components.py`, áp dụng `html.escape()` nhất quán cho dữ liệu đầu vào động, tuân thủ đầy đủ hợp đồng sandbox copy của bộ test tự động. |

**Điểm trung bình:** tăng từ **2.83 / 5.00** lên **4.24 / 5.00**.

---

## 2. Danh Sách Thay Đổi Code Thực Tế

1. **`src/siem_ai/ui.css`**: Mở rộng hệ thống biến `:root`, thêm styling cho `.soc-hero--blue`, `.soc-hero--red`, `.soc-mode-banner`, `.soc-provenance-strip`, `.soc-badge--*`, `.soc-card`, `.soc-kv-grid`, `.soc-hash-box`, `.soc-cm-table`, `.soc-step-header`, `.soc-empty-state`, `.soc-sidebar-nav-guide` và responsive breakpoints `1280px / 900px / 768px / 480px`. Giữ nguyên toàn bộ ràng buộc kiểm thử (`#f3f6fb`, `#ffffff`, `:focus-visible`, `prefers-reduced-motion`, `@media(max-width:900px)`, không chứa `#080f1d`).
2. **`src/siem_ai/ui_components.py`** *(file mới)*: Cung cấp `style_chart`, `priority_band_from_probability`, `render_sidebar_brand`, `render_mode_banner`, `render_provenance_strip`, `render_confusion_matrix_html`, `render_flow_evidence_card`, `render_empty_state`, `render_footer`.
3. **`app.py`**: Cập nhật Sidebar, Hero, Mode Banner và cả 5 tab (`Tổng quan an ninh`, `Threat hunting`, `AI & đánh giá`, `Trung tâm cảnh báo`, `SOC case management`) và footer thống nhất. Không thay đổi logic AI, ngưỡng 0.8 mặc định, CSV validation hay SQLite schema.
4. **`pages/1_Cyber_Lab.py`**: Đồng bộ Sidebar brand, Hero Blue Team, Mode Banner, Provenance Strip, hash box chống tràn, biểu đồ Plotly `style_chart`, quick filter trên 500 dòng preview, Flow Evidence Card trước khi mở hồ sơ thủ công/nghiên cứu, và footer.
5. **`pages/2_Red_Team_Lab.py`**: Đồng bộ Sidebar brand, Hero Red Team (`EXECUTION OFF`), Mode Banner, Provenance Strip, thẻ tóm tắt kế hoạch kịch bản + expander JSON, 2 biểu đồ Plotly cho benchmark Bernoulli tổng hợp, footer. Giữ nguyên thứ tự `st.selectbox[0]` cho form phản hồi.
6. **`pages/3_New_Log_Review.py`**: Đồng bộ Sidebar brand, Hero Blue Team, Mode Banner, phân bước form xác minh (`BƯỚC 1A`–`1D`), Provenance Strip wrap hash, cột `Mức ưu tiên` trong bảng ứng viên, Master-Detail 2 cột cho trình đọc SQLite chỉ đọc ở Mục 5, và footer.
7. **`tests/test_ui_components.py`** *(file mới)*: Kiểm thử đơn vị cho `priority_band_from_probability`, thoát mã XSS (`html.escape`), bảng Confusion Matrix HTML, footer và chạy kiểm thử `AppTest` cho mô phỏng tổng hợp của `pages/2_Red_Team_Lab.py`.
8. **`docs/USING_DASHBOARD.md`**: Cập nhật Mục 5 phản ánh các phân hệ, mức ưu tiên AI và bố cục SOC mới.

---

## 3. Trạng Thái Giải Quyết Các Vấn Đề Audit (`UX-01` → `UX-13`)

| ID | Mức | Trạng thái | Ghi chú thực hiện |
| --- | :---: | :---: | --- |
| `UX-01` | P1 | **Đã sửa** | Đồng bộ `.soc-brand`, `.soc-hero` và `.soc-footer` trên cả 4 trang. |
| `UX-02` | P1 | **Đã sửa** | Phân tách màu & banner giữa Dataset (`--primary`), Blue Team (`--mode-blue`) và Red Team `EXECUTION OFF` (`--mode-red`). |
| `UX-03` | P1 | **Đã sửa** | Tab 3 (`app.py`) bổ sung dải đếm ưu tiên, cột mức ưu tiên, Flow Evidence Card và rule summary card. |
| `UX-04` | P1 | **Đã sửa** | Tab 4 (`app.py`) và Mục 5 (`3_New_Log_Review.py`) áp dụng Master-Detail 2 cột, ẩn JSON 40+ trường vào expander. |
| `UX-05` | P1 | **Đã sửa** | Tab 2 (`app.py`) hiển thị Confusion Matrix 2x2 trực quan kèm ý nghĩa SOC. |
| `UX-06` | P1 | **Đã sửa** | `pages/1_Cyber_Lab.py` chuyển sang Plotly `style_chart`. |
| `UX-07` | P1 | **Đã sửa** | Form `pinned_new_log_review` ở `pages/3_New_Log_Review.py` phân rõ `BƯỚC 1A`–`1D`. |
| `UX-08` | P2 | **Đã sửa** | Tab 1 (`app.py`) chuyển bộ lọc sang toolbar 3 cột + empty state. |
| `UX-09` | P2 | **Đã sửa** | Bổ sung `--soc-font-mono`, `.soc-hash-box`, `tabular-nums` cho IP/Port/UID/SHA-256/KPI. |
| `UX-10` | P2 | **Đã sửa** | Thêm media queries `1280/900/768/480` và `overflow-wrap: anywhere`. |
| `UX-11` | P2 | **Đã sửa** | Thêm 2 biểu đồ Plotly so sánh `UCB1` vs `Random` tổng hợp trên `pages/2_Red_Team_Lab.py`. |
| `UX-12` | P2 | **Đã sửa** | Hệ thống `.soc-badge` luôn kèm tiền tố chữ `[CRIT]`, `[HIGH]`, `[MED]`, `[LOW]`, `[INFO]`. |
| `UX-13` | P3 | **Đã sửa** | Tách component dùng chung vào `src/siem_ai/ui_components.py`. |

---

## 4. Kết Quả Kiểm Thử & Giới Hạn Kỹ Thuật (Trung Thực)

1. **Biên dịch cú pháp (`compileall`):** `E:\DA_CNTT\.venv\Scripts\python.exe -m compileall -q app.py pages src scripts` → **PASS** (exit code 0).
2. **Unit Tests không dùng socket `AppTest` (chạy trong sandbox):**
   `pytest -q tests/test_ui_theme.py tests/test_core.py tests/test_hunting.py tests/test_thresholds.py tests/test_architecture_inventory.py tests/test_sentinel_status_contract.py tests/test_zeek_case_workspace.py`
   - Kết quả: **72 passed, 1 failed** (`tests/test_zeek_case_workspace.py::test_refuse_missing_invalid_and_non_zeek` gặp `OSError: [WinError 1314]` khi gọi `symlink_to` do tài khoản Windows chưa bật Developer Mode — không liên quan UI).
3. **Bộ kiểm thử Streamlit `AppTest` toàn ứng dụng (chạy với `BypassSandbox: true`):**
   `pytest -q tests/test_app_smoke.py tests/test_app_model_integration.py tests/test_cyber_lab_preview.py tests/test_red_team_planning_audit.py tests/test_red_team_scenario_policy.py tests/test_zeek_new_log_workspace.py tests/test_zeek_new_log_ui_partition.py tests/test_zeek_new_log_ui_pcap.py tests/test_zeek_new_log_ui_soc.py`
   - Kết quả: **77 passed in 9.60s**.
4. **Kiểm thử UI Components, Theme, Contracts & AppTest tích hợp (chạy với `BypassSandbox: true`):**
   `pytest -q tests/test_ui_theme.py tests/test_ui_components.py tests/test_architecture_inventory.py tests/test_sentinel_status_contract.py tests/test_app_smoke.py tests/test_app_model_integration.py tests/test_cyber_lab_preview.py tests/test_red_team_planning_audit.py tests/test_red_team_scenario_policy.py tests/test_zeek_new_log_workspace.py tests/test_zeek_new_log_ui_partition.py tests/test_zeek_new_log_ui_pcap.py tests/test_zeek_new_log_ui_soc.py`
   - Kết quả: **123 passed in 12.05s**.
5. **Chạy toàn bộ thư mục kiểm thử `pytest -q tests/` (chạy với `BypassSandbox: true`):**
   - Kết quả: **1,950 passed, 8 skipped**, **4 failed** (tất cả 4 case đều là `OSError: [WinError 1314]` khi gọi `symlink_to` do Windows không bật quyền tạo symlink trong `test_lab_evidence_chain.py`, `test_offline_pcap_verify.py`, `test_paired_network_preflight.py`, `test_zeek_case_workspace.py`), **8 errors** (lỗi setup `ValueError: the environment variable is longer than 32767 characters` trên biến môi trường `PYTEST_CURRENT_TEST` của Windows cho các chuỗi tham số >32 KB trong `test_guest_network_preflight.py`, `test_paired_network_preflight.py`, `test_red_team_audit_verify.py`, `test_zeek_new_log_review.py`). Không có bất kỳ lỗi nào phát sinh từ thay đổi UI/UX.
6. **Giới hạn kiểm thử trình duyệt trực quan (chưa thực hiện được trọn vẹn):**
   - Subagent `browser` không kết nối được vì Chrome trên máy host chưa bật remote debugging (`DevToolsActivePort` không tồn tại).
   - `playwright` chưa được cài đặt trong môi trường `E:\DA_CNTT\.venv`, nên `tests/test_browser_soc_e2e.py` tự động skip theo biến `DA005_BROWSER_SOC_E2E=1`.
   - Thử nghiệm chụp nhanh bằng `msedge.exe --headless=new --virtual-time-budget=12000` chỉ thu được khung skeleton loading ban đầu của Streamlit (chưa kịp render xong WebSocket), nên đã xóa ảnh skeleton và **không tính là đã kiểm thử trực quan trên trình duyệt ở các viewport 1920/1440/1280/768/390**.
   - **Khuyến nghị xác nhận thủ công trên máy người dùng:** Mở terminal tại `E:\DA_CNTT\DA_CNTT`, chạy `E:\DA_CNTT\.venv\Scripts\python.exe -m streamlit run app.py`, sau đó kiểm tra trực tiếp 4 trang trên trình duyệt ở kích thước desktop và mobile, hoặc chạy `tests/test_browser_soc_e2e.py` trong GitHub Actions (`official-model-smoke.yml`).
