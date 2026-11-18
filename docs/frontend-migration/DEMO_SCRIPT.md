# Kịch bản Trình diễn Hội đồng (5–10 phút) — DA005 Sentinel Lab (Next.js + FastAPI)

> **Mục tiêu:** Chứng minh đầy đủ luồng nghiệp vụ từ nạp dữ liệu → phân tích đặc trưng → suy luận AI → điều tra cảnh báo → quản lý hồ sơ SOC (kèm Audit Trail), và phân tách rạch ròi giữa **Dataset Mode**, **Blue Team Offline Zeek**, và **Red Team Scenario Planner (`EXECUTION OFF`)**.

---

## 0. Chuẩn bị trước khi trình diễn

1. Mở Terminal 1 tại thư mục gốc repo, chạy:
   ```powershell
   .\start_backend.ps1
   ```
   Kiểm tra OpenAPI tại `http://127.0.0.1:8000/docs`.
2. Mở Terminal 2 tại thư mục gốc repo, chạy:
   ```powershell
   .\start_frontend.ps1
   ```
   Mở trình duyệt tại `http://127.0.0.1:3000`.
3. **Lưu ý về trạng thái Model AI & Zeek:**
   - **Nếu không có `artifacts/unsw_binary_rf.joblib`:** Giao diện vẫn chạy hoàn chỉnh ở **Chế độ khám phá** (tổng quan UNSW-NB15, Threat hunting theo proto/service/state, đọc báo cáo benchmark & comparison official từ `reports/`, Cyber Lab mẫu tổng hợp, và toàn bộ Red Team Lab).
   - **Để bật suy luận AI thực sự và lập hồ sơ từ cảnh báo AI:** Chạy trước `python scripts/train_siem.py` để tạo `artifacts/unsw_binary_rf.joblib` và `artifacts/metrics.json`.
   - **Phần New Log Review xác minh thật:** Yêu cầu có cặp tệp riêng tư ngoài Git (`zeek-research-model.json`, `manifest.json`, `conn.log` mới và giá trị SHA-256 ghi độc lập).

---

## 1. Kịch bản Demo 7 phút

| Thời lượng | Phân hệ / Màn hình | Thao tác trực tiếp trên UI | Điểm cần nhấn mạnh với Hội đồng |
| :---: | --- | --- | --- |
| **0:00 – 1:00** | **App Shell & Dataset SOC — Tổng quan** (`/`) | Chỉ trạng thái Sidebar (`API CONNECTED`, `AI Model: READY`, `Live Capture: OFF`, `Red Execution: OFF`). Xem 4 KPI, thanh phân bố ưu tiên AI (`[CRIT]`, `[HIGH]`, `[MED]`, `[LOW]`) và 2 biểu đồ giao thức / ground truth. | Ranh giới trung thực: UNSW-NB15 là dữ liệu lịch sử không có IP/Timestamp gốc; `Attack trong nhãn gốc` và `AI dự đoán Attack` là hai đại lượng độc lập. |
| **1:00 – 2:30** | **Dataset SOC — Threat hunting** | Lọc `proto = tcp`, bật `Chỉ các flow AI dự đoán Attack`, sắp xếp theo `P(Attack)`, nhấp vào một dòng để mở ngăn kéo `FlowInspectorDrawer` và xem JSON raw + tín hiệu heuristic (`assess_signal`), sau đó nhấn `Xuất CSV an toàn`. | Hỗ trợ điều tra nhanh, giữ JSON raw gọn trong side drawer, xuất CSV đã khử formula injection (`safe_csv_bytes`). |
| **2:30 – 3:45** | **Dataset SOC — AI & đánh giá** | Mở Tab `AI & đánh giá`. Chỉ Ma trận nhầm lẫn 2x2 (`TN/FP/FN/TP`), bảng so sánh ngưỡng đã khóa `0,50` vs `0,55` (giảm 1.265 FP, tăng 342 FN), biểu đồ Global Feature Importance (MDI) và đường cong chẩn đoán ngưỡng. | Giải thích vì sao không tối ưu ngưỡng trên tập test, vì sao giảm FP đi kèm đánh đổi tăng FN, và giới hạn của MDI. |
| **3:45 – 5:15** | **Trung tâm cảnh báo → SOC Case Management** | Kéo thanh trượt ngưỡng ở `Trung tâm cảnh báo`, chọn flow điểm cao nhất → bấm `Tạo SOC case từ flow đã chọn`. Tự động chuyển sang `SOC case management`: xem snapshot bất biến, chuyển trạng thái `New → Investigating`, nhập ghi chú và nhấn `Lưu diễn biến điều tra`, sau đó nhấn `Xuất JSON hồ sơ`. | Toàn bộ ghi nhận lưu trong SQLite (`runtime/soc_cases.sqlite3`) có Audit Trail theo thời gian UTC không thể xóa lịch sử cũ. |
| **5:15 – 6:15** | **Cyber Lab · Zeek** (`/cyber-lab`) | Chuyển sang `/cyber-lab`. Nhấn `Nạp mẫu tổng hợp để kiểm thử UI` (hoặc tải tệp `conn.log` thật). Xem `SHA-256`, lọc UID/IP, nhấp dòng xem chi tiết, tích xác nhận và bấm `Tạo hồ sơ Unclassified` + `Tải JSON đối chiếu log gốc`. | Phân tách hoàn toàn mô hình UNSW-NB15 với schema Zeek; trạng thái VMware hiển thị trung thực là ngoại tuyến (`Chưa kiểm tra kết nối trực tiếp`). |
| **6:15 – 7:00** | **Red Team Lab & New Log Review** (`/red-team-lab`, `/new-log-review`) | Vào `/red-team-lab`: chỉ banner đỏ `EXECUTION OFF`, bấm `Đề xuất kịch bản`, nhập 1 phản hồi thủ công để xem Timeline cập nhật, chạy nhanh `So sánh mô phỏng` (`UCB1` vs `Random`). Chuyển qua `/new-log-review` giới thiệu quy trình 4 bước xác minh SHA-256 (`1A → 1D`) và trình đọc SQLite chỉ đọc. | Red Team chỉ lập kế hoạch trên danh mục an toàn, không phát lưu lượng hay khai thác thật; mọi chỉ số mô phỏng được gắn nhãn `SYNTHETIC`. |
