# DA005 – Hướng dẫn sử dụng Sentinel Lab

> Mini-SIEM học thuật, phân tích dữ liệu **lịch sử** UNSW-NB15. Đây không phải hệ thống giám sát mạng thời gian thực.

## 1. Đọc giao diện trong 30 giây

**Thanh bên trái** quyết định nguồn dữ liệu:

- **UNSW-NB15 test:** xem các flow từ tập test gốc. Mặc định chỉ đọc 2.500 dòng đầu. Tăng thanh trượt đến 10.000 để xem thêm; đây không phải toàn bộ 82.332 dòng test.
- **Tải lên CSV:** thử dữ liệu tương thích UNSW-NB15 của riêng nhóm, tối đa 15 MB. Tệp không có nhãn vẫn được xử lý nếu đặc trưng đúng.
- **Trạng thái phân tích:** “AI sẵn sàng” nghĩa là tồn tại mô hình đã huấn luyện cục bộ. Nếu không, có thể khám phá nhãn gốc nhưng không được nói AI đã dự đoán.

Phía trên màn hình có nhắc **chế độ mô phỏng**, không có IP và timestamp gốc trong tập train/test.

## 2. Năm tab theo thứ tự làm việc

| Tab | Dùng để làm gì? | Cần chú ý |
| --- | --- | --- |
| **Tổng quan an ninh** | Xem số flow, số nhãn Attack, số AI dự đoán Attack, số hồ sơ; xem phân bố giao thức/loại tấn công. | “Attack trong nhãn gốc” là đáp án bộ dữ liệu, **khác** dự đoán của AI. |
| **Threat hunting** | Lọc lưu lượng theo giao thức (TCP/UDP...), dịch vụ, trạng thái và xác suất AI. | Chỉ lọc trong mẫu đang tải. Xuất CSV không thực thi công thức bảng tính. |
| **AI & đánh giá** | Hiểu Precision, Recall, F1, confusion matrix; so sánh 0,50 và 0,55; xem MDI importance. | Chỉ số benchmark là của **tập test chính thức**, không phải của vài dòng đang xem. |
| **Trung tâm cảnh báo** | Chọn các flow mô hình đánh giá có khả năng Attack và lập hồ sơ điều tra. | Ngưỡng cao có thể giảm cảnh báo nhầm **nhưng** bỏ sót thêm tấn công. |
| **SOC case management** | Xem bằng chứng và audit trail, cập nhật trạng thái/ghi chú, xuất JSON hồ sơ. | Không thể đồng nhất dữ liệu lịch sử thành một sự cố đang xảy ra ngoài đời. |

## 3. Bốn khái niệm dùng để vấn đáp

- **Network flow:** bản ghi tóm tắt một phiên/luồng giao tiếp mạng; không phải packet capture nguyên gốc.
- **Ground truth:** nhãn Attack/Normal có sẵn trong dataset, chỉ dùng đánh giá, không được đưa làm đặc trưng khi AI dự đoán.
- **Alert / cảnh báo:** một flow có xác suất Attack vượt ngưỡng trên dashboard; cảnh báo có thể là false positive.
- **SOC case / hồ sơ điều tra:** một đối tượng quản lý do người phân tích tạo từ alert, chứa bản chụp đặc trưng và lịch sử cập nhật, lưu trong SQLite.

## 4. Kịch bản demo 5 phút

1. Trong CMD tại `E:\DA_CNTT`, chạy `.venv\Scripts\python.exe -m streamlit run app.py`; mở `http://localhost:8501`.
2. Nhìn sidebar: nguồn UNSW-NB15 test và trạng thái AI. Nếu chưa có mô hình, chạy `.venv\Scripts\python.exe scripts/train_siem.py` ở terminal khác rồi khởi động lại dashboard.
3. Xem 4 chỉ số ở **Tổng quan**. Giải thích vì sao “AI dự đoán Attack” và nhãn gốc có thể khác nhau.
4. Mở **Threat hunting**, chọn giao thức và quan sát bảng thay đổi. 
5. Mở **Trung tâm cảnh báo**, chọn một flow có xác suất cao, nhấn **Tạo SOC case từ flow đã chọn**.
6. Mở **SOC case management**, tải JSON hồ sơ; đổi trạng thái **New → Investigating**, nhập ghi chú rồi nhấn **Lưu diễn biến điều tra**. Tải lại JSON để kiểm tra audit trail.

**Bằng chứng nên lưu:** ảnh màn hình thật ở cả 5 tab, dòng `LOCAL VERIFICATION PASSED`, tệp `artifacts/local_verification.json` lưu **cục bộ**, bản JSON hồ sơ điều tra. Không giả lập chứng cứ local từ GitHub CI.

## 5. Nguyên tắc giao diện

Thiết kế mới áp dụng hướng dẫn [UI UX Pro Max](https://github.com/tbao4151/ui-ux-skill): ưu tiên tương phản chữ, phân cấp rõ, điều khiển truy cập được bằng bàn phím, dữ liệu và trạng thái có nhãn, màu sắc nhất quán và bố cục phân tích gọn. Chủ đạo: nền sáng, thẻ trắng, sidebar xanh navy, xanh dương cho thao tác, xanh ngọc cho dữ liệu thứ hai. Tránh “neon cybersecurity” vì dễ giảm khả năng đọc liên tục.

Giao diện không thay đổi thuật toán AI, ngưỡng 0,8 mặc định của Alert Queue, định dạng dữ liệu, schema SQLite hoặc API tạo/xuất case.
