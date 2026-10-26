# DA005 — Tài liệu chuẩn bị bảo vệ hội đồng

Tài liệu giải thích sản phẩm, không phải minh chứng mô hình đã đạt chỉ số nào đó.

## Trình tự demo dự kiến

1. Giới thiệu DA005, Network Flow Logs và lựa chọn dataset UNSW-NB15.
2. Chứng minh train/test chính thức, checksum và phân bố Normal/Attack.
3. Trình bày pipeline AI không đưa `id`, `label`, `attack_cat` vào đầu vào.
4. Mở dashboard: tổng quan dữ liệu, threat hunting, chỉ số mô hình **chỉ sau khi huấn luyện**.
5. Mở alert queue từ xác suất AI, tạo case SOC, cập nhật trạng thái và ghi chú.
6. Nêu giới hạn: offline prototype, không có IP/timestamp trong bộ train/test, chưa phải SIEM/SOC production.

## Vấn đáp trọng điểm

**SIEM vs SOC?** SIEM là hệ thống thu thập/phân tích/cảnh báo sự kiện; SOC là bộ phận và quy trình giám sát, phân tích và ứng phó. Hệ thống nhóm mô phỏng một phần chức năng hai bên.

**Sao không chỉ dùng Accuracy?** Dữ liệu có thể mất cân bằng; luôn xem Attack Precision, Recall, F1, macro-F1 và confusion matrix. Đánh giá trên tập test giữ nguyên.

**Model có học thuộc nhãn không?** `label` và `attack_cat` bị loại trước khi huấn luyện; bước tiền xử lý chỉ fit trên train.

**Có giám sát thời gian thực?** Chưa. Dữ liệu UNSW-NB15 train/test thiếu timestamp/IP gốc; công cụ hiện đọc CSV lịch sử.

**Có thể giải thích quyết định AI?** Random Forest tổng hợp các cây quyết định; các rule bổ trợ không được gọi là AI. Cần bổ sung explainability và kiểm tra false positive/false negative.

**Dữ liệu nguồn có đáng tin không?** Nguồn học thuật UNSW; bản sao tải được kiểm tra checksum SHA-256 đã ghi trong metadata. Giới hạn tính tổng quát hóa sang mạng thực.

## Minh chứng bắt buộc trước nộp cuối kỳ

- Version/commit demo, CI thành công.
- Training reproducible; metrics thật, confusion matrix.
- Script/model có thể chạy bằng một bộ lệnh rõ ràng.
- Kiểm thử tạo và cập nhật case.
- Sơ đồ kiến trúc, giới hạn nghiên cứu, phân công và báo cáo thảo luận với GVHD.

Không được tuyên bố đã hoàn thành các mục trong danh sách này nếu chưa có bằng chứng.
