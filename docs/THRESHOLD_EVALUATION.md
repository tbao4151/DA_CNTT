# DA005 — Phân tích ngưỡng cảnh báo (diagnostic)

Baseline Random Forest hiện sử dụng 0.5 làm ngưỡng phân loại; theo
`reports/official_baseline_metrics.json`, 8.400 mẫu Normal bị báo nhầm trên
37.000 Normal của tập kiểm thử chính thức (FPR 22,70%).

Sau khi tự tạo mô hình tin cậy trên máy (`python scripts/train_siem.py`), chạy:

```powershell
python scripts/analyze_thresholds.py
```

Lệnh đọc toàn bộ *test* UNSW-NB15, in bảng theo các ngưỡng 0.5, 0.6, 0.7,
0.8, 0.9 và lưu `artifacts/threshold_diagnostics.csv`. Các cột gồm TP/FP/TN/FN,
Precision, Recall, F1, False Positive Rate, tổng cảnh báo. Đây là công cụ phân
tích nhạy cảm theo ngưỡng, **không tự động tìm ngưỡng tối ưu và không cải tiến
mô hình chỉ nhờ đổi ngưỡng**.

**Nguyên tắc phương pháp luận:** Không chọn ngưỡng tối ưu dựa trên test chính
thức vì gây thiên lệch. Để quyết định ngưỡng triển khai, tách một tập validation
từ training, chọn ngưỡng trên validation, sau đó đánh giá *một lần* trên test
chính thức. Có thể dùng bộ test để giải thích baseline và quan sát tradeoff,
nhưng không báo cáo ngưỡng được lựa chọn trên test là kết quả không thiên lệch.

Bảng phân tích dựa trên dự đoán xác suất từ *mô hình thật*; không dùng nhãn
gốc để tạo score. Mỗi lần chạy cần ghi checksum dữ liệu, phiên bản model và
thiết lập môi trường nếu đưa vào báo cáo khoa học.

## Dashboard tương tác

Khi có mô hình tin cậy, tab **AI & đánh giá** hiển thị bảng TP/FP/TN/FN và đồ thị Precision/Recall/FPR ở các ngưỡng cố định. Kết quả chỉ tính trên các dòng đang xem, không tương đương số liệu full test trong báo cáo. CSV không có nhãn chỉ hiển thị số lượng cảnh báo. Không chọn ngưỡng từ biểu đồ test để rồi báo cáo chính biểu đồ đó là đánh giá độc lập.
