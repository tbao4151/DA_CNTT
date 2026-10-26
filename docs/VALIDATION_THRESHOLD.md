# Chọn ngưỡng trên validation, không tối ưu trên test

Script `scripts/select_validation_threshold.py` đọc **chỉ** tập training chính thức
UNSW-NB15, tách 80% fit và 20% validation có phân tầng nhãn (seed 42).
Một Random Forest tạm được huấn luyện trên 80% và cho điểm xác suất trên
20% validation. Chính sách chọn ngưỡng có số **False Positive ít nhất**
trong các ứng viên 0.50–0.95, với ràng buộc Attack Recall >= 95%.
Nếu không có ngưỡng thỏa mãn, script báo lỗi, không tự hạ tiêu chí.

Chạy trên máy có đủ RAM và dependencies:

```powershell
python scripts/select_validation_threshold.py
```

Kết quả lưu `artifacts/validation_threshold.json` (không commit), gồm
ngưỡng đề xuất, TP/FP/TN/FN và Precision/Recall/F1 trên **validation**.
Script không đọc tập test chính thức, không sửa baseline hoặc cấu hình
ngưỡng của dashboard. Không có số liệu mới cho tới khi chạy script.

**Giới hạn:** ngưỡng được chọn cho mô hình huấn luyện trên 80% training;
mô hình benchmark chính thức được huấn luyện trên 100% training nên phân bố
score có thể khác. Quy trình nghiên cứu đúng là chọn trước phương pháp,
ngưỡng và ràng buộc trên validation; sau đó refit mô hình theo thiết kế
đã khóa và đánh giá *một lần* trên official test. Không dùng test để
điều chỉnh ngưỡng hoặc chọn mô hình.

## Chạy kiểm chứng trên GitHub Actions

GitHub Actions workflow `.github/workflows/validation-threshold.yml` có thể chạy
thủ công (Actions → **Validation-only alert threshold experiment** → **Run workflow**),
hoặc chạy khi chính workflow được thêm/sửa trên nhánh `main`.

Các bước gồm xác thực tệp UNSW-NB15 và SHA-256, chọn ngưỡng chỉ từ
validation của training, xác nhận tổng TP/FP/TN/FN và Recall >= 95%,
sau đó lưu `validation_threshold.json` dưới artifact
`da005-validation-threshold` (14 ngày). Workflow không tự commit JSON,
không xuất mô hình joblib và không cập nhật benchmark test chính thức.

Dù workflow chạy thành công, ngưỡng được chọn mới là **ứng viên từ
validation**, không phải bằng chứng hiệu năng đã cải thiện trên official test.
