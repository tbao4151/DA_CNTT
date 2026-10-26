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

## Ứng viên đã xác minh và đánh giá trên test độc lập

Actions run [40366465257](https://github.com/tbao4151/DA_CNTT/actions/runs/40366465257)
đã chạy thành công: 140.272 hàng fit, 35.069 hàng validation, chọn
ngưỡng 0,55 (TP=22.861, FP=567, TN=10.633, FN=1.008;
Recall=0,95776949, F1=0,96669979). File
`reports/validation_threshold_experiment.json` lưu ứng viên và nguồn
kiểm chứng **trước khi** đánh giá trên test. Các số này **không** là
benchmark chính thức và không thể đối chiếu FP trực tiếp với baseline test.

`.github/workflows/locked-threshold-test.yml` huấn luyện lại Random
Forest trên toàn bộ 175.341 hàng training, đánh giá trên đúng 82.332 hàng
test và so sánh 0,50 với ngưỡng **đã khóa 0,55** trên cùng một vector
xác suất. Lệnh chạy cục bộ sau khi tự tạo mô hình tin cậy:

```powershell
python scripts/train_siem.py
python scripts/evaluate_locked_threshold.py
```

Workflow kiểm tra checksum trước khi chạy và chỉ xuất
`artifacts/locked_threshold_official_test.json` làm Actions artifact
14 ngày. Kết quả phải báo cả thay đổi false positives **và** false
negatives/recall, không tự chọn lại ngưỡng từ test. Không tự động áp
ngưỡng này vào giao diện cảnh báo SOC.

## Kết quả official test đã xác minh (không tối ưu lại)

Workflow [40373007093](https://github.com/tbao4151/DA_CNTT/actions/runs/40373007093)
đã thành công trên 82.332 flow official test với Random Forest được
huấn luyện trên toàn bộ 175.341 flow official training. Báo cáo lưu tại
`reports/official_locked_threshold_comparison.json`.

| Chỉ số | Baseline 0,50 | Ngưỡng khóa 0,55 |
| --- | ---: | ---: |
| TP | 44.467 | 44.125 |
| FP | 8.400 | 7.135 |
| TN | 28.600 | 29.865 |
| FN | 865 | 1.207 |
| Attack Precision | 84,11% | 86,08% |
| Attack Recall | 98,09% | 97,34% |
| Attack F1 | 90,57% | 91,36% |

Giảm 1.265 false positives tương đương khoảng 15,06% so với baseline,
đổi lại **tăng 342 false negatives**. Ngưỡng 0,55 được chọn từ
validation trước khi chạy official test, **không** được điều chỉnh theo
kết quả này. Không suy diễn thành tỷ lệ phát hiện tấn công ngoài thực tế;
chưa có kiểm thử Windows end-to-end và chưa triển khai ngưỡng mới trên
SOC dashboard.
