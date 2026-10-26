# Global AI Explainability — MDI / Gini importance

## Vì sao có phần này?

Khi bảo vệ DA005, nhóm cần giải thích **mô hình Random Forest sử dụng các
đặc trưng network flow nào trong quá trình huấn luyện**. Tab **AI & đánh giá**
trình bày mức độ quan trọng toàn cục (global feature importance), không phải
lý do cụ thể khiến một flow bị gán nhãn Attack.

## Cách tính

Mô hình huấn luyện trong `src/siem_ai/model.py` dùng `ColumnTransformer`,
`SimpleImputer` và `OneHotEncoder` trước `RandomForestClassifier`.
Thư viện sklearn cung cấp `forest.feature_importances_`: tầm quan trọng
theo *mean decrease in impurity* (MDI).

`src/siem_ai/explain.py` lấy thứ tự đầu ra từ transformer đã **fit**,
gộp các chiều one-hot cùng thuộc một đặc trưng đầu vào (chẳng hạn
`proto`, `service`, `state`) bằng cách **cộng** các giá trị MDI tương
ứng, và giữ nguyên mỗi đặc trưng số. Hàm kiểm tra kích thước và từ chối
mapping khi cấu hình tiền xử lý không tương thích; không đoán tên feature
từ dấu gạch dưới trong category.

Các trường `id`, `label`, `attack_cat` bị loại khỏi đầu vào AI.
Không dùng ground truth test để tính MDI; biểu đồ được lấy từ **mô hình đã
huấn luyện thật**, không phát sinh số liệu mẫu để giả lập biểu đồ.

## Giới hạn cần trả lời trước hội đồng

- MDI đo mức đóng góp vào giảm độ hỗn tạp của cây, **không phải tác động
  nhân quả** của đặc trưng lên nguy cơ tấn công.
- MDI có thể thiên lệch về các biến có nhiều giá trị duy nhất; giữa các
  đặc trưng tương quan, mức quan trọng có thể bị chia sẻ.
- Đây là giải thích **toàn cục**, không phải bằng chứng cho một alert
  đơn lẻ. Tín hiệu quy tắc ở màn hình SOC là heuristic phụ trợ, không
  thay thế giải thích của mô hình.
- Không chọn thuật toán/ngưỡng dựa trên kết quả official test từ biểu đồ
  này. Nếu cần nghiên cứu bổ sung, chạy permutation importance trên
  validation từ **training** với protocol cố định.
- Có mô hình joblib tin cậy thì mới hiển thị; nếu không có mô hình,
  UI thông báo rõ, không tạo feature importance giả.

## Cách kiểm tra

```powershell
python -m pytest -q tests/test_explain.py
python -m pytest -q tests
python scripts/train_siem.py
streamlit run app.py
```

Mở **AI & đánh giá** → **AI Explainability**. So sánh tên đặc trưng
với danh sách `features` trong report baseline; tổng MDI gốc nên xấp
xỉ 1 (100%) và tổng chiều sau mã hóa bằng số chiều đầu vào fitted forest.

Chưa có kết quả feature ranking chính thức trước khi chạy với
mô hình UNSW-NB15 thật. Không được dùng thứ hạng từ synthetic unit tests
làm kết luận nghiên cứu.

## Thực nghiệm tái lập trên UNSW-NB15 chính thức

```powershell
python scripts/download_unsw_nb15.py
python scripts/train_siem.py
python scripts/report_feature_importance.py
```

Script báo cáo sử dụng `artifacts/unsw_binary_rf.joblib` do người dùng
hoặc workflow tin cậy **tự huấn luyện**, không tải pickle không rõ nguồn.
Nó chỉ sử dụng cấu trúc RandomForest đã fitted; không đọc nhãn test để
xếp hạng biến. Kết quả `artifacts/official_feature_importance.json`
có danh sách xếp hạng, tổng trọng số (xấp xỉ 1), tên đặc trưng,
số chiều sau one-hot, SHA-256 dữ liệu training và SHA-256 file mô hình.

Workflow `.github/workflows/explainability.yml` trên GitHub Actions
thực hiện đúng các bước và lưu artifact `da005-official-global-explainability`
trong 14 ngày, **không tự động commit** kết quả hay pickle lên nhánh chính.
Chỉ kết luận thứ hạng đặc trưng sau khi kiểm tra log CI và báo cáo.
Đây là **MDI toàn cục từ mô hình được fitted**; không phải phép kiểm định
độ quan trọng độc lập, không phải giải thích cho từng alert và có thể có
thiên lệch do cardinality/tương quan.

## Kết quả thực nghiệm đã được xác minh (27/10/2026)

GitHub Actions [#40377900643](https://github.com/tbao4151/DA_CNTT/actions/runs/40377900643)
đã chạy thành công trên 175.341 flow train UNSW-NB15 và tạo báo cáo
[official_global_feature_importance.json](../reports/official_global_feature_importance.json).
Bảng đo được gồm 42 đặc trưng gốc từ mô hình (194 chiều sau mã hóa).
Top 5 **global MDI**: `sttl` 10,32%; `ct_state_ttl` 6,86%;
`rate` 5,31%; `dload` 5,23%; `sload` 4,50%.

Các giá trị này là trọng số mô tả *mô hình được huấn luyện*, không phải
ước lượng hiệu năng mới, yếu tố gây tấn công hoặc bằng chứng cho một flow.
Không chọn lọc biến/thuật toán dựa trên official test từ bảng xếp hạng.
Có thể tải artifact từ workflow trong vòng 14 ngày; bản JSON trong `reports/`
được giữ lâu dài cùng SHA-256 của dữ liệu và mô hình để tái lập.
