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
