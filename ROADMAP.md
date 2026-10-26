# DA005 — Lộ trình phát triển có thể kiểm chứng

## Tiêu chí nghiệm thu

1. Chạy cục bộ từ README; không yêu cầu dịch vụ trả phí.
2. Dữ liệu UNSW-NB15 chính thức; checksum và tập train/test rõ ràng.
3. Pipeline chống rò rỉ nhãn; kết quả Precision/Recall/F1 và confusion matrix có thể tái lập.
4. Dashboard trực quan phục vụ phân tích mạng; không nhầm ground truth thành dự đoán AI.
5. SOC case management: tạo cảnh báo, trạng thái xử lý, ghi chú/bằng chứng.
6. Automated tests, xử lý lỗi và tài liệu demo/bảo vệ.
7. Không tuyên bố thời gian thực, không khẳng định đây là SIEM sản xuất.

## Ưu tiên triển khai (đề xuất nhóm, không phải phân công của GVHD)

- [x] Dữ liệu UNSW-NB15, metadata và script tải.
- [x] Cấu trúc MVP Mini-SIEM bằng Streamlit, thư viện phân tích, SQLite.
- [x] Script Random Forest train/test không đưa nhãn vào features.
- [x] CI khởi tạo (trạng thái chạy cần xác minh).
- [x] CI syntax và unit tests đã chạy thành công (GitHub Actions, bao gồm PR #4); vẫn cần kiểm thử giao diện end-to-end trên Windows.
- [ ] Kiểm thử Streamlit end-to-end trên Windows, sửa lỗi môi trường và các trường hợp biên (đã bổ sung smoke test AppTest không có model và integration test AI → SQLite SOC với dữ liệu tổng hợp; vẫn chưa phải E2E Windows).
- [x] Huấn luyện Random Forest trên train/test chính thức, lưu metrics thật và artifact (GitHub Actions).
- [ ] Tái lập benchmark độc lập trên môi trường sạch và xác minh artifact chạy với giao diện.
- [x] Xây dựng chính sách chọn ngưỡng chỉ trên validation từ tập training (đã có code + unit tests; chưa có kết quả chạy trên dữ liệu thật và chưa tích hợp tự động vào dashboard).
- [ ] Bổ sung so sánh Logistic Regression / Random Forest / Gradient Boosting.
- [ ] Thêm explainability (feature importance hoặc permutation importance trên tập cố định).
- [ ] Nâng UX demo (đã bổ sung phân tích ngưỡng và bằng chứng flow đầy đủ cho case mới; còn lọc đa chiều và xuất báo cáo case).
- [ ] Kiểm thử an toàn tệp đầu vào và giới hạn tài nguyên (đã bổ sung bảo vệ CSV formula injection ở đường xuất; chưa hoàn tất kiểm thử upload, file lớn và tài nguyên).
- [ ] Tài liệu kiến trúc, threat model, kịch bản demo và câu hỏi hội đồng.
- [ ] Đề nghị GVHD xác nhận phạm vi Network Flow Logs và nghiệp vụ SOC.

Giữ scope khả thi: UNSW-NB15 train/test thiếu IP và timestamp gốc; chức năng correlation theo IP/thời gian chỉ triển khai khi có dữ liệu nguồn phù hợp.
