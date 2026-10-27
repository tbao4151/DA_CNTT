# DA005 — Quy trình thực nghiệm trên máy Windows và thu thập minh chứng

Tài liệu này dành cho **thành viên nhóm trực tiếp chạy và phân tích** dự án trên máy của mình trước khi báo cáo GVHD. Các lần chạy GitHub Actions, kể cả Windows runner, **không phải** bằng chứng nhóm đã tự thao tác trên máy cá nhân.

## 1. Chuẩn bị

Yêu cầu: Windows 10/11, Git, Python 3.11, dung lượng đĩa/RAM đủ để huấn luyện Random Forest. Dùng PowerShell trong thư mục dự án:

~~~powershell
git clone https://github.com/tbao4151/DA_CNTT.git
cd DA_CNTT
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-app.txt
~~~

Nếu đã có repository, kiểm tra thay đổi chưa commit trước khi chạy git pull; **không ghi đè mã hoặc dữ liệu local**.

## 2. Thực nghiệm có thể tái lập

~~~powershell
.\.venv\Scripts\python.exe scripts/download_unsw_nb15.py
.\.venv\Scripts\python.exe scripts/train_siem.py
.\.venv\Scripts\python.exe scripts/verify_local_run.py
~~~

- Lệnh thứ nhất kiểm tra SHA-256 và số dòng của hai tập UNSW-NB15 (có thể tải lại khi thiếu).
- Lệnh thứ hai **thực sự huấn luyện** trên 175.341 flow train và tạo model/metrics trong thư mục artifacts/ cục bộ.
- Lệnh thứ ba **không huấn luyện lại**: kiểm tra SHA-256 train/test, đọc model joblib tin cậy do chính nhóm tạo, dự đoán lại trên 82.332 flow test, so sánh confusion matrix, classification report và average precision với artifacts/metrics.json. Nếu bất nhất, lệnh báo lỗi và **không xuất kết quả thành công mới**.
- Kết quả được lưu tại artifacts/local_verification.json (đã gitignore), gồm thời điểm UTC, OS/Python/pandas/scikit-learn, commit, checksum dataset/model/metrics và chỉ số tính lại. Không tự tải file này lên GitHub.
- Trường dashboard_vs_model_predict_disagreements_at_0_5 ghi nhận khác biệt nếu quy tắc ngưỡng >=0.5 trên dashboard không trùng hoàn toàn với model.predict (ví dụ xác suất hòa 0,5). Nếu khác 0, phải phân tích trước khi khẳng định hai cách đánh giá tương đương.

**An toàn:** joblib dùng pickle, có thể thực thi mã khi load. Chỉ chạy verifier với model do chính nhóm huấn luyện hoặc nguồn thực sự tin cậy. Không đưa log/mẫu mạng nhạy cảm lên repository.

## 3. Thao tác SIEM/SOC trực tiếp

~~~powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
~~~

Trên trình duyệt localhost: kiểm tra 5 tab, dùng Threat hunting lọc proto/service/state, mở **Trung tâm cảnh báo** để chọn flow AI dự đoán Attack, tạo SOC case, cập nhật trạng thái và ghi chú, tải JSON hồ sơ. Thử tải một CSV hợp lệ và một CSV lỗi (ví dụ header trùng); ghi nhận kết quả. Đây là dữ liệu lịch sử, không phải giám sát mạng trực tiếp.

## 4. Hồ sơ minh chứng cho giảng viên

Lưu riêng tại máy cá nhân: ảnh terminal hiện phiên bản Python/Git và lệnh đã chạy, ảnh kết quả train, ảnh JSON verification và checksum, ảnh từng bước UI/SOC, ảnh case JSON xuất được, ghi chú lỗi gặp phải và cách khắc phục. Ghi rõ ngày giờ, commit, tên máy/OS nếu nhóm đồng ý chia sẻ. **Không tạo ảnh giả, không gắn nhãn 'đã chạy local' cho kết quả CI.**

Ghi lại nhận xét độc lập của nhóm: giải thích TP/FP/TN/FN; tại sao 8.400 FP ở baseline là hạn chế; đánh đổi Recall/FP của ngưỡng 0,55; lý do không dùng label và attack_cat làm đầu vào; giới hạn thiếu IP/timestamp của official train/test. Không chọn lại ngưỡng dựa trên test.

## 5. Trạng thái và giới hạn

Chỉ khi **người dùng thực sự chạy trên Windows của mình**, đối chiếu tệp JSON với ảnh màn hình và ghi nhận lỗi, mới được ghi vào báo cáo rằng nhóm đã thực nghiệm local. Script kiểm chứng tính nhất quán artifact/dataset, không chứng minh ai đã thực hiện thao tác, không kiểm định hệ thống production và không thay thế kiểm thử thủ công. Báo cáo JSON không có chữ ký số và có thể bị sửa.
