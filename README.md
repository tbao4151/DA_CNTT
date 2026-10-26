# DA005 — AI Applications in System Log Analysis and Attack Detection

**Môn học:** Dự án CNTT — Đại học Tôn Đức Thắng (TDTU)  
**Mã đề tài:** DA005 — Ứng dụng AI trong phân tích nhật ký hệ thống và phát hiện tấn công  
**Nhóm:** Nguyễn Văn Thiên Bảo (52300179) & Đặng Triệu Vỹ (52300274)  
**Giảng viên hướng dẫn:** Trương Đình Tú

## Sentinel Lab: Mini-SIEM + AI + SOC Workflow (Prototype)

Nhóm lựa chọn **Network Flow Logs**, thiết kế một **bản mô phỏng Mini-SIEM** với AI phát hiện tấn công và quy trình SOC Analyst. Sản phẩm chạy cục bộ, đọc tệp lưu lượng mạng lịch sử UNSW-NB15, cho phép phân tích tương tác, tạo cảnh báo từ mô hình đã huấn luyện và theo dõi hồ sơ điều tra.

**Phân biệt quan trọng:** Đây là prototype nghiên cứu, không phải SIEM/SOC vận hành thật; bản UNSW-NB15 train/test không cung cấp IP nguồn/đích và thời gian sự kiện gốc. Không được diễn giải thứ tự dòng là timeline thời gian. Các nhãn `label` / `attack_cat` chỉ là ground truth, **không phải input AI**.

## Chạy nhanh trên Windows 10/11

Yêu cầu Python 3.11 và Git:

```powershell
git clone https://github.com/tbao4151/DA_CNTT.git
cd DA_CNTT
py -3.11 -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements-app.txt
streamlit run app.py
```

Truy cập URL cục bộ Streamlit hiển thị trong terminal (thường là http://localhost:8501). Giao diện mặc định cho phép **khám phá ground truth ngay cả khi chưa có mô hình**; hệ thống không giả lập dự đoán khi chưa train.

Dataset đã có ở `data/raw/unsw_nb15/`. Nếu thiếu:

```powershell
python scripts/download_unsw_nb15.py
```

## Huấn luyện và tạo cảnh báo AI thực sự

```powershell
python scripts/train_siem.py
streamlit run app.py
```

Lệnh huấn luyện tạo `artifacts/unsw_binary_rf.joblib` và `artifacts/metrics.json` **trên máy của bạn**. Những file này được gitignore; chạy train có thể tốn thời gian/bộ nhớ. Chỉ tải model joblib do chính bạn tạo và tin cậy (pickle có thể thực thi mã).

Sau khi có mô hình: Tab **AI & đánh giá** hiển thị kết quả test chính thức; **Trung tâm cảnh báo** hiển thị điểm dự đoán và tạo case; **SOC case management** lưu hồ sơ, bản chụp bằng chứng flow và lịch sử thay đổi trạng thái vào SQLite tại `runtime/soc_cases.sqlite3` (audit trail cho demo, không chống sửa đổi bởi người có quyền DB).

## Cấu trúc mã nguồn

```text
app.py                     Giao diện Streamlit
src/siem_ai/core.py         Kiểm tra log, rules mẫu, quản lý SOC cases
src/siem_ai/model.py        Huấn luyện, đánh giá và dự đoán
scripts/train_siem.py       CLI tạo mô hình/metrics
scripts/download_unsw_nb15.py Tải và kiểm tra SHA-256
data/raw/unsw_nb15/         Train/test chính thức và metadata
tests/                      Unit tests
.github/workflows/ci.yml    Kiểm tra tự động
PROGRESS.md                 Công việc thực tế / phần còn thiếu
ROADMAP.md                  Mục tiêu / thứ tự ưu tiên
```

## Minh chứng benchmark AI và chuẩn bị bảo vệ

- **Metrics thực nghiệm:** [reports/official_baseline_metrics.json](reports/official_baseline_metrics.json), sinh từ workflow huấn luyện toàn bộ trên GitHub Actions (không phải số giả).
- **Mô hình Random Forest:** Attack Precision 84,11%; Recall 98,09%; F1 90,57%. Tập test 82.332 flow. Đây là baseline ban đầu, còn 8.400 false positives, cần tối ưu.
- **Tài liệu vấn đáp:** [docs/DEFENSE_GUIDE.md](docs/DEFENSE_GUIDE.md).
- **Tải model dùng cho demo:** vào [Actions → Official UNSW-NB15 benchmark](https://github.com/tbao4151/DA_CNTT/actions/workflows/benchmark.yml), mở lần chạy thành công và tải artifact `da005-unsw-random-forest`. Giải nén các file `unsw_binary_rf.joblib` và `metrics.json` vào thư mục `artifacts/` của project. Chỉ tải artifact do workflow tin cậy của repository tạo.
- Nếu artifact quá hạn 7 ngày, chạy `python scripts/train_siem.py` trên máy để tạo lại model.
- Dashboard có thể hiển thị benchmark từ file report GitHub ngay cả khi chưa có model; **chức năng dự đoán và cảnh báo chỉ hoạt động khi có model thực sự**.

## Kiểm thử

```powershell
python -m pytest -q tests
```

## Dữ liệu và trích dẫn

- UNSW-NB15 official description: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- Bản train/test: 175.341 và 82.332 bản ghi, gồm nhãn Normal/Attack cùng 9 nhóm tấn công.
- Nguồn tải và SHA-256 của bản sao được ghi tại `data/raw/unsw_nb15/metadata.json`.
- Moustafa, N. & Slay, J. (2015). *UNSW-NB15: A comprehensive data set for network intrusion detection systems*. MilCIS.

Đánh giá bằng Attack Precision/Recall/F1, macro-F1, confusion matrix và average precision; accuracy một mình không đủ. Đây là đánh giá trên dataset nghiên cứu, không suy rộng thành hiệu suất production.

## Trạng thái

Xem **[PROGRESS.md](PROGRESS.md)** (đã làm, đã kiểm chứng) và **[ROADMAP.md](ROADMAP.md)** (chưa làm). Tài liệu này không tuyên bố có kết quả huấn luyện hay kiểm thử đã hoàn thành nếu chưa có bằng chứng.
