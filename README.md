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

Lệnh huấn luyện tạo `artifacts/unsw_binary_rf.joblib` và `artifacts/metrics.json` **trên máy của bạn**. Những file này được gitignore; chạy train có thể tốn thời gian/bộ nhớ. Chỉ tải model joblib do chính bạn tạo và tin cậy (pickle có thể thực thi mã). Khi thay thế artifact mô hình tại cùng đường dẫn, dashboard dùng thời gian sửa đổi và kích thước tệp để làm mới cache mô hình ở lần chạy lại; nếu sao chép tệp mà giữ nguyên cả hai metadata này, hãy khởi động lại Streamlit để chắc chắn tải đúng mô hình.

Pipeline huấn luyện yêu cầu nhãn `label` đầy đủ, chỉ nhận giá trị 0/1 ở cả train và test; từ chối nhãn thiếu hoặc sai định dạng trước khi fit. Các trường ground truth (`id`, `label`, `attack_cat`) và trường phát sinh từ giao diện/dự đoán (`AI_verdict`, `AI_attack_probability`, `flow_ref`) đều bị loại khỏi đặc trưng học để tránh rò rỉ thông tin khi tái sử dụng bảng đã phân tích.

Khi dự đoán, pipeline xác định xác suất Attack theo nhãn lớp `1` thực tế trong mô hình (không mặc định cột thứ hai), và từ chối mô hình thiếu lớp 0/1 hoặc xác suất không hợp lệ. Huấn luyện yêu cầu có cả hai lớp trong tập train; không tự sửa hay tái huấn luyện model không tương thích.

Sau khi có mô hình: Tab **AI & đánh giá** hiển thị kết quả test chính thức; **Trung tâm cảnh báo** hiển thị điểm dự đoán và tạo case; **SOC case management** lưu hồ sơ, bản chụp các đặc trưng flow (không gồm nhãn gốc hoặc cột AI/UI phát sinh) và lịch sử thay đổi trạng thái vào SQLite tại `runtime/soc_cases.sqlite3` (audit trail cho demo, không chống sửa đổi bởi người có quyền DB). Trong tab **SOC case management**, có thể tải **JSON của một hồ sơ** (metadata, snapshot đặc trưng, lịch sử xử lý) để trình bày khi bảo vệ; đây là bản xuất cục bộ, không có chữ ký số và có thể chứa ghi chú nhạy cảm, không phải chứng cứ pháp lý chống sửa đổi.

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

**Nhập CSV kiểm soát:** Chế độ tải CSV chỉ đọc tối đa 10.000 flow trong bản xem trước và giới hạn tệp 15 MiB. Parser kiểm tra header CSV gốc trước khi pandas tự đổi tên cột trùng (`proto,proto` thành `proto,proto.1`), từ chối cột rỗng, tệp rỗng và mã hóa không phải UTF-8 (có hỗ trợ BOM). Sau đó hệ thống tiếp tục kiểm tra các cột network flow bắt buộc. Đây là biện pháp giảm lỗi nhập liệu cho prototype, không phải sandbox bảo mật cho dữ liệu không tin cậy.

**Xuất CSV an toàn:** Kết quả threat hunting được xử lý để chuỗi bắt đầu bằng ký tự công thức không tự thực thi khi mở bằng ứng dụng bảng tính. Giá trị text nguy hiểm được thêm dấu nháy đơn, vì vậy CSV xuất phục vụ xem và không phải bản sao nguyên trạng của dữ liệu gốc.

## Bộ lọc Threat hunting đa chiều

Tab **Threat hunting** lọc theo giao thức (`proto`), dịch vụ (`service`), trạng thái kết nối (`state`), và — khi có mô hình AI thật — chỉ các flow AI dự đoán Attack hoặc xác suất Attack tối thiểu. Chọn nhiều giá trị trong cùng một bộ lọc nghĩa là **OR**; các nhóm lọc kết hợp theo **AND**. Bảng kết quả và CSV xuất chỉ chứa những dòng đã lọc. Số dòng hiển thị được tính trên **mẫu đang tải** (tối đa 10.000 dòng qua thanh trượt), không phải toàn bộ tập test. Không có model vẫn lọc được theo thuộc tính network flow, không giả lập dự đoán.

## Phân tích ngưỡng ngay trên dashboard

Tab **AI & đánh giá** có bảng và biểu đồ Precision, Recall, False Positive Rate theo ngưỡng khi có mô hình và nhãn ground truth 0/1. Đây là **phân tích trên mẫu đang tải** (mặc định là những dòng đầu của test), không phải kết quả chính thức trên toàn bộ test và không dùng để chọn ngưỡng triển khai. CSV không có nhãn chỉ hiển thị số lượng cảnh báo theo ngưỡng. Xem [docs/THRESHOLD_EVALUATION.md](docs/THRESHOLD_EVALUATION.md).

## Chọn ngưỡng trên tập validation

Để nghiên cứu giảm False Positive mà không tối ưu trên tập test chính thức, chạy `python scripts/select_validation_threshold.py`. Script chỉ đọc tập train, tách train/validation có phân tầng, tìm ngưỡng giảm cảnh báo nhầm với ràng buộc Recall tối thiểu 95%. Kết quả được lưu cục bộ trong `artifacts/validation_threshold.json`; không tự áp dụng vào dashboard hoặc thay đổi benchmark. Để chạy thí nghiệm trên GitHub, vào **Actions → Validation-only alert threshold experiment → Run workflow**. Workflow xác minh checksum, huấn luyện trên phần train của training split, kiểm tra JSON và cung cấp artifact `da005-validation-threshold` (lưu 14 ngày); không ghi kết quả lên repository và không thay đổi báo cáo official test. Xem [docs/VALIDATION_THRESHOLD.md](docs/VALIDATION_THRESHOLD.md).

Đã kiểm chứng trên validation thật: ứng viên ngưỡng **0,55** (Attack Recall 95,78%, 567 false positives trên 35.069 flow validation) từ [GitHub Actions #40366465257](https://github.com/tbao4151/DA_CNTT/actions/runs/40366465257). Kết quả **không được so sánh trực tiếp** với baseline test 0,50 vì khác mô hình/tập dữ liệu. Workflow `locked-threshold-test.yml` đánh giá ngưỡng đã khóa 0,55 và baseline 0,50 trên **cùng** full-training model và official test; không tự chọn lại ngưỡng dựa trên test. Workflow đã chạy thành công tại [Actions #40373007093](https://github.com/tbao4151/DA_CNTT/actions/runs/40373007093). Trên **82.332 flow official test**, ngưỡng 0,55 giảm false positives từ **8.400 xuống 7.135** (giảm 1.265, khoảng 15,1%) nhưng false negatives tăng từ **865 lên 1.207** (tăng 342); Attack Recall giảm từ **98,09% xuống 97,34%**, F1 tăng từ **90,57% lên 91,36%**. Đây là trade-off có đo đạc, không phải cải thiện đồng thời mọi chỉ số. Báo cáo lưu tại `reports/official_locked_threshold_comparison.json`. Chưa tự động áp ngưỡng 0,55 vào dashboard. Tab **AI & đánh giá** nay có bảng so sánh **official test 0,50 vs 0,55** đọc từ báo cáo lưu trong repository, hiển thị TP/FP/TN/FN, Precision/Recall/F1 và trade-off ngay cả khi chưa tải model. Bộ kiểm tra dữ liệu báo cáo từ chối số liệu thiếu hoặc mâu thuẫn; bảng này tách biệt hoàn toàn với biểu đồ chẩn đoán trên mẫu đang xem.


## Giải thích mô hình (global explainability)

Khi máy có mô hình Random Forest đã huấn luyện, tab **AI & đánh giá** hiển thị 12 đặc trưng network flow có MDI (Gini importance) cao nhất, gộp các chiều one-hot về tên cột nguồn; có bảng tất cả đặc trưng và xuất CSV an toàn. Đây là **mức quan trọng toàn cục**, không phải giải thích cho từng cảnh báo, và có thể thiên lệch với biến nhiều giá trị. Không có mô hình sẽ không hiển thị kết quả giả. Xem [docs/EXPLAINABILITY.md](docs/EXPLAINABILITY.md). Để tạo bảng xếp hạng **thực nghiệm** từ full-training UNSW, chạy `python scripts/train_siem.py` rồi `python scripts/report_feature_importance.py`; xuất `artifacts/official_feature_importance.json` gồm 42 đặc trưng, checksum dataset và model. Có workflow **Official UNSW-NB15 global AI explainability** trên GitHub Actions để kiểm chứng; chỉ dùng bảng ranking sau khi run thành công. **Đã xác minh:** [Actions #40377900643](https://github.com/tbao4151/DA_CNTT/actions/runs/40377900643) chạy thành công; báo cáo đủ 42 cột lưu tại [reports/official_global_feature_importance.json](reports/official_global_feature_importance.json). Top 3 MDI của Random Forest: `sttl` 10,32%, `ct_state_ttl` 6,86%, `rate` 5,31%. Đây không phải giải thích nhân quả hoặc cho từng flow.

## Kiểm thử giao diện bằng trình duyệt Windows (opt-in)

Workflow [Official-model dashboard integration smoke](.github/workflows/official-model-smoke.yml) có thêm bài kiểm thử Playwright Chromium trên **Windows**, sau khi xác minh checksum và huấn luyện từ tập train chính thức. Bài kiểm thử mở Streamlit qua **localhost** trong thư mục tạm, dùng 2.500 dòng đầu official test **chỉ để suy luận**, tạo SOC case bằng trình duyệt và tải/xác minh JSON. Không dùng mô hình không tin cậy, không ghi vào SQLite thực tế, không triển khai công khai.

Bài kiểm thử tại `tests/test_browser_soc_e2e.py` chỉ chạy khi `DA005_BROWSER_SOC_E2E=1` trong workflow cài Playwright/Chromium. `pytest` thông thường bỏ qua bài kiểm thử này. **Đã xác minh trên Windows Chromium:** [PR #25](https://github.com/tbao4151/DA_CNTT/pull/25), [GitHub Actions run 40442408258](https://github.com/tbao4151/DA_CNTT/actions/runs/40442408258) thành công cho cả Windows browser E2E và AppTest Windows/Ubuntu. Đây là kiểm thử đường đi AI → cảnh báo → tạo case → tải JSON; chưa xác minh mọi trường hợp biên hoặc trải nghiệm thủ công trên máy người dùng.

Bài kiểm thử Chromium được mở rộng để thay đổi trạng thái SOC từ `New` sang `Investigating`, lưu ghi chú, tải lại trang và kiểm tra JSON xuất sau cập nhật (cả trạng thái, sự kiện audit trail và bằng chứng gốc không đổi). **Đã kiểm chứng** trong [PR #26](https://github.com/tbao4151/DA_CNTT/pull/26), [GitHub Actions run 40443155381](https://github.com/tbao4151/DA_CNTT/actions/runs/40443155381): Chromium E2E Windows thành công với mô hình UNSW-NB15 huấn luyện chính thức. Vẫn chưa thay thế việc kiểm thử thủ công và bao phủ trường hợp biên.

## Kiểm thử

Bộ kiểm thử còn có `tests/test_soc_integration.py`: huấn luyện mô hình nhỏ trên dữ liệu **tổng hợp** để xác minh luồng dự đoán AI → tạo SOC case → lưu bằng chứng → cập nhật và truy xuất audit trail. Đây là integration regression test, không phải benchmark UNSW-NB15 hay kiểm thử giao diện Windows.

`tests/test_app_model_integration.py` chạy **Streamlit AppTest với mô hình Random Forest thật được huấn luyện trên dữ liệu tổng hợp**, dùng bản sao ứng dụng trong thư mục tạm để kiểm tra AI alert → tạo SOC case → xuất JSON mà không ghi vào cơ sở dữ liệu thực. Đây là kiểm thử giao diện không trình duyệt trên CI, **không** phải E2E Windows hoặc benchmark UNSW-NB15.

**Kiểm thử tích hợp với mô hình UNSW-NB15 chính thức:** Workflow [Official-model dashboard integration smoke](https://github.com/tbao4151/DA_CNTT/actions/workflows/official-model-smoke.yml) xác minh SHA-256 của dataset, huấn luyện mô hình trên official train rồi chạy `tests/test_official_model_app.py` với 2.500 dòng đầu official test để kiểm tra dự đoán → cảnh báo → tạo SOC case → xuất JSON trong thư mục tạm. [Run #40435254982](https://github.com/tbao4151/DA_CNTT/actions/runs/40435254982) đã thành công (1 test passed). Có thể kích hoạt lại bằng **Actions → Official-model dashboard integration smoke → Run workflow**. Workflow chạy ma trận **Ubuntu và Windows** (Python 3.11), mỗi runner tự xác minh checksum, huấn luyện mô hình và chạy kiểm thử headless. Run #40435254982 chỉ xác nhận **Linux**; [run #40440966634](https://github.com/tbao4151/DA_CNTT/actions/runs/40440966634) trên PR và [run #40441303872](https://github.com/tbao4151/DA_CNTT/actions/runs/40441303872) sau merge đã **thành công trên cả Ubuntu và Windows**. AppTest không mở trình duyệt, nên **không thay thế kiểm thử giao diện bằng trình duyệt trên Windows** và không tạo benchmark AI mới.


```powershell
python -m pytest -q tests

# Bao gồm smoke test Streamlit không cần trình duyệt (AppTest).
# Chưa thay thế kiểm thử thủ công với model trên Windows.
```

## Dữ liệu và trích dẫn

- UNSW-NB15 official description: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- Bản train/test: 175.341 và 82.332 bản ghi, gồm nhãn Normal/Attack cùng 9 nhóm tấn công.
- Nguồn tải và SHA-256 của bản sao được ghi tại `data/raw/unsw_nb15/metadata.json`.
- Moustafa, N. & Slay, J. (2015). *UNSW-NB15: A comprehensive data set for network intrusion detection systems*. MilCIS.

Đánh giá bằng Attack Precision/Recall/F1, macro-F1, confusion matrix và average precision; accuracy một mình không đủ. Đây là đánh giá trên dataset nghiên cứu, không suy rộng thành hiệu suất production.

## Trạng thái

Xem **[PROGRESS.md](PROGRESS.md)** (đã làm, đã kiểm chứng) và **[ROADMAP.md](ROADMAP.md)** (chưa làm). Tài liệu này không tuyên bố có kết quả huấn luyện hay kiểm thử đã hoàn thành nếu chưa có bằng chứng.
