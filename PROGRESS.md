# DA005 — Nhật ký tiến độ có căn cứ

## 2026-10-26: Khởi tạo bộ khung Mini-SIEM

- Đã có `data/raw/unsw_nb15/` gồm hai CSV và metadata số hàng, SHA-256 (được thêm ở các commit trước).
- Thêm `app.py` Streamlit: overview, threat hunting, AI metrics, alert queue, SOC case management.
- Thêm `src/siem_ai/core.py`: validate sơ đồ cột, flow digest không dùng nhãn, rule heuristic, SQLite cases.
- Thêm `src/siem_ai/model.py` và `scripts/train_siem.py`: pipeline Random Forest, fit train và evaluate trên test chính thức.
- Thêm unit tests và GitHub Actions CI; **chưa được xác nhận CI pass** tại thời điểm ghi.
- Không có kết quả accuracy/F1 được bịa ra, chưa lưu model hay metrics thực nghiệm trong repository.
- MVP hiện là hệ thống phân tích dữ liệu lịch sử, KHÔNG là SIEM production và KHÔNG có giám sát real-time.

## Bước ưu tiên tiếp theo

1. Kiểm tra CI thực tế và chạy giao diện end-to-end.
2. Huấn luyện model và lưu metrics thật dưới dạng artifact (không đưa file pickle không rõ nguồn lên repo).
3. Nâng cấp trải nghiệm demo, quản lý case và tài liệu vấn đáp.

## Khi tiếp tục ở cuộc trò chuyện mới

Đọc `README.md`, `PROGRESS.md`, `ROADMAP.md`, kiểm tra commit mới nhất/CI trước khi thêm mã. Không diễn giải kế hoạch là công việc đã hoàn thành.

## 2026-10-26: SOC data-integrity hardening (merged)

- Flow digests exclude AI-derived prediction columns and UI identifiers, so the
  same flow retains its reference before and after model inference.
- Reject non-finite confidence values and whitespace-only analyst notes.
- Add regression tests for those cases.
- Unit tests and syntax checks passed in GitHub Actions runs 40304227558 and 40304234394.
- Merged as PR #2, squash commit 688a3a245a1ce0a4cfce47df88ae28c60111d7ce.

## 2026-10-26: Benchmark chính thức và tài liệu bảo vệ (đã xác minh)

- PR #3 đã hợp nhất: regression test chống rò rỉ nhãn, workflow benchmark và `docs/DEFENSE_GUIDE.md`.
- GitHub Actions CI chạy thành công trên main tại commit `bce488f74`.
- Benchmark trên tập UNSW-NB15 train (175.341) / test (82.332) chạy thành công, xuất `reports/official_baseline_metrics.json`.
- Attack Precision = 0.8411107; Recall = 0.9809186; F1 = 0.9056508; macro-F1 = 0.8831270. Confusion matrix [Normal, Attack] = [[28600,8400],[865,44467]].
- Model joblib có trong GitHub Actions artifact ngắn hạn (7 ngày), không commit pickle binary vào repository. Có thể tự huấn luyện để tái tạo model.
- Còn nhiều False Positive (8.400/37.000 bản ghi Normal), cần nghiên cứu ngưỡng cảnh báo, so sánh các mô hình, tăng tính giải thích và kiểm thử tích hợp.
- Có kết quả AI thật nhưng **không đồng nghĩa đã hoàn thành sản phẩm Mini-SIEM**, chưa xác minh giao diện end-to-end trên Windows.

## 2026-10-26: SOC evidence + audit trail (merged, CI verified)

- Thêm bảng SQLite `case_events` lưu từng lần tạo/cập nhật hồ sơ theo transaction; giữ lại trạng thái trước/sau, ghi chú và thời gian UTC.
- Thêm `case_evidence` đọc bản chụp đặc trưng lúc tạo case, `case_history` đọc lịch sử; hiển thị trong tab SOC.
- Có kiểm thử hồi quy cho lịch sử, cập nhật sai và nâng cấp database cũ không xóa case. CI syntax + unit tests thành công: Actions run 40311765832; PR #4 squash merge commit 894155c4e3daff64481d93928fc7f7552ca36448.
- Giới hạn: chưa có đăng nhập/định danh analyst, log audit không chống sửa đổi ở cấp DB; chỉ phục vụ demo cục bộ.

## 2026-10-26: Hardening CSV export (PR #5 merged, CI verified)

- Phát hiện nguy cơ CSV formula injection khi tải kết quả threat hunting và mở trong ứng dụng bảng tính.
- Thêm `safe_csv_bytes` để vô hiệu hóa công thức trong ô text và header, bảo toàn giá trị số, xuất UTF-8 BOM cho Excel.
- Thêm ba unit tests cho formula prefix, ký tự vô hình, dữ liệu trống và tính bất biến của DataFrame đầu vào.
- Kiểm thử cục bộ riêng module export: `python -m pytest -q tests/test_export.py` → **3 passed**. GitHub Actions CI (syntax + toàn bộ unit tests) thành công tại runs **40319621687** và **40319638968**; PR #5 squash merge commit `e7ff8297ed2ca20a83748f21cdfba78ddffbfb47`. Chưa xác minh smoke test Streamlit/Windows.


## 2026-10-26: Threshold diagnostics (PR #6 merged, CI verified)

- Added `threshold_diagnostics` pure evaluator calculating TP/FP/TN/FN, Attack Precision/Recall/F1, false-positive rate and alert count at explicit thresholds.
- Added input validation and unit regression tests for counts, malformed probabilities, labels and empty inputs.
- Added `scripts/analyze_thresholds.py` to analyze probabilities from a **trusted locally trained model**, with CSV output under ignored `artifacts/`.
- Added `docs/THRESHOLD_EVALUATION.md` explaining tradeoffs and avoiding choosing thresholds on the official test set.
- GitHub Actions CI success for PR head e73995a648ca5072c52e506079e32ecb27b79334 (run 40342277345); merged as PR #6, squash commit 40ea3ddf7138666bd37e7b02ece964f276817310. No new empirical threshold scores are claimed and no model settings were changed.

## 2026-10-26: Dashboard threshold analysis and smoke test (PR #7 merged, CI verified)

- Tab `AI & đánh giá` now includes per-threshold diagnostic table and Precision/Recall/FPR curves when a trusted local model and 0/1 ground-truth labels are available. For unlabeled CSV, only alert counts are shown; invalid labels do not produce fabricated metrics.
- Explicit warnings distinguish the currently loaded subset from the official full held-out benchmark and prohibit tuning thresholds on the official test set.
- Added Streamlit AppTest smoke test for startup without a trained model, using repository test data; CI passed on PR head c0510266330e1fa00e6951b932315656e54b389f (run 40345278403). Merged as PR #7, squash commit 64a28cde21fbdac31f1072a9dc6cf3d28ab15450. This is **not** Windows E2E verification.
