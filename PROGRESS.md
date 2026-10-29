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
- Added Streamlit AppTest smoke test for startup without a trained model, using repository test data; CI passed on PR head c0510266330e1fa00e6951b932315656e54b389f (run 40345278403) and on main squash commit 64a28cde21fbdac31f1072a9dc6cf3d28ab15450 (run 40345469464). Merged as PR #7, squash commit 64a28cde21fbdac31f1072a9dc6cf3d28ab15450. This is **not** Windows E2E verification.

## 2026-10-26: Full flow evidence + AI-to-SOC integration regression (PR pending)

- Store all available original flow feature columns (bounded to 256 characters per value), not only the seven preview fields, when creating new SOC cases. Exclude `id`, `label`, `attack_cat` and AI/UI-derived columns; existing SQLite case rows are not migrated or overwritten.
- Added a synthetic-data integration regression that trains a small real Random Forest pipeline, generates an actual alert probability, creates a SQLite SOC case, verifies the feature snapshot and digest, and checks state changes and audit history.
- Synthetic fixture metrics are **not** UNSW-NB15 research results. No new official benchmark or Windows E2E validation claimed.
- GitHub Actions CI (syntax + unit/integration tests + Streamlit smoke) passed for PR #8 head `f78a1ff88e5d3bea321e7a27a0114b61c40768c2` (run `40355351753`). PR #8 merged into `main` as squash commit `5d48f541d6dac11509bb29fb6829606d5389ad71`; post-merge main CI also passed (run `40355540401`). Windows E2E with the official trained model remains unverified.

## 2026-10-26: Validation-only threshold policy (PR #9 merged, PR CI verified)

- Added a deterministic selection policy minimizing false positives subject to a validation recall floor, with unit tests for tradeoffs, infeasible constraints and invalid inputs.
- Added a CLI that uses a stratified 80/20 split of **official training only** and stores candidate metrics in ignored `artifacts/validation_threshold.json`.
- Added research-method documentation; no official test used for selection and no new benchmark or performance improvement claimed.
- GitHub Actions PR checks passed: runs 40364481944 and 40364494536 (syntax + tests). Merged via PR #9 as squash commit 50d548f7e758c291ccd30c88411228200c1969e1. Post-merge main CI also passed (run 40364700658, commit 50d548f7e758c291ccd30c88411228200c1969e1). Windows end-to-end and execution of the new validation CLI on the full dataset remain unverified.

## 2026-10-27: Validation experiment workflow (PR #10 merged, CI verified)

- Added `.github/workflows/validation-threshold.yml` to run training-only validation threshold selection with official UNSW-NB15 checksums.
- Workflow checks JSON consistency and recall floor, uploads `validation_threshold.json` as a time-limited Actions artifact (14 days), without overwriting official test metrics or committing model artifacts.
- PR #10 merged as commit `9107e116b8df228db66228f44c919ed89d95abf4`; PR CI **passed** (run `40366310170`).
- Main workflow automatically started on merge: [Actions run 40366465257](https://github.com/tbao4151/DA_CNTT/actions/runs/40366465257). Its final result is **not yet verified**. No selected threshold or improved False Positive performance claimed.

## 2026-10-27: Locked candidate for held-out test (PR pending)

- Verified Actions run 40366465257 **success**: validation-only threshold 0.55 on 35,069 rows (TP 22,861; FP 567; TN 10,633; FN 1,008; Attack Recall 0.95776949; F1 0.96669979). This is a temporary model trained on 140,272 training rows, **not** official test performance.
- Added a provenance-tracked immutable candidate report in `reports/validation_threshold_experiment.json`, locked threshold evaluator and regression tests, and `.github/workflows/locked-threshold-test.yml` to refit the model on all 175,341 training rows and compare 0.50/0.55 on the same official held-out test scores. Does not tune on official test or overwrite baseline metrics.
- At time of this commit, locked official test workflow **has not been run**. No claim of reduced false positives or Windows end-to-end verification.

## 2026-10-27: Official held-out comparison completed and verified

- PR #11 merged as commit `188283d099d2db694363606f1769b357d67763cd`; PR CI run `40372879416` and post-merge main CI `40373007026` passed.
- GitHub Actions official locked-test run `40373007093` **success**. It re-fitted Random Forest on all 175,341 official training rows, evaluated the validation-preselected threshold 0.55 and baseline 0.50 on the same 82,332 official test rows, and verified baseline confusion matrix consistency.
- Baseline 0.50: TP=44,467, FP=8,400, TN=28,600, FN=865; Attack Precision=0.84111071, Recall=0.98091856, F1=0.90565077.
- Locked 0.55: TP=44,125, FP=7,135, TN=29,865, FN=1,207; Attack Precision=0.86080765, Recall=0.97337422, F1=0.91363674.
- **Measured trade-off**: 1,265 fewer false positives (15.06% reduction relative to baseline), but 342 more false negatives and 0.7544 percentage points lower Attack Recall. This is official held-out test evidence for this fixed model/threshold, not proof of real-world production performance.
- Preserved measured result in `reports/official_locked_threshold_comparison.json` with Actions provenance. No further threshold tuning based on official test; SOC alert threshold remains unchanged. Windows end-to-end verification remains outstanding.

## 2026-10-27: Global AI explainability (PR #13 merged, PR CI verified)

- Added `src/siem_ai/explain.py` aggregating fitted RandomForest MDI importances over original UNSW input columns, including categorical one-hot dimensions. Rejects unexpected preprocessing mapping instead of silently mislabeling features.
- Added AI-tab visualization, feature table and safe CSV export, shown **only** if a trusted local model is loaded; no synthetic importance values in dashboard.
- Added synthetic-model unit tests for grouping, importance conservation, top-N ordering and invalid inputs; documentation `docs/EXPLAINABILITY.md` explicitly differentiates global impurity importance from per-alert causality.
- PR #13 merged as squash commit `65ccf2cc02a63fbbb5fcffb059d7b1e29367052b`. PR CI (syntax + tests) **passed: 55 tests** in run `40374925458`. Post-merge main CI run `40375071202` **passed**. No official UNSW importance ranking, Windows E2E result, or performance improvement claimed.

## 2026-10-27: Reproducible UNSW global explainability experiment (PR #14 merged, verified)

- Added `scripts/report_feature_importance.py` and `src/siem_ai/importance_report.py` to export **measured** global MDI from a trusted locally fitted Random Forest, grouped by original UNSW feature names, with SHA-256 of training CSV and joblib model.
- Added schema/integrity regression tests for feature coverage, sum of importance, provenance and rejection of feature mismatches.
- Added `.github/workflows/explainability.yml` to train on official UNSW training data, verify checksums, validate report, and upload a 14-day JSON artifact without pushing model binaries.
- Subsequently verified: PR #14 passed CI (58 tests, run 40377736217), merged as 3c088136e3bdb3ed3e19babfc8436d64b5ef4814; main CI 40377900386 passed. Research run 40377900643 also passed; see section below. Windows end-to-end remains unverified.

## 2026-10-27: Official global MDI experiment verified; permanent report PR #15 merged

- PR #14 merged as commit `3c088136e3bdb3ed3e19babfc8436d64b5ef4814`; PR CI passed 58 tests (run 40377736217). Post-merge main CI also passed (run 40377900386).
- GitHub Actions [run 40377900643](https://github.com/tbao4151/DA_CNTT/actions/runs/40377900643) **success**: official dataset checksums verified, full 175,341-row training RandomForest fitted; global MDI grouped from fitted model and validated for 42 original features / 194 encoded dimensions; feature importance sums to 1. No test label used for attribution.
- Measured top original features: `sttl` 10.31795%, `ct_state_ttl` 6.86247%, `rate` 5.30762%, `dload` 5.22735%, `sload` 4.49849%. Full measured report and workflow/commit provenance archived permanently in `reports/official_global_feature_importance.json`; PR #15 merged as `04f406907f13acba335a4376e86de1a39705538e` after CI run `40378797783` passed. No fabricated rankings.
- **Caveats:** Global MDI may favor high-cardinality predictors and is neither causal nor a per-alert explanation. A real-model Windows UI end-to-end test remains outstanding. No new model quality improvement claimed.

## 2026-10-27: Display archived locked-threshold evidence in SOC dashboard (PR #16 merged, CI verified)

- Added `src/siem_ai/official_comparison.py` to validate the archived official-test report (provenance, confusion totals, metrics and deltas) before display. No test-set threshold selection or model inference is performed here.
- Added a clearly labeled, model-independent comparison table and FP/FN trade-off to the AI dashboard; the alert queue's operational slider remains unchanged.
- Added regression tests against the archived report and intentionally corrupted copies, plus an offline Streamlit AppTest assertion; updated README.
- PR #16 passed CI (syntax + pytest/AppTest) in [run 40383061855](https://github.com/tbao4151/DA_CNTT/actions/runs/40383061855), merged via squash commit `50c572e052f384a6c7e2706e14ac821ca45a55d7`; post-merge main CI also passed in [run 40383279860](https://github.com/tbao4151/DA_CNTT/actions/runs/40383279860).
- No new official model experiment was run; results displayed are the previously verified archived comparison. Windows E2E with the official model remains unverified.

## 2026-10-27: SOC case portable JSON export (PR #17 merged, CI verified)

- Added a read-only, versioned UTF-8 JSON export for one selected SOC case, including metadata, stored flow feature snapshot and chronological audit events from a consistent SQLite read transaction.
- Ground-truth and UI-derived fields are excluded from exported flow evidence; report explicitly warns that local SQLite history is mutable and not signed forensic evidence.
- Added regression tests for case lifecycle, Unicode, legacy cases without events, invalid IDs and corrupt evidence, and confirmed that export does not change case records in the test.
- UI exposes a download button in SOC Investigation Workspace. No external upload or public deployment is performed.
- PR #17 merged as squash commit `2f809cd79b07798000c498be7ec433a48375b68a`. GitHub Actions CI passed on PR head `1c9210df2a239ff169a8d980ff6e36861133684d`: push run `40392002072` and pull_request run `40392025167` (syntax and pytest suite).
- Post-merge main CI **passed**: Actions run `40392183591` at squash commit `2f809cd79b07798000c498be7ec433a48375b68a`. Windows end-to-end with the official model remains unverified.


## 2026-10-27: Guard AI training against incomplete labels and derived-field leakage (PR #18 merged, CI verified)

- Tightened `fit_and_evaluate` input checks: both train and held-out test must have complete 0/1 labels; missing/invalid labels fail early instead of silently passing a `dropna()`-based subset check.
- Excluded dashboard-generated `AI_verdict`, `AI_attack_probability` and `flow_ref` alongside ground-truth columns from model training, preventing accidental target leakage when an already-enriched dataframe is reused.
- Added regression tests for NaN, non-binary and string labels in both splits, plus a synthetic-data test asserting that derived columns are absent from fitted features and inference still works.
- PR #18 merged as squash commit `4589f6d6168998f97662b8df72e9d2d892251709`. PR CI syntax + pytest passed (Actions run `40400840066`); post-merge main CI also passed (Actions run `40400969036`). No new official UNSW benchmark or improvement in measured AI scores is claimed. Windows end-to-end with official model remains unverified.

## 2026-10-27: Multi-dimensional historical Threat hunting (PR #19 merged, CI verified)

- Added pure, read-only filters for `proto`, `service`, `state`, optional AI Attack verdict and minimum AI Attack probability; category values use OR within one dimension, AND across dimensions. The filters preserve source data and row indexes.
- Updated Streamlit Threat hunting tab with new controls, count of filtered rows, and export of the filtered view. All filtering applies only to the currently loaded historical sample; it is not live monitoring or an official test benchmark.
- Added 10 regression tests covering combined filters, missing AI columns, null values, invalid probabilities, no-match results and non-mutation. Isolated tests passed locally. GitHub Actions PR CI (syntax + full pytest suite, including Streamlit AppTest) passed in run `40409230967`.
- PR #19 squash-merged into `main` at commit `be747503f13b853a4dccb3f41c76549b91595b18`; post-merge main CI also passed in run `40409401639`.
- No new UNSW-NB15 model experiment, performance improvement, deployment or model threshold change claimed. Windows end-to-end with official trained model remains **unverified**.

## 2026-10-27: Headless trained-model dashboard integration regression (PR #20 merged, CI verified)

- Added `tests/test_app_model_integration.py`: in an isolated temporary app copy, fit a real Random Forest on **synthetic** network flows, load the saved trusted joblib artifact through Streamlit AppTest, create a case from an AI-generated alert, then verify the SQLite case and portable JSON export.
- The test uses neither official UNSW test labels for fitting nor the real runtime database. It does **not** constitute an official benchmark or Windows browser end-to-end verification.
- Syntax was checked locally. GitHub Actions PR CI (full pytest suite including the new AppTest) **passed** in [run 40416651430](https://github.com/tbao4151/DA_CNTT/actions/runs/40416651430); PR #20 was squash-merged into `main` as `378edd77dac48060c6ed125e0693c7fbad012035`. Post-merge `main` CI also **passed** in [run 40416810079](https://github.com/tbao4151/DA_CNTT/actions/runs/40416810079). Windows browser E2E with the official UNSW-trained model remains unverified.

## 2026-10-27: Refresh cached model after local artifact replacement (merged, CI verified)

- Found that Streamlit `st.cache_resource` keyed the model only by its fixed joblib path. Re-training or replacing the model in place could leave an older in-memory model serving predictions while the local metrics file had changed.
- Added `model_artifact_signature` (mtime in nanoseconds and byte size) to the cache key; treat a directory at the artifact path as not trained. Added unit regression tests for replaced files, same-size rewrites with updated mtime, and missing artifacts. Documented the metadata limitation and restart workaround.
- PR #21 GitHub Actions CI (syntax + full pytest suite) **passed** in runs `40423296416` and `40423467964`; squash-merged into `main` as `bca1a9f992f48d84e7abcbda02c67c162689116e`. Post-merge main CI **passed** in run `40423483805`. No new official benchmark, threshold change, or Windows E2E validation claimed.

## 2026-10-27: Guard binary class probability mapping (PR #22 merged, PR CI verified)

- Updated `fit_and_evaluate` to reject a training split missing either Normal (0) or Attack (1), rather than creating a single-class artifact.
- Updated `predict_batch` to map Attack probability by the model's actual `classes_` ordering and reject incompatible class labels, malformed probability shapes and non-finite/out-of-range scores.
- Added regression cases for reversed class order, missing/wrong classes, invalid scores, and single-class training. These tests use synthetic fixtures, not the official UNSW benchmark.
- PR #22 passed GitHub Actions PR CI (syntax and pytest) in run `40429640323`; squash-merged into `main` as commit `48788f9281110eb33267011caae1f0313ed47708`. Post-merge main CI also passed in run `40429747524` (syntax and pytest). No benchmark, threshold, or Windows E2E result is claimed.

## 2026-10-27: Official-model Streamlit/SOC integration smoke (PR #23 merged, verified)

- Added an **opt-in** AppTest using a model trained on the official 175,341-row UNSW training split to infer on the first 2,500 held-out test flows. It checks the UI alert count against direct model inference, creates one SOC case, and validates the exported JSON evidence and audit event.
- Dedicated workflow verifies the official dataset checksums, trains a trusted model and runs the AppTest in a temporary isolated application/SQLite directory with read-only repository permissions. The model is not published, and benchmark reports are not changed.
- PR #23 squash-merged into `main` as commit `71b9d50173f68749f2508295230b39cbc7feb4c2`. PR CI passed in Actions run `40435134602`; post-merge main CI passed in run `40435254835`.
- Dedicated official-model smoke run `40435254982` **passed**: checksum verification, official training, and **1 headless AppTest passed** (3.54 seconds for test). Training logged Attack Recall 0.98091856 and Attack F1 0.90565077, consistent with the archived baseline. This is **not** a new independent benchmark or Windows/browser E2E certification. Ordinary fast CI skips this expensive opt-in test.

## 2026-10-27: Official-model smoke cross-platform verification (PR pending)

- Extended `.github/workflows/official-model-smoke.yml` with an Ubuntu/Windows matrix and a narrowly scoped pull-request trigger so the same official UNSW-NB15 checksum verification, full-train Random Forest fit, and isolated Streamlit AppTest run on both operating systems.
- Updated the AppTest docstring and README to distinguish headless Windows CI from a real Windows browser end-to-end test.
- **At time of this commit, Windows workflow results are not yet verified.** The prior Linux-only official-model smoke run 40435254982 passed; no new AI benchmark or Windows browser certification is claimed.

## 2026-10-27: Windows and Ubuntu official-model CI verified (PR #24 merged)

- PR #24 [merged](https://github.com/tbao4151/DA_CNTT/pull/24) as squash commit `bf3e0bde03624ce5a199b943f63b9383bd513f64`.
- PR quality gate `40440966632` and cross-platform official-model smoke `40440966634` **passed** on both Windows and Ubuntu. Post-merge main quality gate `40441303983` and cross-platform official-model smoke `40441303872` also **passed**.
- Each official-model smoke job verifies official UNSW-NB15 checksums, fits the full training model, then runs isolated Streamlit AppTest (AI prediction → alert → SQLite case → exported JSON). This is the first verified **headless Windows CI** run using the official model.
- Still **not** a Windows **browser-based end-to-end** test; no new independent benchmark, model change, deployment, or production SIEM capability claimed.

## 2026-10-27: Add opt-in Windows browser E2E for official model (verification pending)

- Added `tests/test_browser_soc_e2e.py`: Playwright Chromium drives a real Windows browser against a private local Streamlit process. The model is freshly fitted from official UNSW-NB15 training data; 2,500 official test rows are used **only for inference**. Browser actions create one SOC case and download its JSON, which is checked for attack verdict, evidence sanitization and audit event.
- Extended `.github/workflows/official-model-smoke.yml`: existing official-model AppTest still runs on Ubuntu/Windows; Windows also installs Chromium/Playwright and runs the opt-in browser test. Ordinary `pytest` skips it.
- Browser and database run in a temporary local app copy; no production capture, public deployment or benchmark/threshold update.
- **At commit time:** new browser test passed Python syntax compilation locally; **Windows GitHub Actions browser E2E has not yet been confirmed**. Record workflow outcome before marking the milestone complete.

## 2026-10-27: Windows Chromium official-model browser E2E verified (PR #25 merged)

- PR #25 squash-merged into `main` at `02fac2d820cf6dcafff45737bcc7164319f6d6e1`.
- PR quality gate **passed** in [Actions 40442408126](https://github.com/tbao4151/DA_CNTT/actions/runs/40442408126). PR official-model workflow **passed** in [Actions 40442408258](https://github.com/tbao4151/DA_CNTT/actions/runs/40442408258), including the Windows Chromium browser step and Windows/Ubuntu headless AppTest jobs.
- The browser E2E used the model fitted from official UNSW train, navigated to Alert Queue, created a case through the UI, downloaded case JSON from the SOC tab, and validated evidence and audit trail in a private temporary application. It did not tune on the official test split, alter benchmark scores or perform external deployment.
- Remaining scope: user-machine manual E2E and edge-case browser coverage for CSV upload, filtering and SOC state transitions. GitHub Actions passing does not certify production security.

## 2026-10-27: Extend real-browser SOC case lifecycle test (verification pending)

- Expanded opt-in `tests/test_browser_soc_e2e.py` (Windows Chromium, official UNSW-trained model): after first case JSON export, use the SOC UI to change `New` → `Investigating`, save an analyst note, confirm SQLite persistence, reload the browser, and export JSON again.
- Assertions now check persisted analyst note, ordered audit history (`New`, `Investigating`), prior state, and preservation of the original flow snapshot, flow reference and model verdict.
- Changes are scoped to a temporary localhost app and SQLite copy; official model training, benchmark, dataset, alert threshold and production deployments are unchanged.
- **At commit time:** CI result for this expanded browser test is pending. Do not mark the extension as verified until GitHub Actions succeeds.

## 2026-10-27: Windows Chromium SOC state transition verified (PR #26 merged)

- PR #26 merged into `main` as squash commit `27fb21b6d21aeec94a1f603fd61fe4cd9dcce122`.
- [CI quality gates 40443155406](https://github.com/tbao4151/DA_CNTT/actions/runs/40443155406) **passed** (syntax and pytest). [Official-model workflow 40443155381](https://github.com/tbao4151/DA_CNTT/actions/runs/40443155381) **passed** on Windows and Ubuntu; the Windows Chromium browser step also passed.
- The browser test confirms a `New` → `Investigating` state transition and analyst note saved through Streamlit, persistence in isolated SQLite after browser reload, updated downloaded JSON, correct audit order and unchanged original evidence/verdict. This is regression evidence for one SOC workflow, not exhaustive UI security testing.
- No model, dataset, threshold, benchmark or deployment changes. Remaining E2E coverage: CSV import/error handling, threat hunting filters and manual Windows demonstration.

## 2026-10-27: Investigate intermittent Windows browser SOC selectbox failure (PR pending)

- The post-merge official-model smoke on `main` at [Actions 40443531393](https://github.com/tbao4151/DA_CNTT/actions/runs/40443531393) **failed** on Windows Playwright: `get_by_role('option', name='Investigating')` timed out after 90 seconds. Windows training/headless AppTest and Ubuntu workflow still passed; the equivalent E2E test had passed on PR #26 (40443155381). This is a browser-test reliability defect; no AI metric regression was observed.
- Changed the state-selection step in `tests/test_browser_soc_e2e.py` to keyboard navigation (`Home`, `ArrowDown`, `Enter`) on the focused selectbox instead of querying a transient popup option. Existing SQLite and downloaded-JSON assertions remain unchanged.
- **Verification pending:** do not claim the browser test is stable or the fix successful until subsequent PR CI and post-merge CI pass. CSV-upload browser coverage remains to be done. No model/threshold changes.

## 2026-10-27: Windows SOC selectbox regression fix verified on PR #27

- PR [#27](https://github.com/tbao4151/DA_CNTT/pull/27) squash-merged into `main` as `77f67a031a2d173104a92e60fef700a00aeb064e`.
- [CI quality gates 40444171096](https://github.com/tbao4151/DA_CNTT/actions/runs/40444171096) **passed** and [official-model smoke 40444171121](https://github.com/tbao4151/DA_CNTT/actions/runs/40444171121) **passed** on Ubuntu and Windows, including Chromium browser E2E after switching to keyboard-based selection.
- Prior failure at main Actions 40443531393 is retained in the history; a single green rerun does not prove zero flakiness. Post-merge `main` workflow result needs separate verification.
- No AI pipeline, UNSW dataset, thresholds, benchmark, runtime database or application deployment changed. CSV-upload/Threat Hunting browser coverage remains pending.

## 2026-10-27: Post-merge Windows Chromium regression verification

- `main` quality gate [40444580183](https://github.com/tbao4151/DA_CNTT/actions/runs/40444580183) **passed**; official-model workflow [40444580258](https://github.com/tbao4151/DA_CNTT/actions/runs/40444580258) **passed** after PR #27 merge on both Windows and Ubuntu, including the expanded browser E2E SOC state transition.
- This confirms the corrected keyboard interaction at the PR and main CI checkpoints, not a guarantee against future intermittent failures; prior failed main run 40443531393 remains documented.
- Next: browser smoke for CSV upload (valid/invalid) and Threat Hunting filters, plus local Windows manual demonstration. No new benchmark or model change.

## 2026-10-27: Validate original CSV headers before dashboard import (PR verification pending)

- Found a correctness gap: pandas silently renames duplicate CSV header fields (e.g. `proto,proto` becomes `proto,proto.1`), so the existing DataFrame duplicate-column check did not reject ambiguous uploaded files.
- Added `src/siem_ai/upload.py` and integrated it into the Streamlit CSV upload path. The parser checks original UTF-8/UTF-8-BOM headers, rejects duplicate/blank columns and empty/oversized files, and bounds the preview to 10,000 rows; existing `validate_flows` still checks required UNSW network features. No change to the official dataset loader, training pipeline, model, thresholds or SOC database.
- Added `tests/test_upload.py` covering valid BOM input, duplicate headers, invalid/blank headers, invalid encoding, file-size and preview-row limits. **Local isolated result:** 12 tests passed with pandas 2.2.3 and pytest 9.0.2. Full repository CI and Windows browser coverage for uploaded files are **not yet verified** at commit time.
- Remaining: confirm PR CI, then add browser-level valid/invalid CSV upload and Threat Hunting filtering coverage. No new UNSW benchmark, attack-detection improvement or production-security guarantee claimed.

## 2026-10-27: CSV upload header validation verified (PR #28 merged)

- PR [#28](https://github.com/tbao4151/DA_CNTT/pull/28) squash-merged into `main` as `ef0e284f3cca163d239bb0445e3ae14893f7537e`.
- [PR quality gates 40447168973](https://github.com/tbao4151/DA_CNTT/actions/runs/40447168973) **passed** (syntax and full pytest suite); [post-merge main quality gates 40447262148](https://github.com/tbao4151/DA_CNTT/actions/runs/40447262148) **passed**. Isolated local `tests/test_upload.py`: 12 passed.
- The raw-header parser now rejects duplicate/blank CSV headers, oversized/empty uploads and invalid UTF-8 before displaying uploaded flows. The official model, benchmark, threshold policy and stored SOC cases are unchanged.
- Remaining: browser-level CSV upload/Threat Hunting coverage and a manual Windows demo. This validation does not establish production-grade CSV parser security.


## 2026-10-27: Local reproducibility evidence checker (PR verification pending)

- Added scripts/verify_local_run.py for **opt-in** verification after a user trains a trusted UNSW-NB15 model locally. It checks pinned SHA-256 of both official partitions, expected train/test sizes, model feature order, recomputed confusion matrix/classification report/average precision and dashboard-versus-model threshold disagreements. It writes a local-only JSON manifest with UTC time, software versions, Git SHA and artifact hashes to artifacts/local_verification.json (gitignored).
- Added tests/test_verify_local_run.py with four synthetic-only regression cases: successful report, tampered test data, tampered confusion matrix and leaked ground-truth feature. **Isolated local test run:** 4 passed (pytest with a minimal local model adapter). Full repository CI is **pending** and must be verified before claiming this PR stable.
- Added docs/LOCAL_EXPERIMENT.md and README instructions for Windows setup, local training, SOC demonstration, screenshots and honest evidence collection.
- **Not performed:** no actual Windows user-machine execution, no new official UNSW benchmark, no model tuning or threshold change, no claim that a student performed the demonstration. CI results, once available, do not substitute for a human local run.
- Next: verify PR quality gates, then have the group perform a Windows local run and archive screenshots/JSON before revising the advisor progress report.


## 2026-10-27: Local verification evidence tool merged and CI verified (PR #29)

- [PR #29](https://github.com/tbao4151/DA_CNTT/pull/29) squash-merged into main at commit 036a2d248d0dfae822bcc969c5229a11cc97a9d8.
- [PR quality gates 40452298446](https://github.com/tbao4151/DA_CNTT/actions/runs/40452298446) **passed**; [post-merge main quality gates 40452375343](https://github.com/tbao4151/DA_CNTT/actions/runs/40452375343) **passed** (syntax and full pytest suite). Four new synthetic verifier tests also passed in isolated local testing.
- The new verification command can generate artifacts/local_verification.json **only after the user has trained a trusted model and run the command**; this file is not committed. Neither GitHub CI nor development of the script proves the group ran the project on its own Windows machine.
- Next: group-run Windows training, independent examination of FP/FN and screenshots/JSON for the advisor; extend browser upload/filter test coverage. No new official benchmark, model change, production deployment or manual Windows verification claimed.

## 2026-10-27: Reject ragged CSV rows before AI inference (PR #30 merged, CI verified)

- Found an input-integrity gap: pandas may silently reinterpret a leading data field as a DataFrame index when a CSV row has more fields than its header, shifting network features without an obvious parse error.
- Updated `src/siem_ai/upload.py` to validate the raw CSV header **and field counts of each preview row** using strict Python CSV parsing before passing content to pandas. Quoted commas remain valid; missing/extra fields and unterminated quoted fields are rejected. Validation is bounded to the requested preview (max 10,000 rows) and 15 MiB upload size; rows outside the preview are not inspected.
- Added 5 new parameterized/regression test cases to `tests/test_upload.py` (two ragged-row cases, quoted comma, unclosed quote, preview boundary). Existing upload tests remain.
- Ran isolated upload regression suite in the automation's Linux sandbox: **17 passed**, Python syntax compilation passed. This is not a Windows manual test and does not verify browser upload behavior.
- PR #30 was squash-merged into `main` as `eb83188706ce9714e6531921560b712970efd05c`. PR quality gate [40458049122](https://github.com/tbao4151/DA_CNTT/actions/runs/40458049122) **passed** (full pytest suite and syntax check); post-merge main quality gate [40458162423](https://github.com/tbao4151/DA_CNTT/actions/runs/40458162423) **passed**. No AI model, dataset, official benchmark, SOC database, deployment or manual Windows verification changes.

## 2026-10-27: Extend Windows Chromium smoke to CSV upload and Threat Hunting (verification pending)

- Extended the existing opt-in Windows Playwright smoke after the SOC lifecycle check. The browser uploads eight official-test feature rows without labels, verifies the dashboard renders them, applies a protocol filter expected to return four rows, and uploads a malformed duplicate-header CSV that must be rejected before AI inference.
- The test continues to use a private localhost Streamlit app and temporary SQLite database; the official test partition is used only for inference, not training or threshold selection. No changes to the model, benchmark, alert policy, real SOC cases or public deployment.
- **At commit time:** this new browser path has not yet been verified by Windows GitHub Actions. A successful run must be recorded before treating it as complete. The user's own Windows machine has still not been tested.

- Initial PR browser attempt [Actions 40463809314](https://github.com/tbao4151/DA_CNTT/actions/runs/40463809314) **failed** on Windows: Playwright `get_by_role("radio").check()` timed out because the styled input was covered by the visible Streamlit radio label. Ubuntu official-model AppTest and the PR quality gate passed. Updated the browser test to click the visible sidebar label; the new Windows run is pending, not yet confirmed.

## 2026-10-27: Windows CSV upload and Threat Hunting browser smoke verified on PR #31

- [PR #31](https://github.com/tbao4151/DA_CNTT/pull/31) quality gates [40464307180](https://github.com/tbao4151/DA_CNTT/actions/runs/40464307180) **passed**; official-model smoke [40464307137](https://github.com/tbao4151/DA_CNTT/actions/runs/40464307137) **passed** on both Ubuntu (AppTest) and Windows (AppTest + Chromium browser E2E).
- The Windows Chromium test verified an eight-row uploaded UNSW feature CSV (without ground-truth labels), a protocol Threat Hunting filter narrowing to 4/8 rows, and duplicate CSV header rejection. It also retained the existing AI alert -> SOC case -> state update -> JSON audit checks.
- The initial browser run [40463809314](https://github.com/tbao4151/DA_CNTT/actions/runs/40463809314) failed because Playwright clicked a radio input obscured by Streamlit's styled label. Clicking the visible sidebar label fixed the interaction in the later successful run; intermittent UI issues remain possible.
- This is a CI-hosted Windows browser regression test, **not** evidence of manual operation on a student's Windows PC. It is not a new benchmark, does not assess every upload edge case, and does not alter the official model, threshold, data or local SOC records.

## 2026-10-27: PR #31 merged; post-merge Windows browser regression confirmed

- PR [#31](https://github.com/tbao4151/DA_CNTT/pull/31) squash-merged into `main` at `fc27f4b96c907c1cd7a0a03f24d03d81a2aede71`.
- Final PR checks [quality gates 40464731858](https://github.com/tbao4151/DA_CNTT/actions/runs/40464731858) and [official-model smoke 40464732093](https://github.com/tbao4151/DA_CNTT/actions/runs/40464732093) both **passed**. Post-merge `main` checks [quality gates 40465141845](https://github.com/tbao4151/DA_CNTT/actions/runs/40465141845) and [official-model smoke 40465141765](https://github.com/tbao4151/DA_CNTT/actions/runs/40465141765) also **passed**, including Windows Chromium and Ubuntu/Windows AppTest.
- Browser coverage now includes valid/invalid CSV upload and protocol Threat Hunting filtering in addition to SOC case lifecycle. The earlier failed radio-input interaction remains documented; no manual Windows user-machine run or production-security certification is claimed.

## 2026-10-27: Grouped local FP/FN evidence for advisor review (PR verification pending)

- Added `src/siem_ai/error_analysis.py` to aggregate **held-out test** confusion-matrix counts by attack category and network protocol, including per-group Attack Recall and Normal false-positive rate where defined. The helper exports no individual flow rows; missing categories are represented explicitly. Group totals are reconciled against the already-verified confusion matrix.
- Integrated summaries into `scripts/verify_local_run.py` under `error_breakdown`, generated **only after** trusted model/dataset/metrics verification. Updated `docs/LOCAL_EXPERIMENT.md` and `ROADMAP.md` so students can examine actual FP/FN patterns after training on their own Windows computer.
- Added six synthetic-only unit tests for grouped TP/FP/TN/FN, missing groups and invalid inputs, plus integration assertions for local verifier output. **Isolated Linux sandbox:** six helper tests passed and helper module compiled. Full repository CI and actual Windows user-machine run are **not yet verified** at commit time.
- This is descriptive test-set error analysis, **not** a new model, independent replication, threshold optimization, production benchmark or evidence that the group ran anything on its own PC. Never select new thresholds/features from official test breakdowns.

## 2026-10-27: Local FP/FN grouped analysis merged and CI verified (PR #32)

- [PR #32](https://github.com/tbao4151/DA_CNTT/pull/32) squash-merged into `main` at commit `a4fb7e3118ba6711e3be96a99c64f9a6a70ee8a3`.
- [PR quality gates 40470228083](https://github.com/tbao4151/DA_CNTT/actions/runs/40470228083) **passed**; [post-merge main quality gates 40470349268](https://github.com/tbao4151/DA_CNTT/actions/runs/40470349268) **passed** (repository syntax check and pytest suite). The six synthetic helper tests also passed in an isolated Linux sandbox.
- The opt-in `scripts/verify_local_run.py` now produces grouped TP/FP/TN/FN summaries only after existing model/dataset/metrics checks. This change does not create a new official UNSW benchmark, tune on held-out test, expose raw flows or establish that students performed local Windows training. No SOC DB, deployment, AI model or threshold changes.
- Next: group members must train on their own Windows PC, run the verifier, interpret grouped FP/FN counts with denominators, capture real screenshots and revise the advisor progress report with verified local evidence.

## 2026-10-27: Reject NUL-byte CSV uploads before AI inference (PR verification pending)

- Found a parser inconsistency: Python `csv.reader` preserves NUL characters but pandas' C CSV parser can silently truncate the same header or field at a NUL byte. This could alter a network-flow feature without a visible parsing error.
- Updated `src/siem_ai/upload.py` to reject any NUL byte in a bounded (max 15 MiB) uploaded CSV, including content after the selected preview rows. This affects only user-uploaded CSV; official UNSW data loading, model, benchmark, threshold and SOC case storage remain unchanged.
- Added three parameterized regression cases for NUL in a header, a preview-row value, and a value after the preview boundary. **Isolated Linux sandbox:** 20 upload tests passed; syntax compilation passed. Full GitHub Actions PR checks and Windows browser verification are pending at commit time.
- No new model performance or local Windows student experiment is claimed. Next: verify CI, merge if green, then collect manual Windows training/demo evidence for the advisor.

## 2026-10-27: NUL-byte CSV upload guard verified and merged (PR #33)

- [PR #33](https://github.com/tbao4151/DA_CNTT/pull/33) squash-merged into `main` at commit `865b86ccada7ab01066683f5869edfcf13ea568f`.
- [PR quality gates run 40477056751](https://github.com/tbao4151/DA_CNTT/actions/runs/40477056751) **passed** (syntax and full pytest suite). In an isolated Linux sandbox, `tests/test_upload.py` passed **20/20** cases, including three new NUL-byte cases.
- The guard rejects NUL in any uploaded CSV byte to avoid pandas silently truncating flow features. No model, official UNSW benchmark, alert threshold, SOC database, or deployment change. No manual Windows student-machine run claimed.
- [Post-merge main quality gates 40477206216](https://github.com/tbao4151/DA_CNTT/actions/runs/40477206216) **passed** on the squash-merge commit (syntax and full pytest suite). Next: student-run Windows training, artifact verification and SIEM/SOC screenshots for the advisor.

## 2026-10-27: Align CSV preview validation with pandas blank-line handling (CI pending)

- Identified an import consistency bug: `csv.reader` yields an empty list for physically blank lines, while `pandas.read_csv` skips those lines. The strict validator previously rejected otherwise valid uploads containing blank lines between flows.
- Changed `src/siem_ai/upload.py` to skip only truly empty CSV records, counting logical data rows up to the preview limit. Quoted empty fields are still validated and rejected if they have the wrong number of columns; rows beyond the logical preview remain outside the validation scope.
- Added four regression cases: valid blank line, malformed row after a blank line, quoted empty-field row, and a malformed row after the logical preview. Updated README to document the behavior.
- **At commit time:** CI for this branch has not been checked. No model, official UNSW dataset, benchmark, alert threshold, SOC database or public deployment changes. This is not evidence of a manual Windows experiment by the students.

## 2026-10-27: CSV blank-line preview fix verified and merged (PR #34)

- [PR #34](https://github.com/tbao4151/DA_CNTT/pull/34) squash-merged into `main` as `637227ab830db342e54f4c78bed98f42bbd11fe9`.
- [PR quality gates 40484898887](https://github.com/tbao4151/DA_CNTT/actions/runs/40484898887) **passed** (repository syntax check and full pytest suite); the two preceding branch push checks also passed. Four isolated representative CSV parsing cases passed in a Linux sandbox, but that smoke is not a full repository run.
- The CSV preview validator now ignores physically blank lines when counting preview records, matching pandas' default behavior, while continuing to reject malformed rows and quoted empty-field records with incorrect field counts. No model, official UNSW benchmark, threshold, SOC data, deployment, or manual Windows student experiment changed.
- Post-merge main CI has not yet been verified at the time of this progress entry. Next priority remains student-operated Windows training, verifier output, SOC demo and genuine screenshots for advisor review.

- **Post-merge main quality gate [40485028645](https://github.com/tbao4151/DA_CNTT/actions/runs/40485028645) passed** on squash commit `637227ab830db342e54f4c78bed98f42bbd11fe9` (syntax check and full pytest suite). This verifies CI on GitHub, not a manual Windows run.

## 2026-10-27: Reject altered official UNSW CSV before training (PR/CI pending)

- Found a reproducibility gap: `scripts/train_siem.py` previously read whichever CSV files existed under the official train/test names, without checking their pinned SHA-256. A modified local copy could be trained and its metrics presented as an official UNSW-NB15 benchmark.
- Added `load_verified_split` to hash both CSVs against the fixed checksums in `scripts/download_unsw_nb15.py` and validate row counts before `fit_and_evaluate` or `persist_model`. A missing or modified file fails closed; it does not overwrite an existing model/metrics artifact. Local metadata.json is not trusted as the checksum source.
- Added six synthetic-only regression cases covering valid inputs, altered train/test, missing train/test, and row-count mismatch. Updated README and ROADMAP. CI status and independent local test execution are **not yet verified at commit time**.
- This is a training-input integrity guard, not a new AI benchmark or evidence that students ran the project on their Windows machine. No model hyperparameters, test labels, alert thresholds, SOC DB, or deployment changed.

## 2026-10-27: Official training split checksum gate merged (PR #35)

- [PR #35](https://github.com/tbao4151/DA_CNTT/pull/35) was squash-merged into `main` at `d0f1fbd81f26c3590af3eba8ebcd5a6af4f6081c`.
- [PR quality gates 40492434317](https://github.com/tbao4151/DA_CNTT/actions/runs/40492434317) **passed**, including repository Python syntax check and full pytest suite with six new synthetic split-integrity cases. Post-merge `main` CI is pending verification at the time of this entry.
- `scripts/train_siem.py` now refuses altered or missing official train/test CSVs before fitting or saving a model, and checks their row counts against pinned constants. It does not trust local metadata.json. No model or benchmark numbers changed; no manual Windows student experiment claimed.

- **Post-merge main quality gates [40492595694](https://github.com/tbao4151/DA_CNTT/actions/runs/40492595694) passed** on squash commit `d0f1fbd81f26c3590af3eba8ebcd5a6af4f6081c` (Python syntax and full repository pytest). This is CI-hosted Linux verification, not a student-run Windows training experiment.

## 2026-10-27: Validate downloaded UNSW CSV before promotion (PR/CI pending)

- Found that `scripts/download_unsw_nb15.py` previously renamed a newly downloaded `.part` file to the official CSV filename **before** verifying SHA-256. A corrupted download could therefore leave an invalid official-named file, blocking subsequent setup and confusing local users.
- Changed the downloader to stream-hash the temporary download and require the pinned official SHA-256 before renaming it; failures remove only the temporary `.part` file. Existing CSVs are still verified but **never silently overwritten or deleted**.
- Added four synthetic, offline pytest cases: valid promotion, tampered download rejection, interrupted transfer cleanup and preservation of a pre-existing invalid CSV. Updated README and ROADMAP. **CI is pending at commit time**; no claim of Windows student-machine execution.
- No change to model, official dataset bytes/checksums, benchmark metrics, alert threshold, SOC database or public deployment. Next: verify PR CI and merge if green; then student-run Windows training and evidence collection.

## 2026-10-27: Verified downloader integrity fix merged (PR #36)

- [PR #36](https://github.com/tbao4151/DA_CNTT/pull/36) squash-merged into `main` at commit `ed6b15e377c8387253efb51c8849894577d6c563`.
- [PR quality gates run 40500609154](https://github.com/tbao4151/DA_CNTT/actions/runs/40500609154) **passed**, including Python syntax and full repository pytest with four new synthetic downloader cases. [Additional branch run 40500641271](https://github.com/tbao4151/DA_CNTT/actions/runs/40500641271) **passed**.
- [Post-merge main quality gates run 40500764818](https://github.com/tbao4151/DA_CNTT/actions/runs/40500764818) **passed** on the squash-merge commit.
- Newly downloaded UNSW CSVs are verified against pinned SHA-256 while still named `.part`, before promotion to official filename. Interrupted or corrupted downloads cannot create an official-named CSV through the downloader. Existing files remain untouched on checksum failure.
- This is GitHub-hosted automated testing, not evidence that the students ran the project on their Windows PC. No new model training, benchmark, alert-threshold change, SOC DB mutation or deployment.
- Next: manually run `scripts/download_unsw_nb15.py`, `scripts/train_siem.py` and `scripts/verify_local_run.py` on a student's Windows computer; capture genuine evidence and analyze false positives/false negatives for the advisor.

## 2026-10-27: Validate UTF-8 across the entire bounded CSV upload (PR CI pending)

- Identified a preview-boundary gap: the strict CSV reader and `pandas.read_csv(nrows=limit)` only decode the selected preview rows, so an invalid UTF-8 byte sequence after the preview could be silently accepted despite the stated UTF-8-only upload policy.
- Added a streaming strict UTF-8 decoder across the complete **already size-bounded** (maximum 15 MiB) upload, before CSV preview parsing. UTF-8 BOM remains supported. Structural field-count checks still apply **only** to the preview; no claim of full-file CSV structural validation.
- Added five synthetic regression cases: invalid UTF-8 tail, two truncated multibyte tails, valid UTF-8 tail, and invalid continuation crossing the 64-KiB decoding boundary. The five focused cases passed in an isolated Linux sandbox with pandas 2.2.3 and pytest 9.0.2; Python syntax compilation also passed. Full repository CI and Windows browser tests are **not yet verified at commit time**.
- No model retraining, official dataset/benchmark modification, threshold tuning, SOC database change, deployment, or student-operated Windows experiment. Next: check PR quality gates and merge only if green; local Windows training and genuine evidence collection remain the highest-priority outstanding task.

## 2026-10-27: Whole-file UTF-8 upload guard merged and PR CI verified (PR #37)

- [PR #37](https://github.com/tbao4151/DA_CNTT/pull/37) squash-merged into `main` at `0943dbbdebdbc6ca67e52e79f7dc6949bba7410a`.
- [PR quality gates run 40507892802](https://github.com/tbao4151/DA_CNTT/actions/runs/40507892802) **passed**, including Python syntax and repository pytest. An isolated Linux sandbox also passed 29/29 upload regression cases using a reconstructed test copy; this is not a complete repository run.
- The bounded CSV uploader now rejects invalid UTF-8 anywhere in the uploaded bytes, even after the selected preview. The full-file encoding check does **not** extend structural row validation beyond the preview.
- Post-merge `main` CI is not independently confirmed at the time of this entry. No student-operated Windows local experiment, model retraining, benchmark change, SOC data change, or deployment is claimed. Next priority: real Windows training, verification JSON, FP/FN analysis, and manual SIEM/SOC screenshots for advisor review.

## 2026-10-27: Check CSV structure beyond the selected preview (PR CI pending)

- Found an import integrity gap: the upload parser checked CSV field counts and balanced quotes only for the first `limit` logical records. An otherwise UTF-8-valid malformed tail was accepted, despite the entire upload already being capped at 15 MiB.
- Changed `src/siem_ai/upload.py` to validate the CSV header and **every logical data record** with `csv.reader(strict=True)`, while `pandas.read_csv(nrows=limit)` still loads at most 10,000 rows into the dashboard. Physically blank lines remain skipped; quoted commas and multiline quoted fields remain valid. The whole-file UTF-8 and NUL checks are unchanged.
- Updated upload regression tests for extra/missing fields after preview, unclosed quote after preview, a valid multiline quoted tail, malformed row beyond 10,000 preview records, and blank-line boundaries. Updated README and ROADMAP.
- **At branch commit time:** GitHub CI and local pytest are not yet verified. No claim of AI model improvement, UNSW benchmark change, SOC DB mutation, deployment or student-operated Windows experiment. Next: inspect PR CI and merge only if green; collect genuine Windows training/demo evidence separately.

## 2026-10-27: Full-file CSV row validation merged and PR CI passed (PR #38)

- [PR #38](https://github.com/tbao4151/DA_CNTT/pull/38) squash-merged into `main` as commit `51c8ad39d995964b94f37dad1dd331c833a05710`.
- [PR quality gates run 40516373608](https://github.com/tbao4151/DA_CNTT/actions/runs/40516373608) **passed**: Python syntax and full repository pytest (`155 passed, 2 skipped, 2 warnings`). The two pandas-related warnings are not test failures; one originates in `tests/test_model.py:46` and should be addressed separately. Post-merge `main` CI has not yet been independently verified at the time of this entry.
- Uploaded CSV structure is now validated across every row within the 15 MiB size limit, including rows outside the 10,000-row display preview. The parser rejects extra/missing fields and unclosed quotes in the tail, while supporting blank lines and quoted multiline fields. The UI still reads at most the selected preview count.
- No official dataset, model, benchmark, threshold, SOC case database, public deployment or student-operated Windows experiment changed. Next: check post-merge CI, profile large-upload performance, and obtain genuine Windows local training/demo evidence.

## 2026-10-27: Stage training artifacts before replacing existing files (PR/CI pending)

- Found a local reliability gap: `persist_model` wrote joblib directly to the existing `unsw_binary_rf.joblib`, so an interrupted serialization could truncate the last usable model before the new metrics were written.
- Changed `src/siem_ai/model.py` to serialize model and metrics into a temporary directory on the destination filesystem, then replace their respective final paths only after **both** serializations succeed. Temporary staging files are cleaned on failure; existing model and metrics remain untouched on staging errors.
- Added three synthetic-only tests for successful output and cleanup, interrupted joblib serialization, and invalid metrics JSON. A small isolated Python smoke check of the staging logic passed, but **repository CI and Windows verification are not yet confirmed at this entry**.
- Limitation: the two final `os.replace` operations are **not an atomic pair**. A crash or I/O error between replacements can still leave model/metrics inconsistent; the existing local verifier is required before using the pair as research evidence. No official UNSW training, benchmark, SOC data, threshold, or deployment was changed.
- Next: verify PR CI and merge only if green; student-run Windows training, verifier output and genuine SOC demo screenshots remain outstanding.

## 2026-10-27: Staged local artifact persistence merged and CI verified (PR #39)

- [PR #39](https://github.com/tbao4151/DA_CNTT/pull/39) squash-merged into `main` at commit `3774212cea0dd862d47d64fa74761667cc3ea49f`.
- [PR quality gates 40525521073](https://github.com/tbao4151/DA_CNTT/actions/runs/40525521073) **passed** (Python syntax + full pytest: 158 passed, 2 skipped, 2 warnings). [Post-merge main quality gates 40525727397](https://github.com/tbao4151/DA_CNTT/actions/runs/40525727397) **passed** on the merge commit.
- Model and metrics are now fully staged before replacing existing local artifact files, so serialization errors (including a partially written staged joblib file or non-JSON-serializable metrics) preserve the last existing artifacts. Three new synthetic regression tests cover success, interrupted dump and metrics serialization failure. An isolated staging smoke also passed.
- **Remaining risk:** replacing two final files is not an atomic pair; a crash between `os.replace` calls may still leave a mismatched model/metrics pair. Re-run training and `scripts/verify_local_run.py` after interrupted writes. No official benchmark/model hyperparameter change, SOC DB mutation, deployment or student-operated Windows experiment claimed.
- Next: collect real Windows training/verifier output and SOC UI screenshots; consider an explicit artifact manifest if stronger pair-consistency guarantees are required.

## 2026-10-27: GitHub Actions Python 3.12.9 alignment (PR #40 merged; PR CI verified)

- Replaced Python 3.11 with an exact Python **3.12.9** `setup-python` pin in all eight GitHub Actions workflows, including official-model smoke on Ubuntu and Windows. Pinned runners to **Ubuntu 24.04 / Windows 2022** because Python 3.12.9 could not be found by setup-python on the newer Ubuntu 26.04 runner. The two dataset fetch workflows no longer use runner-default `python3`.
- Added a runtime Python patch-version assertion to each workflow; updated README and local Windows instructions to `py -3.12` / CMD-friendly `.venv\Scripts\python.exe`. Data-fetch and baseline-benchmark workflows now run on **manual dispatch only** to avoid unexpected GitHub writes when their runtime definitions change.
- [PR #40](https://github.com/tbao4151/DA_CNTT/pull/40) squash-merged into `main` at `a8432813b1378a7f537636fa40ba6a232dffa9f8` after [PR quality gates #40534775708](https://github.com/tbao4151/DA_CNTT/actions/runs/40534775708) **passed** (`158 passed, 2 skipped, 2 warnings`) and [official-model Windows/Ubuntu smoke #40534775619](https://github.com/tbao4151/DA_CNTT/actions/runs/40534775619) **passed**, including Windows Chromium SOC E2E with official model.
- Post-merge [main CI run 40535478537](https://github.com/tbao4151/DA_CNTT/actions/runs/40535478537) **passed** on merge commit `a8432813b1378a7f537636fa40ba6a232dffa9f8`; post-merge research and Windows official-model workflow outcomes should be checked separately. Historical UNSW-NB15 baseline metrics were measured with previous dependencies and are not claimed identical with new runtime; no user-operated local Windows training or screenshots claimed.

## 2026-10-27: Manifest kiểm tra cặp model/metrics (PR #41 CI đã xác minh)

- Nhận diện rủi ro còn lại sau PR #39: nếu quá trình `os.replace` bị gián đoạn giữa model và metrics, hai file có thể không thuộc cùng một lần huấn luyện.
- Thêm `artifact_manifest.json` chứa SHA-256 của hai file, chỉ xuất bản sau khi thay thế xong cả hai; `scripts/verify_local_run.py` xác minh manifest trước khi gọi `joblib.load`. File cũ không có manifest được ghi nhận là `missing_legacy` để giữ tương thích, **không** được coi là đã kiểm tra manifest.
- Bổ sung kiểm thử synthetic cho checksum, thay thế bị lỗi ở file thứ hai, phát hiện model/metrics bị sửa và schema manifest không hợp lệ. [PR #41 quality gates run 40536864231](https://github.com/tbao4151/DA_CNTT/actions/runs/40536864231) **passed**: Python 3.12.9, syntax và full pytest (`163 passed, 2 skipped, 2 warnings`). Đây là CI trên PR head, chưa phải CI sau merge; không tuyên bố đã thực nghiệm Windows hay thay đổi kết quả UNSW.
- Giới hạn: manifest không ký số; người có quyền sửa tất cả artifact có thể sửa cả manifest. Các lần `os.replace` vẫn không phải một transaction; verifier sẽ từ chối mismatch khi có manifest trước đó. Cần chạy lại train sau gián đoạn.
- Bước tiếp theo: merge PR khi CI đã xanh, xác minh main CI; nhóm vẫn cần chạy thật trên Windows và lưu minh chứng thực nghiệm.

## 2026-10-27: Artifact pair manifest merged and CI verified (PR #41)

- [PR #41](https://github.com/tbao4151/DA_CNTT/pull/41) squash-merged vào `main` tại commit `8cec768ff6eada343fbc425719dc41bf6d9fd414`.
- [PR quality gates run 40537122750](https://github.com/tbao4151/DA_CNTT/actions/runs/40537122750) và [post-merge main quality gates run 40537387088](https://github.com/tbao4151/DA_CNTT/actions/runs/40537387088) đều **success**. PR run trước đó 40536864231 ghi nhận `163 passed, 2 skipped, 2 warnings` trên Python 3.12.9, cùng kiểm tra syntax thành công. Các lần CI lỗi ở commit trung gian chưa hoàn thiện không được coi là kết quả cuối.
- `persist_model` tạo `artifact_manifest.json` SHA-256 sau khi ghi model và metrics; local verifier kiểm tra checksum trước khi giải tuần tự hóa joblib, từ chối file bị sửa hoặc cặp ghi dở khi manifest cũ tồn tại. Legacy artifacts không có manifest được đánh dấu `missing_legacy`, không giả định có bảo đảm checksum.
- Không có thay đổi dữ liệu UNSW-NB15, tham số Random Forest, benchmark, ngưỡng cảnh báo, dữ liệu SOC hoặc triển khai công khai. Manifest không phải chữ ký số và không biến ba lần thay thế file thành transaction nguyên tử.
- Chưa có minh chứng sinh viên trực tiếp huấn luyện và chạy dashboard trên máy Windows cá nhân. Tiếp theo: chạy local training, verifier và chụp màn hình thực nghiệm thật để chuẩn bị báo cáo giảng viên.

## 2026-10-27: SOC UX redesign applying ui-ux-skill (PR #42 merged; PR CI verified)

- Read the supplied [UI UX Pro Max skill](https://github.com/tbao4151/ui-ux-skill) and used its accessibility/contrast, visual hierarchy, chart, responsive and focus-state rules. Implemented a light enterprise SOC theme in `.streamlit/config.toml` and `src/siem_ai/ui.css`: navy sidebar, clear white metric cards, compact white Plotly charts, legible form labels and responsive spacing.
- Refactored `app.py` presentation to include clear hero/offline scope, trained AI status, 5-tab guidance, explainers distinguishing ground-truth labels vs model predictions, and concise descriptions inside the existing tabs. Original tab labels and browser-tested controls retained; no model/threshold/SQLite changes.
- Added `docs/USING_DASHBOARD.md`, regression tests of theme configuration, and browser E2E checks for computed backgrounds plus a real Chromium screenshot artifact. Updated the isolated tests to copy the same Streamlit configuration they run locally.
- [PR #42](https://github.com/tbao4151/DA_CNTT/pull/42) squash-merged into main at `be3f29871b378472d8c03bda0824201dff4ea032`. [PR quality CI #40538948085](https://github.com/tbao4151/DA_CNTT/actions/runs/40538948085) **passed**; [official-model smoke #40538948167](https://github.com/tbao4151/DA_CNTT/actions/runs/40538948167) **passed on Ubuntu and Windows**, including Chromium verification of white KPI background/light canvas, AI → Alert → SOC case, state update and JSON export. Screenshot artifact `da005-soc-redesign-preview` (7-day retention) uploaded successfully, artifact ID 12750200788. Post-merge [main quality gates #40539826259](https://github.com/tbao4151/DA_CNTT/actions/runs/40539826259) **passed (165 passed, 2 skipped, 2 warnings)**. Post-merge Windows/Ubuntu browser run #40539826120 was still in progress at the time of this entry.
- No student-operated laptop screenshot or acceptance testing has been observed. UI still needs user review at desktop/mobile breakpoints; scientific metrics unchanged.

## 2026-10-28: Offline Zeek telemetry contract (PR pending)

- Added `src/blue_team_ai/zeek.py`: read bounded local Zeek ASCII `conn.log` without network access, preserve log-supplied timestamps/IPs and SHA-256 provenance, reject malformed records and mark missing numeric values as unknown. Added `src/blue_team_ai/__init__.py`.
- Added `tests/test_zeek_telemetry.py` with 14 synthetic offline test cases. Focused tests passed in an isolated Linux Python 3.13.5 sandbox (`14 passed`); this is **not** repository-wide GitHub CI or a student-run Windows experiment. PR CI and Python 3.12.9 results must be verified separately.
- Added `docs/CYBER_LAB_ARCHITECTURE.md` describing the separation between Dataset Mode and the future Cyber Lab Mode, scientific feature-parity barrier and Windows validation steps.
- No live capture, replay, Red Team operation, Cyber Lab AI inference, alerts or UI are claimed. Existing UNSW model, benchmark, Streamlit entry point and SOC database are untouched. Next: verify PR CI and merge only if green; student should capture an authorized Zeek log on an isolated VMware Host-only network and document local evidence.

## 2026-10-28: Cyber Lab Blue Team offline preview (PR/CI pending)

- Verified previous Zeek parser PR #43 is merged as `a34dcf21af830a085a322f19cc29061b7965d5fa`; PR-head quality gates [40549021768](https://github.com/tbao4151/DA_CNTT/actions/runs/40549021768) completed successfully with Python 3.12.9, syntax check and unit tests. This is not a student-operated Windows test.
- Added `src/blue_team_ai/preview.py`: pure aggregation of validated offline Zeek events with source SHA-256 consistency, true Zeek timestamp bounds, unique endpoints and protocol counts; refuses mixed/non-offline provenance. Does not assign attack labels.
- Added a separately navigable `pages/1_Cyber_Lab.py` Streamlit Blue Team preview, bounded upload, empty/error states, protocol chart and 500-flow preview; existing `app.py` Dataset Mode, Random Forest, official metrics and SQLite remain untouched.
- Added `tests/test_cyber_lab_preview.py` synthetic provenance/timestamp tests and headless Streamlit empty-state smoke. Updated CI path filter for `pages/**` and architecture/README/ROADMAP.
- A standalone syntax compilation and pure summary smoke were run on an isolated local draft. **Full repository pytest, new-page Streamlit AppTest, GitHub PR CI, merge and student-operated Windows/VMware checks remain unverified at the time of this entry.**
- No live network capture, attack traffic, AI detection, alert, SOC Case, Red Team UI or production SIEM claim. Next: inspect PR CI, fix failures, merge only if green, then collect an authorized Zeek conn.log and verify the UI on Windows.

- PR #44 first CI [40552410646](https://github.com/tbao4151/DA_CNTT/actions/runs/40552410646) **failed** with `181 passed, 1 failed, 2 skipped`: Streamlit AppTest executed the page in isolation and could not resolve `st.sidebar.page_link("app.py")`. Replaced this redundant explicit link with guidance to use Streamlit's built-in multipage navigation. A new CI run is required; no success claimed yet.

- After navigation fix, PR #44 quality gates [40552641827](https://github.com/tbao4151/DA_CNTT/actions/runs/40552641827) **passed** on Python 3.12.9: syntax check and full pytest (`182 passed, 2 skipped, 2 warnings`). This verifies the new offline page empty state in Streamlit AppTest and synthetic aggregation tests, **not** real Windows/VMware capture or browser E2E with a user log. Merge and post-merge CI remain to be checked.

## 2026-10-28: Manual offline Zeek review case (feature PR in progress)

- Checked `main` at `4327b61ee563ade5c342a882c0d165d6becf1afd`: prior offline preview PR #44 is merged; most recent main quality gates run `40553047894` completed successfully. No open PRs were returned when this slice began.
- Added `src/blue_team_ai/triage.py`: on an explicit operator action, re-parse original bounded Zeek bytes, select a validated flow by index and create a **manual Unclassified** SOC case (null AI confidence) through the existing case store. No automatic case creation, attack label or AI inference.
- Updated `pages/1_Cyber_Lab.py`: consent checkbox per source digest, first-500-flow selector, explicit case button, separate local `runtime/cyber_lab_cases.sqlite3` and downloadable JSON with original SHA-256, event metadata and SOC audit trail. Dataset Mode SQLite and model remain unchanged.
- Added `tests/test_zeek_manual_triage.py` using synthetic Zeek records to check provenance, Unclassified verdict, no Dataset DB mutation, export/audit and invalid selections. Updated Cyber Lab architecture and roadmap.
- **At creation of this entry:** full GitHub PR CI, merge, post-merge CI and real student Windows/VMware capture are not yet verified. The JSON is a mutable, unsigned snapshot; the shared SOC store stringifies evidence values (not lossless), and explicit repeated clicks can create duplicate manual cases. No Red Team activity, lab traffic, Zeek AI model, automated alert or official benchmark change is claimed.
- Next: inspect PR CI; merge only if green and conflict-free. Student should validate the page on Windows with an authorized Host-only Zeek log, retain original log + checksum and export one manual case as evidence. Separately design typed Cyber Lab evidence and lab-schema model.

## 2026-10-28: Manual Zeek SOC triage PR #45 merged and verified

- [PR #45](https://github.com/tbao4151/DA_CNTT/pull/45) squash-merged into `main` as commit `cb472a788a004e8fe692f734057ccf50de404093`.
- [PR quality gates 40558137956](https://github.com/tbao4151/DA_CNTT/actions/runs/40558137956) **passed** on Ubuntu Python 3.12.9: syntax + full pytest (`190 passed, 2 skipped, 2 warnings`). [Post-merge main quality gates 40558352334](https://github.com/tbao4151/DA_CNTT/actions/runs/40558352334) also **passed** (`190 passed, 2 skipped, 2 warnings`).
- The implementation adds only an operator-initiated, **Unclassified** manual Zeek case with original source digest and JSON evidence; it does not run an AI model or identify attacks. Dataset Mode and official UNSW metrics remain unchanged.
- No real Zeek capture, Windows laptop test, browser E2E for manual case creation, immutable evidence, or Red Team scenario has been verified. Next: manual Windows Host-only validation with a real authorized `conn.log`, then typed Cyber Lab evidence and independently labeled model training.


## 2026-10-28: Source-verified typed Zeek case export (PR pending)

- Checked `main` after PR #45: existing Cyber Lab only stores human-readable, stringified Zeek evidence; post-merge main CI for #45 was green (run 40558352334). No open PRs were returned by GitHub issue search at the start of this slice.
- Added `src/blue_team_ai/verified_report.py` and `tests/test_zeek_verified_report.py`: original log bytes are re-parsed at export, SHA-256 and selected record index are checked against the SOC snapshot and flow digest, and a v2 JSON export retains numeric/null Zeek types while preserving legacy case/audit fields.
- Updated Cyber Lab page to export only after verifying original bytes; current upload/session must retain the source and selected index. Existing Dataset Mode, model, metrics, SQLite schema and legacy v1 export are unchanged.
- **At writing:** changes are on feature branch; full GitHub PR CI, merge, post-merge checks, browser E2E and student Windows/VMware verification are NOT yet established. No new AI detection, lab attack or true network capture is claimed. This verifies internal source consistency, not authenticity or tamper-proof evidence.

- PR #47 [quality gates 40562186490](https://github.com/tbao4151/DA_CNTT/actions/runs/40562186490) **passed** on Ubuntu Python 3.12.9: compileall + full pytest (`199 passed, 2 skipped, 2 warnings`). Merge, post-merge CI and real Windows verification remain pending at this point. This run does not establish real Zeek capture or AI detection.

## 2026-10-28: Zeek-only lab feature projection v1 (feature PR in progress)

- Checked main commit `814e739cb11ac065ef06adda835ab30ca8d2b88e`, no open PRs, latest main quality gates [40562663215](https://github.com/tbao4151/DA_CNTT/actions/runs/40562663215) **success**. Previous typed-export [PR #47](https://github.com/tbao4151/DA_CNTT/pull/47) is merged; no duplicate implementation needed.
- Added `src/blue_team_ai/features.py` with a strict nine-column, versioned **Zeek-only** feature projection. It rejects malformed/mixed-source events and unexpected/leaky columns; preserves missing numeric values as `None`, preserves measured zeros, and excludes IP/UID/timestamps/digests/labels from projected model inputs. Added synthetic `tests/test_zeek_features.py` for field order, type validation, missingness, leakage and provenance rejection.
- This is **feature extraction only**, not trained AI, labeling, attack detection or an alert pipeline. No change to Dataset Mode, UNSW-NB15 Random Forest, official metrics, SQLite or active lab traffic. Feature extraction cannot authenticate original capture; evaluation must avoid cross-session/host leakage and document port/protocol shortcuts.
- **At writing:** changes are on a feature branch; PR CI, merge, post-merge CI and real Windows/VMware validation are not yet confirmed. Next: verify CI, merge only if green and conflict-free; then design independent Zeek labels/split protocol and lab-specific model. Students must still capture a genuine authorized Host-only Zeek log and archive SHA-256 plus setup evidence.

## 2026-10-28: Zeek feature projection merged; PR CI verified (#48)

- [PR #48](https://github.com/tbao4151/DA_CNTT/pull/48) squash-merged into `main` at commit `7e3871c950ecdaab638c6364d9a1ee5ee2eedacd`. [PR quality gates #40567319032](https://github.com/tbao4151/DA_CNTT/actions/runs/40567319032) completed **success** on Ubuntu Python 3.12.9: syntax + full pytest (`223 passed, 2 skipped, 2 warnings`). The warnings are existing pandas FutureWarnings in `tests/test_model.py`, not new feature-contract failures.
- At the time of this record, a **post-merge main CI run for commit 7e3871c was not yet visible** in GitHub Actions; do not infer it from the green PR run. Verify later before claiming main CI passed.
- Nine typed Zeek-only feature columns are now available to future lab-model work, with strict source/field/type validation and explicit rejection of label/AI fields. No independent labels, lab-trained AI, calibrated alerts, active capture, Red Team operation or genuine Windows/VMware evidence has been produced. Dataset Mode and official UNSW metrics remain unchanged.
- Next: design independent labeling + session-aware split and train a separate Zeek-compatible baseline only when authorized labeled logs exist; test the offline feature contract on student-owned Host-only `conn.log` and preserve SHA-256.


## 2026-10-28: Independently labeled offline Zeek dataset contract (feature PR pending)

- Reviewed `main` at `6747d601089e8ffdb6b1fef2aff65f7a29948cd0`, existing Zeek parser, nine-feature v1 projection, architecture, roadmap and open PRs (none returned). Previous PR #48 was merged; [post-merge CI for its commit](https://github.com/tbao4151/DA_CNTT/actions/runs/40567806172) is **success** on main. No real Windows/VMware capture or model inference was verified.
- Added `src/blue_team_ai/labeled_dataset.py`: accepts only bounded raw Zeek bytes and external per-UID 0/1 labels with explicit session, host, split, labeling method and reference; refuses duplicate source/session/UID, missing/invalid labels, cross-split host leakage and missing classes in any partition. Returns separate Zeek-v1 feature matrices, labels and provenance, without fitting a model or modifying Dataset Mode.
- Added synthetic regression tests in `tests/test_zeek_labeled_dataset.py` and documented how to collect and preserve independent annotation evidence in `docs/CYBER_LAB_ARCHITECTURE.md`; updated ROADMAP.
- **At writing:** GitHub PR CI, merge and post-merge CI are not yet verified. No legitimate lab log, independent labels, Zeek-trained classifier, AI attack alert, Red Team AI or Windows E2E has been produced by this slice. The label reference is self-declared metadata and not authentication of the labels. Next: inspect PR CI, fix failures, merge only after success, then design a train-only preprocessing/validation-only tuning pipeline. Students must still capture authorized Host-only Zeek logs and record separate ground-truth evidence.


## 2026-10-28: Offline Zeek train/validation/test baseline (PR #51 pending)

- Checked `main` at `0ee44eb005ce7308adde832d6cf16244795ede61`:
  prior independent-label contract PR #50 is merged; latest main quality gates
  [40571438304](https://github.com/tbao4151/DA_CNTT/actions/runs/40571438304)
  completed successfully. No open PRs were returned at the start of this slice.
- Added `src/blue_team_ai/offline_baseline.py`: strictly separate Zeek-only
  Logistic Regression pipeline. It validates host/session/source-disjoint
  labels/features, fits median imputation, scaling, categorical encoding and
  model on **train only**, selects a threshold on **validation only**, then
  evaluates held-out test once. Reports confusion counts, Precision/Recall/
  F1/FPR and bounded source/host/session provenance. No raw log/IP/UID/label
  references are exported in the report.
- Added `tests/test_zeek_offline_baseline.py`: synthetic regression for
  train/test isolation, held-out-label changes, unknown categories, null
  measurements, provenance/feature leakage and malformed input. Updated
  architecture and roadmap.
- **At writing:** PR #51 is open; its final CI result, merge, post-merge
  quality gates and real Windows/VMware experiments are not verified.
  Synthetic test metrics are not scientific attack-detection results.
- No saved/deployed model, AI alert, active capture, Red Team operation,
  changes to official UNSW benchmark or SOC database. Next: verify PR CI and
  merge only if green and conflict-free; students must collect authorized
  Host-only Zeek logs with independent labels and holdout before claiming
  any Cyber Lab detection performance.


## 2026-10-28: Offline Zeek research baseline merged and CI verified (#51)

- [PR #51](https://github.com/tbao4151/DA_CNTT/pull/51) squash-merged into
  `main` as commit `f25cacd1e605345bee0fd5bcb7c5f6aa701dc6f3`.
  Final PR-head [quality gates 40575163730](https://github.com/tbao4151/DA_CNTT/actions/runs/40575163730)
  **passed** on Ubuntu Python 3.12.9: syntax + full pytest
  (`251 passed, 2 skipped, 2 warnings`). Post-merge main
  [quality gates 40575309335](https://github.com/tbao4151/DA_CNTT/actions/runs/40575309335)
  **passed** at the same merge commit.
- An earlier intermediate branch run 40575051745 **failed** one new
  provenance-validation regression; the feature branch was fixed and the
  final PR-head run passed. Do not interpret the intermediate failure as a
  failure of the merged commit.
- This is an **offline code path** for independently labeled Zeek features:
  train-only preprocessing/Logistic Regression, validation-only threshold
  selection and one-time test evaluation. No real Zeek-lab dataset or measured
  attack-detection score is available. Synthetic fixtures only.
- Still outstanding: student-run Windows/VMware Host-only captures, independent
  annotation evidence, model calibration, actual lab held-out evaluation,
  model persistence/trust, UI inference, SOC alerts and safe Red Team controls.
  Dataset Mode's UNSW model and benchmark remain unchanged.


## 2026-10-28: Private-manifest offline Zeek experiment CLI (feature PR pending)

- Checked latest `main` at `22ef4398d3606532cc5904896860f1cfc7274d65`: PR #52 merged, previous #51 baseline PR/main CI green, and no open PRs returned at the start of this slice. This work is isolated on `feature/zeek-offline-experiment-cli-20261028`.
- Added `scripts/evaluate_zeek_lab.py`: explicit private manifest v1 with three host-disjoint partitions; reads bounded local original Zeek logs and separate per-UID label JSON, checks exact source SHA-256 in both manifest and annotation, rejects duplicate JSON keys and path escapes, then runs the existing train-only Logistic Regression/validation-threshold/held-out test pipeline. Writes a new private report without overwriting an existing one. Does not persist a model, create AI alerts, capture traffic or change UNSW/SOC.
- Added `tests/test_zeek_lab_cli.py` with synthetic end-to-end CLI and fail-closed input regressions; added `docs/ZEEK_OFFLINE_EXPERIMENT.md` with a Windows usage and evidence protocol.
- **At writing:** feature PR CI, merge and post-merge CI have not yet been verified. No student-operated VMware capture, independently authenticated labels, real Zeek attack-detection performance, model deployment or Red Team operation is claimed.
- Next: verify PR CI, fix failures, merge only when green; on Windows collect authorized Host-only logs, assign independent labels and run a pre-registered host-disjoint experiment in a private folder outside Git.

## 2026-10-28: Offline Zeek experiment CLI verified and merged (#53)

- [PR #53](https://github.com/tbao4151/DA_CNTT/pull/53) squash-merged as `3e440050227e5971ef217ab313bc0d1e25b857b4`.
- Final PR-head [quality gates #40580782727](https://github.com/tbao4151/DA_CNTT/actions/runs/40580782727) **passed** on Ubuntu Python 3.12.9: syntax and full pytest (`260 passed, 2 skipped, 2 warnings`). Post-merge main [quality gates #40581017701](https://github.com/tbao4151/DA_CNTT/actions/runs/40581017701) **passed** at the merge commit.
- Verified functionality is a bounded local CLI + synthetic regression, not actual student Windows/VMware evidence. It accepts preassigned independent labels; the code cannot authenticate those labels or Host-only isolation. No real Zeek detection score, model deployment, automatic alert or Red Team AI has been demonstrated.
- Next: student-owned Host-only captures, genuine per-UID ground truth, reserved host-disjoint test and Windows run using `docs/ZEEK_OFFLINE_EXPERIMENT.md`. Preserve raw logs privately; do not publish IPs or notebook references.

## 2026-10-28: Zeek offline probability diagnostics (feature PR pending)

- Reviewed `main` at `828ceb24f446676716716785431d5cd3ed1d2360`; PR #53 offline CLI and #54 CI documentation were merged, recent main quality gates completed successfully, and GitHub returned no open PRs at start of slice.
- Added `src/blue_team_ai/probability_diagnostics.py`: bounded, five-bin descriptive Brier score/ECE/reliability counts, explicit empty-bin nulls and small-sample warnings; refuses invalid labels/probabilities. No calibration, training, network access or AI-to-SOC alert behavior.
- Updated Zeek-only `offline_baseline.py` to include validation and held-out test probability diagnostics in report v2 **after** validation-only threshold selection; no test-based refit, threshold tuning or deployment. Added synthetic tests and Windows experiment documentation. Dataset Mode and official UNSW benchmark untouched.
- **At writing:** feature branch exists; GitHub PR CI, merge, post-merge CI, student-operated Windows/VMware experiment and genuine attack-detection/calibration measurements are not yet verified. Do not interpret synthetic fixture scores as scientific results. Next: verify PR CI, merge only after success and no conflicts; students must preserve independent labels, original logs and Host-only isolation evidence.

## 2026-10-28: Zeek probability diagnostics merged and CI verified (#55)

- [PR #55](https://github.com/tbao4151/DA_CNTT/pull/55) squash-merged as `db46f2e4ea9c04a2a46a30d627abbbed19389e59`. Final PR-head [quality gates #40584685479](https://github.com/tbao4151/DA_CNTT/actions/runs/40584685479) **passed** on Ubuntu Python 3.12.9: syntax and full pytest (`278 passed, 2 skipped, 2 warnings`). Post-merge main [quality gates #40584856503](https://github.com/tbao4151/DA_CNTT/actions/runs/40584856503) **passed** at the squash-merge commit.
- Earlier intermediate branch CI failures were superseded by the successful final PR-head run; the two remaining pytest warnings are pre-existing pandas FutureWarnings in `tests/test_model.py`. This verifies code behavior on synthetic fixtures, not calibrated probabilities or real lab performance.
- Report v2 adds validation and test Brier score, fixed-bin ECE, reliability counts and small-sample warnings. No model persistence, test-based tuning, automated SOC alert, Red Team operation or changes to UNSW official benchmark. Real independent labels, Host-only isolation and Windows/VMware experiment evidence remain unverified.
- Next: students should collect authorized Zeek captures with independent scenario labels and preassigned host-disjoint splits; run `scripts/evaluate_zeek_lab.py` privately and retain original SHA-256, Zeek version and isolation proof. Avoid using test diagnostics for model selection.

## 2026-10-28: Zeek flow-level detection uncertainty (feature PR pending)

- Inspected main after PR #55 was merged; no open PRs returned by GitHub search at the start of this slice. The last documented main quality gates were green for PR #55; no student-operated Windows/VMware evidence exists in the repository.
- Added `src/blue_team_ai/uncertainty.py` to compute 95% Wilson score intervals for flow-level Attack Precision, Recall and FPR from confusion counts, with JSON null when a denominator is zero. Added synthetic regression tests and report v3 fields to the existing offline Zeek baseline; preserved validation-only threshold selection and test isolation.
- The new intervals assume independent flows, which can be false for correlated host/session events. They are descriptive and NOT host-cluster-adjusted or evidence of real attack detection. No trained Zeek model was persisted, no live capture/alerts/Red Team execution was introduced, and UNSW Dataset Mode was unchanged.
- **At writing:** feature PR CI, merge and post-merge CI are not yet verified. Next: review final CI, merge only if green; students must collect authorized Host-only captures, independent labels, and host/scenario-level evidence before interpreting detection performance.

## 2026-10-28: Zeek Wilson uncertainty merged and verified (#57)

- [PR #57](https://github.com/tbao4151/DA_CNTT/pull/57) squash-merged as `e0a2029c601a59e5a688b8d345f9aeb1829d64d9`. Final PR-head [quality gates #40589156075](https://github.com/tbao4151/DA_CNTT/actions/runs/40589156075) passed on Ubuntu Python 3.12.9; post-merge main [quality gates #40589335170](https://github.com/tbao4151/DA_CNTT/actions/runs/40589335170) also passed (`295 passed, 2 skipped, 2 warnings`).
- The first PR-head run #40588946783 failed a new boundary test because a floating-point Wilson upper endpoint was 0.9999999999999999 instead of exactly 1; fixed by explicit boundary clamping in commit `43072281ec15f4b853ac155f52697d395ccf7de8` and revalidated. The final merged commit is green.
- Offline Zeek report v3 includes flow-level Wilson 95% intervals for Attack Precision/Recall/FPR on validation and held-out test. The intervals assume independent flows and may be too narrow for correlated sessions; no real lab attack-detection results or Windows evidence are claimed.
- Next: student-run Host-only captures, independent ground truth, host/scenario-level variability and Windows experiment; do not use synthetic CI scores as research evidence. No Zeek deployment, automated SOC alerts or Red Team AI was added.

## 2026-10-28: Offline Zeek host-group variability (feature PR pending)

- Verified the latest `main` after merged PR #58 (commit `cd004785eeba90f40b081b904be2df8aa4f4b344`); no open PRs were returned at the start of this slice. PR #57 final head and post-merge CI had passed (295 passed, 2 skipped, 2 warnings).
- Added `src/blue_team_ai/host_variability.py` to summarize fixed-threshold, operator-declared host-group confusion counts, Precision/Recall/FPR and across-group ranges/means for validation and held-out test separately. No raw host names, UIDs, IPs or annotation references are exported; undefined rates are null and insufficient groups/support raise warnings.
- Integrated descriptive host-group summaries into offline Zeek report v4, with synthetic-only unit and integration tests. The model still fits only training data and selects the threshold only on validation. No model persistence, live capture, active Red Team, automated SOC alerts or changes to the UNSW official benchmark.
- This does **not** authenticate host groups or labels and does **not** compute cluster-adjusted confidence intervals. One host group per split (as in existing synthetic fixtures) cannot quantify host variability; actual host/session variation requires multiple independent groups and real student-operated captures.
- **At writing:** PR CI, merge and post-merge CI are not yet verified. Do not report tests as passed until GitHub Actions confirms them. Next: inspect PR quality gates, resolve failures if any, merge only when green. Student must independently collect and label authorized Host-only logs, preserve isolation evidence and test on Windows.

## 2026-10-28: Offline Zeek host-group report v4 merged and CI verified (#59)

- [PR #59](https://github.com/tbao4151/DA_CNTT/pull/59) squash-merged as `7e98914777e883b408128c1a3868651c0d43c746`. Final PR-head [quality gates #40592582729](https://github.com/tbao4151/DA_CNTT/actions/runs/40592582729) passed on Ubuntu Python 3.12.9; post-merge main [quality gates #40592751422](https://github.com/tbao4151/DA_CNTT/actions/runs/40592751422) also passed: **313 passed, 2 skipped, 2 warnings**. Two pandas FutureWarnings are pre-existing in `tests/test_model.py`; transient intermediate push checks are not the final PR gate.
- Offline Zeek report v4 adds validation/test per-host-group descriptive TP/FP/TN/FN, Attack Precision/Recall/FPR, macro ranges and small-group warnings without raw host identifiers. The synthetic test dataset has only one host group per evaluation split and therefore cannot demonstrate actual between-host variation.
- No real Windows/VMware capture, independent ground-truth authentication, host-cluster-adjusted confidence intervals, deployable Zeek model, live alerts or Red Team activity is claimed. UNSW Dataset Mode remains unchanged. Next: independent student captures and labels with multiple host groups within each split, private experiment reports and Windows evidence.

## 2026-10-28: Red Team offline scenario-planning UI and policy (feature PR pending)

- Inspected current main `fbea5e81608cb9180b68d342ab937b771b53332b`, no open PRs, and last PR #60 quality gates successful; Blue Team Zeek report v4 remains research-only, with no student-operated Windows/VMware evidence.
- Added separate `src/red_team_ai/` bounded scenario-policy module (UCB1 and seeded random baseline), immutable catalog of three **non-executable** offline planning labels, strict operator-feedback validation and non-network output. Added `pages/2_Red_Team_Lab.py` Streamlit workspace using existing SOC CSS, operator-entered feedback, JSON proposal export and session-state clearing. This is an offline planner, not an autonomous attack agent, actual traffic replay, or measured Red/Blue competition.
- Added `tests/test_red_team_scenario_policy.py` and `docs/RED_TEAM_OFFLINE_PLANNER.md`. Local isolated Python check: syntax compilation succeeded and 16 policy tests passed; Streamlit UI smoke test could not run locally because Streamlit is not installed and this runtime cannot reach PyPI. GitHub PR CI must verify UI and full regression before merge. No real network access, VMware control, exploit, Blue Team feedback integration or live kill switch.
- **At writing:** PR/head CI, merge and post-merge CI are unverified. Do not claim real attack detection. Next: verify PR CI, merge only if green, and keep Red Team execution disabled until Host-only isolation, explicit consent, allowlist, bounded rates, audit and effective stop are validated by students.

## 2026-10-28: Red Team offline planner merged and verified (#61)

- [PR #61](https://github.com/tbao4151/DA_CNTT/pull/61) squash-merged as `548eb1d494e3a5583b2858317aadf3c53ae5356b`; final PR-head [quality gates #40596607248](https://github.com/tbao4151/DA_CNTT/actions/runs/40596607248) **passed** on Ubuntu Python 3.12.9: syntax and full pytest (**330 passed, 2 skipped, 2 warnings**). Post-merge main [quality gates #40596728175](https://github.com/tbao4151/DA_CNTT/actions/runs/40596728175) **passed**.
- Independent `src/red_team_ai/` and `pages/2_Red_Team_Lab.py` now provide offline UCB1/seeded-random **proposal selection only**, fixed non-executable scenario labels, unverified manual feedback and JSON export. The Streamlit empty-state smoke is included in the green GitHub test suite; this is **not** a Windows laptop/VMware acceptance test.
- No Red Team traffic, exploit, replay runner, lab target, verified Blue Team feedback or real kill switch exists. Dataset Mode and Zeek offline Blue Team remain unchanged. Next: student Windows UI acceptance, verified Host-only captures/labels and offline Red/Blue outcome integration only after evidence/safety gates.


## 2026-10-28: Private Zeek annotation template helper (feature PR pending)

- Checked `main` at `0413f9ae3d7a1415c3e1b894bd768bfb7c643f55`: no open PRs, latest Red Team offline planner (#61/#62) merged, and last PR quality gate successful. No student-operated VMware/Windows evidence is available.
- Added `scripts/prepare_zeek_annotations.py` to create private, **unlabeled** UID-to-`null` JSON templates directly from bounded Zeek ASCII `conn.log`, with the original raw-file SHA-256. It refuses duplicate UIDs, oversize templates, repository-local outputs and overwriting existing evidence. No ground truth is inferred from ports, IPs, protocol, timestamps or model predictions.
- Added `--verify-labels` mode to check strict 0/1 integer labels, exact UID coverage, duplicate JSON keys, source digest and input bounds **without** treating operator labels as authenticated. This output is compatible with the existing private-manifest `scripts/evaluate_zeek_lab.py` contract; it does not alter Dataset Mode, fit a model, generate alerts or transmit network traffic.
- Added synthetic-only `tests/test_zeek_annotation_template.py` and updated `docs/ZEEK_OFFLINE_EXPERIMENT.md` with Windows commands and independent labeling guidance. Isolated local Python 3.13.5 test using a local copy of the current Zeek parser: **12 passed**; GitHub Python 3.12.9 full CI, PR merge and post-merge CI **not yet verified at writing**.
- Next: verify final PR-head GitHub Actions and merge only if green. Student must independently collect authorized Host-only Zeek captures, document label provenance, fill every `null`, check each annotation against unchanged source bytes, and run the existing private experiment on Windows. No real detection performance is claimed.


## 2026-10-28: Private Zeek annotation helper merged and CI verified (#63)

- [PR #63](https://github.com/tbao4151/DA_CNTT/pull/63) squash-merged as `f8b8713f9b7ef2caa198d9f55edb8cd1a8af5ab8`. Final-head [PR quality gates #40600836916](https://github.com/tbao4151/DA_CNTT/actions/runs/40600836916) **passed** on Ubuntu Python 3.12.9, with **342 passed, 2 skipped, 2 warnings** (the two existing pandas FutureWarnings). Post-merge main [quality gates #40600988892](https://github.com/tbao4151/DA_CNTT/actions/runs/40600988892) also **passed**.
- The merged helper generates SHA-bound, UID-complete `null`-only private Zeek annotation templates and verifies operator-entered strict binary labels without inventing ground truth. Tests are synthetic; no genuine Windows/VMware capture or label-authenticity proof has been obtained. The official UNSW Dataset Mode benchmark is unchanged.
- Next: student-run authorized Host-only captures, independent per-UID annotations, manifest v1 with host-disjoint partitions, private CLI experiment and Windows acceptance evidence. No automated Cyber Lab AI alert or Red Team execution is claimed.

## 2026-10-28: Red Team paired synthetic policy comparison (PR #65 merged; CI verified)

- Added `src/red_team_ai/synthetic_benchmark.py` to compare the existing UCB1 versus seeded Random planner on **paired, deterministic, hypothetical Bernoulli observations** for the three non-executing scenario labels. It exports assumed probabilities, per-trial synthetic unflagged fractions, expected pseudo-regret and selection counts with an explicit synthetic-only provenance marker.
- Added a bounded comparison form/table/JSON export to `pages/2_Red_Team_Lab.py`, synthetic regression tests and `docs/RED_TEAM_SYNTHETIC_BENCHMARK.md`. Existing manual feedback remains separate; no networking, attack execution, Blue Team inference, SOC writes or UNSW benchmark changes.
- Local isolated developer check: 13 new synthetic tests passed under Python 3.13. [PR #65](https://github.com/tbao4151/DA_CNTT/pull/65) squash-merged as `e23ba043414dcbf98098e8a8fc2c64e6e550025a`. [PR-head CI #40603700957](https://github.com/tbao4151/DA_CNTT/actions/runs/40603700957) and [post-merge main CI #40603879260](https://github.com/tbao4151/DA_CNTT/actions/runs/40603879260) both passed on Ubuntu Python 3.12.9: **355 passed, 2 skipped, 2 warnings**. Student Windows laptop acceptance remains unverified.
- These numbers are **not** observed Blue Team detections, attack success, lab capture evidence or scientific validation. Next: verify PR CI, then collect independently labeled Host-only Zeek captures and design a source-linked, pre-registered genuine AI-vs-AI comparison before replacing hypothetical feedback.

## 2026-10-28: Offline Zeek manifest preflight (feature PR; CI pending)

- Inspected main after merged PR #66 and found no open PRs. Latest Red Team synthetic policy comparison (#65) and documentation (#66) were merged with recorded green CI; no genuine student Windows/VMware capture or independent label authenticity has been verified.
- Added a read-only `--preflight` mode to `scripts/evaluate_zeek_lab.py` that reuses bounded SHA-256/annotation/host-split validation, prints only aggregate per-split class/host/session counts and warns on tiny samples or single-host splits. It neither fits an AI model nor evaluates the held-out test, writes output files, contacts networks or produces alerts.
- Added synthetic regression tests for valid summaries, no-write behavior, missing labels, cross-split host reuse, mutually exclusive CLI modes and privacy. Documented Windows invocation in `docs/ZEEK_OFFLINE_EXPERIMENT.md`.
- **At writing:** GitHub Python 3.12.9 PR CI, merge and Windows acceptance are not yet verified. No scientific detection metrics, authenticated ground truth, physical isolation proof or deployed Zeek model is claimed. Dataset Mode/UNSW benchmark unchanged.
- Next: verify CI before merge; student collects authorized Host-only Zeek logs, independently annotates every UID, records isolation evidence, checks manifest with preflight, then runs the pre-registered private holdout experiment once.

## 2026-10-28: Zeek structural preflight merged and verified (#67)

- [PR #67](https://github.com/tbao4151/DA_CNTT/pull/67) squash-merged as `22a27aef23934c571caf87d41627c0c07825316e`. Final PR-head [CI #40606690395](https://github.com/tbao4151/DA_CNTT/actions/runs/40606690395) and post-merge main [CI #40606955867](https://github.com/tbao4151/DA_CNTT/actions/runs/40606955867) **both passed** on Ubuntu Python 3.12.9: **360 passed, 2 skipped, 2 warnings**. The two pandas FutureWarnings remain in existing `tests/test_model.py`.
- The new `--preflight` checks private Zeek manifest, SHA-256, UID labels and host-disjoint partitions without fitting/scoring AI, writing a report or touching the network. Five synthetic regression tests were added; this is a structural input check, not attack-detection evidence.
- No Windows/VMware student capture, authenticated labels, live Blue Team alerts or active Red Team execution was verified. Next: run preflight privately on independently annotated authorized Host-only logs, retain isolation evidence and pre-registered holdout, then run the experiment without test tuning.

## 2026-10-28: Offline Zeek declared CIDR scope screening (feature PR pending)

- Reviewed `main` at `67dc37bac380bf14649539d0bdfa318641442ee8`: PR #67/#68 merged, most recent completed PR/main quality gates green; no open PRs at start of this slice. No verified student Windows/VMware capture or independent label authenticity exists.
- Added `src/blue_team_ai/lab_scope.py` and `scripts/check_zeek_lab_scope.py` to screen an existing bounded Zeek ASCII `conn.log` against 1–4 explicitly declared canonical RFC1918 IPv4 CIDRs (/16 or narrower), rejecting any out-of-scope source/destination endpoint. This is strictly **offline**; no network activity, Red Team execution, AI fitting/inference, alerts or SOC writes.
- The exclusive, private JSON report records original log SHA-256, a digest of the declared CIDR set, flow/unique-endpoint counts and log-declared UTC bounds; no raw IPs, UIDs, ports or paths are exported. Added synthetic-only regression tests and `docs/ZEEK_LAB_SCOPE_CHECK.md` with Windows usage and independent isolation-evidence requirements.
- **At writing:** feature PR quality gates, merge, post-merge CI and student Windows acceptance are not yet verified. Passing CIDR membership is **not proof** of VMware Host-only isolation, authorization, authentic capture, genuine ground truth or attack detection. Dataset Mode and official UNSW benchmark unchanged.
- Next: verify final PR CI before merge; student must manually inspect VMware virtual network isolation, capture an authorized genuine `conn.log`, run this scope screen privately and retain separate Zeek version, isolation screenshots, labels and pre-registered split evidence.

## 2026-10-28: Offline Zeek declared CIDR scope screening merged and verified (#69)

- [PR #69](https://github.com/tbao4151/DA_CNTT/pull/69) squash-merged as `9e6d77c30a5e895ea117931e8892dde477c90cab`. Final PR-head [quality gates #40609888602](https://github.com/tbao4151/DA_CNTT/actions/runs/40609888602) and post-merge main [quality gates #40610040898](https://github.com/tbao4151/DA_CNTT/actions/runs/40610040898) both passed on Ubuntu Python 3.12.9: **377 passed, 2 skipped, 2 warnings** (existing pandas FutureWarnings).
- Implemented a bounded, offline-only strict IPv4 RFC1918 CIDR membership check for source and destination addresses in user-provided Zeek `conn.log`, with exclusive private aggregate/hash report and synthetic regression tests. This is NOT a network isolation verifier, authentic capture verifier, AI attack detector or active Red Team runner.
- Student Windows/VMware Host-only execution and genuine independently labeled logs remain **unverified**. Next: collect an authorized local log, record independent VMware isolation evidence, run the scope check privately and then annotation/preflight on pre-registered host-disjoint captures. Dataset Mode and UNSW benchmark unchanged.

## 2026-10-28: Zeek experiment all-capture declared-CIDR gate (feature PR pending)

- Reviewed current `main` at `854b0d235af24dc6a762311eb51228ea44db7b90`, recent merged PR #69/#70 and completed green PR-head CI #40610214721; GitHub returned no open PRs before this change. No student Windows/VMware acceptance or independently authenticated labels were found.
- Extended the existing offline `scripts/evaluate_zeek_lab.py` with optional repeatable `--cidr` for both structural `--preflight` and research `--output`. It reuses the strict `inspect_zeek_lab_scope` guard to check every SHA-verified capture, including held-out test inputs, before labels/model fitting; any out-of-scope endpoint fails closed. Without opt-in, reports explicitly mark scope as **not screened** (null rather than a false assurance).
- Added synthetic regression tests for all-capture enforcement, digest-consistent out-of-scope refusal, invalid CIDRs, CLI modes, no-output-on-failure and privacy; documented Windows usage. No new model, network access, alert, SOC write, active Red Team, UNSW benchmark change or genuine detection result.
- **At writing:** final PR-head GitHub Actions Python 3.12.9 CI, merge and post-merge CI are **not yet verified**. Passing CIDR membership does not authenticate VMware Host-only isolation, authorization, capture provenance or label truth. Next: verify CI before merging. Student must still capture an authorized Host-only log, preserve actual VMware network evidence and independent UID annotations, and run the opt-in scope gate privately.

## 2026-10-28: Zeek experiment CIDR gate merged and CI verified (#71)

- [PR #71](https://github.com/tbao4151/DA_CNTT/pull/71) squash-merged as `1aaf1db80d40e491dd7652ddfd4cc0458a08672d`. Final-head [PR CI #40613565397](https://github.com/tbao4151/DA_CNTT/actions/runs/40613565397) and [post-merge main CI #40613723816](https://github.com/tbao4151/DA_CNTT/actions/runs/40613723816) **both passed** on Ubuntu Python 3.12.9: **384 passed, 2 skipped, 2 warnings** (pre-existing pandas FutureWarnings).
- The optional `--cidr` switch now screens **all** manifest Zeek captures for explicitly declared RFC1918 IPv4 address membership in both read-only preflight and private offline research evaluation. Out-of-scope endpoints fail before fitting or report creation. Without `--cidr`, the output records `declared_scope_screened=false` and `all_endpoints_within_declared_scope=null` instead of suggesting the scope was verified.
- These tests are synthetic; the new check does not prove physical VMware Host-only isolation, authorization, original log authenticity, independent labels, or real AI attack detection. No Windows laptop/VMware experiment is verified. No UNSW benchmark, live capture, Red Team traffic, model deployment or SOC alert path was modified.
- Next: student captures authorized Zeek logs in a verified Host-only lab, archives network configuration screenshots and Zeek version, applies the actual lab CIDR in preflight, completes independent labels and runs the held-out experiment once. Keep all private captures and annotations outside GitHub.


## 2026-10-28: Optional private held-out Zeek prediction trace (feature PR)

- Added an opt-in offline `--trace-output` mode to the Zeek experiment CLI and baseline: it emits a **private** test-flow UID/source-SHA join, Attack probability, validation-locked verdict and comparison with operator-supplied labels. Existing aggregate `--output` remains unchanged; no model artifact, live capture, automatic AI alert or SOC write is introduced.
- Trace files are restricted to the private manifest directory **outside the Git repository**, created exclusively, and the CIDR gate still checks all captures before any model fit. New synthetic tests cover trace opt-in, UID/source join, unchanged model predictions under altered test labels, refusal on out-of-scope input, and mode exclusivity.
- **Verification pending in this feature PR:** GitHub Actions final-head CI and merge. No genuine VMware/Windows capture, independent label authenticity or real-world detection has been verified. Next: inspect CI before merge; student runs one preregistered authorized Host-only experiment and reviews its private trace without tuning on test.


## 2026-10-28: Private held-out Zeek prediction trace merged and verified (#73)

- [PR #73](https://github.com/tbao4151/DA_CNTT/pull/73) squash-merged as `01df0ca204e02edeb1db760bbb9489b96ca52658`. Final-head [PR CI #40616820490](https://github.com/tbao4151/DA_CNTT/actions/runs/40616820490) and [post-merge main CI #40616997285](https://github.com/tbao4151/DA_CNTT/actions/runs/40616997285) both passed on Ubuntu Python 3.12.9: **388 passed, 2 skipped, 2 warnings** (existing pandas FutureWarnings).
- New optional `--trace-output` mode emits a private held-out test-flow source SHA-256/UID, Attack probability, fixed validation-selected prediction, operator-supplied reference label and confusion outcome. Existing aggregate report/preflight remain unchanged; no network access, model deployment, automatic alerts or SOC case writes. Synthetic-only regression tests passed.
- **Not verified:** student Windows/VMware execution, genuine independently annotated captures, isolation/authorization, label authenticity or real attack detection. Test-flow traces must remain private and cannot be used to tune on the held-out test. Next: student runs the scope-checked, pre-registered experiment once and preserves private evidence.

## 2026-10-28: Read-only Blue Team review of private held-out Zeek predictions (feature PR; CI pending)

- Reviewed main at `e86b959759344223f63a2befa96d03085e8bac8f`: latest #73/#74 merged, no open PRs, prior PR quality gate green. No genuine Windows VMware capture or independent label evidence was verified.
- Added `src/blue_team_ai/trace_review.py` to validate bounded private `--trace-output` JSON (schema, duplicate JSON keys, threshold/probability/verdict consistency, test confusion counts, unique SHA/UID pairs) and join one supplied original `conn.log` by SHA-256 plus exact UID coverage. It returns only label-free read-only rows for that log; other test captures are explicitly not authenticated.
- Added an optional private trace uploader and research-candidate table to `pages/1_Cyber_Lab.py`. This does not fit/load a model, write a SOC case, generate traffic, or create live/automatic alerts. It displays only source-matched research predictions, never operator-supplied labels.
- Added synthetic-only regression tests using a real small Logistic Regression baseline and negative cases; updated the offline experiment documentation and roadmap.
- **At writing:** GitHub PR-head Python 3.12.9 CI, merge, post-merge CI, and student Windows acceptance are **not yet verified**. Trace internal consistency cannot prove authentic model provenance, independent ground truth, physical Host-only isolation, or real attack detection.
- Next: verify CI and merge only if green; student must collect authorized Host-only logs and independently annotated test data, run the experiment with `--trace-output`, and review private predictions locally without tuning on held-out test.

## 2026-10-28: Private Zeek trace read-only Blue Team review merged and verified (#75)

- [PR #75](https://github.com/tbao4151/DA_CNTT/pull/75) squash-merged as `58a58ced1348494c7cc74c41d9748777a206d845`. Final-head [PR CI #40619319844](https://github.com/tbao4151/DA_CNTT/actions/runs/40619319844) and [post-merge main CI #40619489913](https://github.com/tbao4151/DA_CNTT/actions/runs/40619489913) both **passed** on Ubuntu Python 3.12.9. PR CI: **403 passed, 2 skipped, 2 warnings** (pre-existing pandas FutureWarnings).
- Read-only `trace_review.py` validates private trace schema, source SHA-256, exact UID join, validation-selected threshold, probabilities/verdicts and confusion totals. Optional Blue Team UI shows up to 500 label-free research Attack candidates from the supplied original Zeek log; no model loaded, no automatic alerts/cases, no traffic generated.
- Tests used synthetic Zeek fixtures and a real small fitted Logistic Regression, **not** genuine student VMware logs. Source/trace consistency cannot authenticate training, independent labels, capture origin or network isolation. Windows UI and authorized Host-only E2E remain **unverified**. UNSW benchmark unchanged.
- Next: student captures authorized genuine Host-only Zeek logs, archives isolation evidence and independent labels, preregisters holdout, then runs `--trace-output` and checks the private trace against original `conn.log` in the Blue Team page without tuning on test.


## 2026-10-28: Analyst-confirmed private Zeek research candidate triage (feature PR, verification pending)

- Reviewed current main at `da4b62c57d5a2b11c0d555acb76844775ce44e63`: PR #75/#76 merged, no open PRs; latest feature PR-head and post-merge main CI green. No genuine student Windows/VMware Host-only experiment or independently authenticated ground truth verified.
- Added an **explicit analyst** action to create a separate Cyber Lab Unclassified SOC case from a source/UID-matched private held-out *research* candidate. The full source and trace are revalidated at click time, only predicted-Attack candidates among the first 500 visible Zeek rows qualify, and the initial case/audit transaction records original SHA-256, private trace SHA-256, Zeek UID, research probability and locked validation threshold. No supplied ground-truth label is copied into the case.
- Existing manual cases retain their default empty note and audit behavior; Dataset Mode, official UNSW benchmark, model inference and Red Team remain unchanged. Added synthetic regression tests and Windows research-only usage documentation.
- **At writing:** final PR-head Python 3.12.9 CI, merge, post-merge CI and Windows laptop acceptance are **not verified**. This is a manually selected research hypothesis, NOT live detection, a trusted Zeek model, an operational AI alert, verified attack or genuine detection performance.
- Next: verify CI and merge only if green; student must collect authorized Host-only logs, independent labels and isolation evidence, run the preregistered held-out experiment once and manually validate the source-linked case and typed export on Windows. No test-set tuning.

## 2026-10-28: Offline research candidate manual SOC triage merged and verified (#77)

- [PR #77](https://github.com/tbao4151/DA_CNTT/pull/77) squash-merged as `17405ab1c586ca0950ac585f64608ea0c833121b`. Final-head [PR CI #40622139148](https://github.com/tbao4151/DA_CNTT/actions/runs/40622139148) and [post-merge main CI #40622287624](https://github.com/tbao4151/DA_CNTT/actions/runs/40622287624) both **passed** on Ubuntu Python 3.12.9: **416 passed, 2 skipped, 2 warnings** (existing pandas FutureWarnings).
- Added `src/blue_team_ai/research_triage.py` and an opt-in Blue Team UI action to select a predicted-Attack *research* candidate after revalidating the original Zeek bytes, private held-out trace, UID and threshold. Only a deliberate analyst click with confirmation creates a New/Unclassified case in the separate Cyber Lab SQLite store. Initial audit note includes source SHA-256, private trace SHA-256, UID, research probability and validation threshold; operator-supplied labels are not stored. Added backwards-compatible atomic optional initial note to shared SOC case creation and synthetic regression tests.
- No new AI inference, operational AI alert, live capture, Red Team execution, trusted model persistence or official UNSW benchmark change. The trace is mutable and its internal consistency does not authenticate model training, labels, or VMware isolation. Repeated explicit clicks can create duplicate manual cases.
- **Unverified:** actual student Windows/VMware Host-only run, authentic independently annotated logs, physical network isolation and measured attack detection. Next: student executes private preflight/holdout once, checks candidate-to-case and typed export locally, and preserves independent lab evidence. No tuning on held-out test.


## 2026-10-28: Atomic deduplication for explicit Zeek research cases (feature PR; CI pending)

- Inspected main at `aaa39bb7f4758269d24be7a574d10b7ba6286182`, merged PR #77/#78, no open PRs and green recent Python 3.12.9 CI. The current research candidate action could create duplicate Unclassified cases on repeated clicks.
- Added an **opt-in** SHA-256 source+Zeek-UID idempotency key for research-only case creation, using a lazily created SQLite key table and `BEGIN IMMEDIATE` to serialize concurrent duplicate submissions. Repeated validated selections reuse the first case and audit note; distinct source files remain distinct. Existing manual cases and Dataset Mode callers omit the key and retain prior behavior.
- Updated the Blue Team UI and private experiment documentation. Added synthetic-only tests for repeated/revised traces, distinct source, legacy manual duplicates, invalid keys and concurrent clicks.
- **At writing:** feature branch/PR CI, merge, post-merge CI and Windows/VMware acceptance have not been verified. No model deployment, new AI detection, network capture, automatic alert, Red Team traffic or UNSW benchmark change. Student must still provide genuine authorized Host-only capture, independently verified labels and isolation evidence.


## 2026-10-28: Research SOC case idempotency merged and CI verified (#79)

- [PR #79](https://github.com/tbao4151/DA_CNTT/pull/79) squash-merged as `5fd4c36ecc56af0197b391db0fb6072bd23b7927`. Final-head [PR CI #40624830622](https://github.com/tbao4151/DA_CNTT/actions/runs/40624830622) and [post-merge main CI #40625031675](https://github.com/tbao4151/DA_CNTT/actions/runs/40625031675) **both passed** on Ubuntu Python 3.12.9: **421 passed, 2 skipped, 2 warnings** (existing pandas FutureWarnings).
- Opt-in research-only SHA-256 source+Zeek-UID idempotency key is stored in a lazily created SQLite table; an immediate write transaction serializes concurrent lookup/insert. Repeated validated clicks (even if a different consistent research trace is supplied) return the first Unclassified case without duplicating its initial audit. Ordinary manual case creation remains non-deduplicated; Dataset Mode benchmark/DB semantics unchanged.
- New regression tests use **synthetic Zeek fixtures**, not genuine Windows VMware captures. This change does not authenticate labels, traces or model training, perform inference, produce automatic alerts, or generate traffic. Student Windows/VMware Host-only acceptance and real detection evidence remain unverified.
- Next: collect authorized Host-only Zeek logs with independently documented labels and preserved source hashes, run private held-out trace review once, and verify duplicate-click behavior on Windows. Never treat a held-out research trace as an operational AI alert.


## 2026-10-28: Private held-out trace source-set guard (feature PR, verification pending)

- Read current main `a21de0598af53a47125ebd2cea3ac31174ff5c8d`, PR #80 merged, no open PRs; latest relevant PR/main quality gates passed. No student Windows/VMware evidence verified.
- Hardened `src/blue_team_ai/trace_review.py`: the private research trace must match the declared held-out test source SHA-256 set and total flow count from the aggregate experiment provenance, with strict schema/count validation. The original supplied log is still matched by SHA-256 and exact UID coverage.
- Updated synthetic fixtures and regression cases for missing/forged sources, duplicate source, incorrect counts and schema mismatch; documented the research-only limitation.
- **At writing:** feature PR CI, merge and Windows acceptance have not been verified. This is internal consistency, not a signed model, authenticated labels, genuine VMware capture, real attack detection or operational AI alert. Dataset Mode and Red Team remain unchanged.

- First PR CI [#40628483916](https://github.com/tbao4151/DA_CNTT/actions/runs/40628483916) **failed** (1 failed, 427 passed, 2 skipped): a synthetic test changed the original capture and trace digest but not the newly required aggregate test provenance digest. Updated that test fixture in follow-up commit; final-head CI must pass before merge.


## 2026-10-28: Held-out private trace provenance guard merged and verified (#81)

- [PR #81](https://github.com/tbao4151/DA_CNTT/pull/81) squash-merged as `df30233f50786790a8f2bce8aca5ede376b0d86a`. Final-head [PR CI #40628673416](https://github.com/tbao4151/DA_CNTT/actions/runs/40628673416) and [post-merge main CI #40628781898](https://github.com/tbao4151/DA_CNTT/actions/runs/40628781898) **passed** on Ubuntu Python 3.12.9: **428 passed, 2 skipped, 2 warnings** (existing pandas FutureWarnings). The initial failing CI and subsequent fixture correction remain recorded above.
- Research trace review now checks exact source SHA-256 set and total flow count against declared held-out test provenance, in addition to original uploaded source/UID matching. Tests use synthetic fixtures only. No model authenticity, genuine VMware isolation, independent label truth, new-log inference or operational alert verified.
- Student Windows/VMware Host-only acceptance is still outstanding; do not tune on held-out test or upload private logs/traces to GitHub.


## 2026-10-28: Private data-only Zeek model export (feature branch; CI pending)

- Reviewed current `main` after merged PR #81/#82; no open PRs, latest main Python 3.12.9 CI passed (428 passed, 2 skipped). Chose a narrowly scoped **offline research model export**, not live inference or another UI mockup.
- Refactored the existing Zeek Logistic Regression baseline to share the identical TRAIN-only preprocessing/classifier construction. Added `src/blue_team_ai/model_artifact.py` with bounded, versioned **JSON-only** coefficients, categorical contributions, numeric imputation/scaling statistics and a validation-locked threshold. No pickle/joblib deserialization. Added deterministic internal scorer and synthetic comparisons against the real scikit-learn pipeline, including unseen categories and missing values.
- Added `scripts/export_zeek_model.py`: explicit `--cidr` screen of every manifest capture, private output path outside Git, exclusive new-file creation, printed artifact SHA-256; **TEST is not scored** by this exporter. See `docs/ZEEK_PRIVATE_MODEL_EXPORT.md`.
- **At writing:** PR-head CI, merge, post-merge CI and student Windows acceptance are pending. No independently authenticated label truth, genuine VMware capture, deployable trusted loader, fresh-log CLI, operational alerts, active Red Team or changes to the official UNSW-NB15 benchmark. A JSON checksum without an independently trusted reference is not an authenticity signature.
- Next: verify CI before merge. Student collects authorized Host-only logs and independent labels, records model SHA-256 privately, checks Windows export; next feature should implement expected-digest verification and new-log offline inference without consulting TEST labels.


## 2026-10-28: Private Zeek JSON model export merged and CI verified (#83)

- [PR #83](https://github.com/tbao4151/DA_CNTT/pull/83) squash-merged as `8f97dd8fb96dd14753c4761d145b23fe7219f9dc`. Final-head [PR CI #40630943857](https://github.com/tbao4151/DA_CNTT/actions/runs/40630943857) and [post-merge main CI #40631126434](https://github.com/tbao4151/DA_CNTT/actions/runs/40631126434) **passed** on Ubuntu Python 3.12.9: **442 passed, 2 skipped, 2 warnings** (existing pandas FutureWarnings).
- Added `src/blue_team_ai/model_artifact.py`, `scripts/export_zeek_model.py`, `tests/test_zeek_model_artifact.py`, and `docs/ZEEK_PRIVATE_MODEL_EXPORT.md`. Synthetic tests compare JSON-only LR scores against fitted scikit-learn probabilities. TRAIN fits; VALIDATION selects threshold; TEST is not scored in this export. CIDR screening is explicitly required, output is private/new-file only, and CLI prints SHA-256 for separate recording.
- **Not verified:** student Windows/VMware Host-only run, independent label truth, real detection performance, artifact authenticity against a trusted external reference, fresh-log inference, operational AI alerts or Red Team traffic. No changes to official UNSW-NB15 benchmark. Next: expected-digest verifier and controlled new-log offline inference, after student evidence; never treat JSON-only research export as deployed detector.


## 2026-10-28: Independently pinned private Zeek JSON loader (feature PR, CI pending)

- Read current `main` at `f3eb852897740d9acbe79d92e74e51d197af74c4` after merged PR #83/#84, with no open PRs. Latest verified PR #84 CI #40631326139 passed; post-merge CI for #84 was not confirmed.
- Added `src/blue_team_ai/trusted_model.py`: bounded 2 MiB read-only loader, explicit independently recorded lowercase SHA-256 comparison **before parsing**, strict JSON duplicate-key/NaN/UTF-8 rejection and existing exact artifact/schema validation. Added `scripts/verify_zeek_model.py` for private Windows verification and synthetic regression tests.
- This is a **byte-integrity gate against an independently pinned reference**, not digital signing or authorship verification. No fresh-log inference, test scoring, automatic AI alerts, SOC writes, network traffic, Red Team execution, or UNSW benchmark changes.
- At writing, feature PR CI/merge/post-merge CI and student Windows/VMware acceptance remain unverified. Next: verify CI before merge; student preserves original Host-only captures, independent labels and model digest outside Git; next slice can add bounded **new-log offline inference** using this gate, without tuning on held-out TEST.


## 2026-10-28: Pinned private Zeek JSON verifier merged, CI verified (#85)

- [PR #85](https://github.com/tbao4151/DA_CNTT/pull/85) squash-merged as `5721004aa3e233fe6f1e2bbf24967cd31cb5a7df`. Final-head [PR CI #40633769315](https://github.com/tbao4151/DA_CNTT/actions/runs/40633769315) and [post-merge main CI #40633974947](https://github.com/tbao4151/DA_CNTT/actions/runs/40633974947) both **passed** on Ubuntu Python 3.12.9; PR CI: **461 passed, 2 skipped, 2 warnings** (existing pandas FutureWarnings).
- The verifier requires an **independently pinned** exact SHA-256 and checks bytes before strict, bounded, duplicate-key-rejecting JSON/schema parsing. Read-only CLI is private/offline. All new tests are synthetic software regressions, not real Zeek detection evidence.
- Still **not verified**: student Windows/VMware Host-only run, independent labels, authentic model authorship, model generalization, new-log inference, operational AI alerts, or Red Team traffic. The model checksum is not a signature. No official UNSW-NB15 changes.


## 2026-10-28: Pinned-model inference on a NEW private Zeek log (feature PR; verification pending)

- Reviewed main at `7bb945667c99aa4664f7dec1ee4bf2c314ebf1ee`, README/PROGRESS/ROADMAP, Zeek parser/features/scope/model export/loader, recent Actions and open PRs (none at feature start). Latest prior PR #85 and post-merge main CI were green; #86 documentation PR CI was green. No verified student Windows/VMware capture exists.
- Added `src/blue_team_ai/new_log_inference.py` and `scripts/score_zeek_new_log.py`: strict, bounded, **offline** inference on a separately SHA-256-pinned new `conn.log` with independently pinned JSON Zeek research model, explicit RFC1918 CIDR screen, unique UID check, and rejection of TRAIN/VALIDATION source reuse. Keeps model/capture private and read-only, writes a new private JSON with actual source UID/time/IP and research probabilities; no labels, no model fitting, no network, no SOC writes or operational alerts.
- Added synthetic regression tests and `docs/ZEEK_NEW_LOG_OFFLINE_INFERENCE.md`; no UNSW-NB15 benchmark change. The model JSON does not list held-out TEST sources, so the tool cannot prove the operator-supplied capture is not TEST. Report explicitly sets `test_partition_exclusion_verified=false`. CIDR membership is not VMware isolation proof; pinned SHA-256 is not a signature or independent ground-truth verification.
- **At writing:** feature PR CI, merge, post-merge CI and Windows acceptance are not verified. Next: inspect CI; merge only if green and conflict-free. Student must independently capture, label/evaluate and preserve Host-only evidence and run the new CLI on a genuinely new capture; do not describe synthetic predictions as detection performance.

## 2026-10-28: Pinned new-log offline research inference merged and verified (#87)

- [PR #87](https://github.com/tbao4151/DA_CNTT/pull/87) squash-merged as `8f97cf9644751354c1ae85ca977a16e78c2f8a5b`. Final-head [PR CI #40636266361](https://github.com/tbao4151/DA_CNTT/actions/runs/40636266361) and [post-merge main CI #40636462691](https://github.com/tbao4151/DA_CNTT/actions/runs/40636462691) both **passed** on Ubuntu Python 3.12.9. PR test summary: **464 passed, 2 skipped, 2 warnings** (existing pandas FutureWarnings).
- `src/blue_team_ai/new_log_inference.py` and `scripts/score_zeek_new_log.py` score a separately SHA-256-pinned **new** private Zeek ASCII `conn.log` with the separately pinned JSON research model, declared CIDR scope, unique UID and no TRAIN/VALIDATION source reuse. New private JSON includes original event timestamps/IPs/UIDs and research candidates, not labels or operational alerts. Synthetic-only regression tests and Windows instructions are in `tests/test_zeek_new_log_inference.py` and `docs/ZEEK_NEW_LOG_OFFLINE_INFERENCE.md`.
- **Not verified:** genuine student Windows/VMware Host-only run, independent ground truth, authentic model authorship, physical isolation, generalization or operational detection. The tool cannot prove the capture is not reserved held-out TEST; report explicitly records `test_partition_exclusion_verified=false`. No live traffic, Red Team execution, automated alert, SOC case write or official UNSW benchmark change.
- Next: student independently preserves isolation and new-capture/model SHA-256 evidence, verifies capture is outside all three research splits, runs private CLI and reviews results. Further AI-to-SOC automation must await credible independently labeled evaluation.


## 2026-10-28: Pinned new-log research report consistency review (feature PR; CI pending)

- Reviewed main at `c5b07c2b4ebaeb9dd7c732bf0c7ac801ff8de2fa`, README/PROGRESS/ROADMAP, architecture, recent CI and open PRs (none at start). Existing #87 new-log offline scorer and #88 documentation are merged; most recent checked CI was successful.
- Added `src/blue_team_ai/new_log_review.py` and `scripts/verify_zeek_new_log_report.py`: **read-only** private verification that independently re-scores a separately SHA-256-pinned original Zeek capture with the separately pinned data-only model, then compares every field and every prediction to the saved JSON. Refuses duplicate JSON keys, nonfinite values, malformed input, altered probabilities/endpoints/timestamps/flags, and oversize reports.
- Added synthetic regression tests in `tests/test_zeek_new_log_review.py` and Windows instructions in `docs/ZEEK_NEW_LOG_REPORT_REVIEW.md`. No model fitting, labels, network traffic, operational alerts, SOC writes, changes to Red Team or UNSW-NB15 benchmark.
- **At writing:** PR CI/merge/post-merge CI and Windows/VMware acceptance are pending. Passing report consistency is not independent model authorship, capture authenticity, Host-only isolation, held-out TEST exclusion or verified attack detection. Next: inspect PR CI and merge only if green and conflict-free; student independently records original capture/model hashes, isolation screenshots, scenario evidence and genuine holdout labels.


## 2026-10-28: Private new-log report verification merged and CI verified (#89)

- [PR #89](https://github.com/tbao4151/DA_CNTT/pull/89) squash-merged as `0eb0140c1dbd27ff3d98ef659d35c634861d74ad`. Final-head [PR CI #40639277298](https://github.com/tbao4151/DA_CNTT/actions/runs/40639277298) and [post-merge main CI #40639475020](https://github.com/tbao4151/DA_CNTT/actions/runs/40639475020) both **passed** on Ubuntu Python 3.12.9; PR CI: **486 passed, 2 skipped, 2 warnings** (existing pandas FutureWarnings).
- Added `src/blue_team_ai/new_log_review.py`, `scripts/verify_zeek_new_log_report.py`, `tests/test_zeek_new_log_review.py` and `docs/ZEEK_NEW_LOG_REPORT_REVIEW.md`. Recomputes every private research prediction from separately pinned original capture and model; refuses altered reports, unsafe JSON and nonprivate paths. Read-only, no SOC writes or network.
- Synthetic-only CI is **not** student Windows/VMware Host-only acceptance, authenticated source/labels, held-out TEST exclusion, trustworthy model authorship or real attack detection. No UNSW benchmark change. Next: student captures new authorized Zeek logs and independently preserves SHA-256, network isolation and label evidence; then consider strictly manual SOC review only after genuine lab evaluation.


## 2026-10-28: Explicit pinned NEW-log research SOC triage (feature branch; CI pending)

- Reviewed `main` at `feedd1f231f1768d0d78e7aa1047cc5738793dc7`, README/PROGRESS/ROADMAP, current Zeek model/new-log verifier, SOC case code, PRs (none open) and recent Actions. PR #89 and #90 were merged; PR #90 final-head CI passed, but its post-merge main CI was not observed at feature start.
- Added `src/blue_team_ai/new_log_triage.py` and `scripts/triage_zeek_new_log.py`: read-only candidate listing, then explicit opt-in **Unclassified** SOC research case creation for a selected new-log candidate. Re-verifies the entire report against separately pinned original log/model at write time; retains source/model/report/scope SHA-256, Zeek UID, score and threshold in bounded audit notes; reuses the existing atomic source+UID research deduplication key. A private SQLite destination outside Git is mandatory for the CLI write.
- Added synthetic-only regression tests and `docs/ZEEK_NEW_LOG_MANUAL_SOC_TRIAGE.md` with Windows steps. No network capture, Red Team execution, automatic AI alert, verified attack verdict, label evaluation, model fitting, or UNSW-NB15 benchmark change.
- **At writing:** final-head PR CI, merge and post-merge CI are pending. Student Windows/VMware Host-only acceptance, independent ground-truth labels, actual isolation, model authorship and exclusion from reserved TEST remain **unverified**; CLI confirmation flags are operator attestations only. Next: inspect CI before any merge, then run with private real lab evidence and independently recorded hashes.


## 2026-10-28: Explicit pinned NEW-log manual SOC triage merged and CI verified (#91)

- [PR #91](https://github.com/tbao4151/DA_CNTT/pull/91) squash-merged as `c2c7308acb6ea210adda4720a1391311b94dfa1b`. Final-head [PR CI #40642225873](https://github.com/tbao4151/DA_CNTT/actions/runs/40642225873) and [post-merge main CI #40642495700](https://github.com/tbao4151/DA_CNTT/actions/runs/40642495700) both **passed** on Ubuntu Python 3.12.9; PR suite **503 passed, 2 skipped, 2 warnings** (existing pandas FutureWarnings). No concurrent open PR at merge time; GitHub reported a clean merge.
- Implemented `src/blue_team_ai/new_log_triage.py`, `scripts/triage_zeek_new_log.py`, `tests/test_zeek_new_log_triage.py`, and `docs/ZEEK_NEW_LOG_MANUAL_SOC_TRIAGE.md`. Offline, read-only listing and opt-in manual `Unclassified` case creation recheck pinned original capture/model/report and enforce existing source+UID research idempotency. Synthetic tests cover tampering, consent, scope, concurrent requests and CLI behavior.
- **Not verified:** any student Windows/VMware Host-only run, independent ground-truth labels, true lab isolation, held-out TEST exclusion, model authorship or real attack detection. CLI flags are operator attestations only. No automatic alert, active Red Team, network capture or official UNSW-NB15 benchmark change. Next: student captures genuine authorized data, documents isolation and private hashes, and validates case export on Windows before claiming an end-to-end lab result.


## 2026-10-28: Pinned declared TRAIN/VALIDATION/TEST non-reuse preflight (feature PR; CI pending)

- Reviewed current main `3edc3690c0a34e1e2518706e46ae251bbab22233`, README, PROGRESS, ROADMAP, architecture, existing Zeek new-log scorer, experiment manifest loader, #91/#92 and recent green Actions; no open PR at feature start.
- Added `src/blue_team_ai/partition_guard.py` and `scripts/check_zeek_partition_exclusion.py`: read-only, offline private preflight requiring separately pinned model/manifest/new-log SHA-256. It verifies original declared experiment capture bytes, annotations, host-disjoint partitions, model-manifest link, TRAIN/VALIDATION source correspondence, declared RFC1918 scope, and refuses exact-byte reuse of **held-out TEST** as well as TRAIN/VALIDATION.
- Added synthetic-only regression tests and `docs/ZEEK_PARTITION_GUARD.md`. Does not change model scoring, existing report format, SQLite, Red Team or official UNSW-NB15 benchmark. It cannot prove the operator's manifest was preregistered, that differently encoded flows were not reused, that labels are true or that VMware was physically isolated.
- [PR #93](https://github.com/tbao4151/DA_CNTT/pull/93) squash-merged as `e05ee751ac298b8bb57cd2975fdfb5a5805e5525`. Final-head [PR CI #40645100893](https://github.com/tbao4151/DA_CNTT/actions/runs/40645100893) and [post-merge main CI #40645382107](https://github.com/tbao4151/DA_CNTT/actions/runs/40645382107) **passed** on Ubuntu Python 3.12.9: **508 passed, 2 skipped, 2 existing pandas warnings**. Student Windows/VMware acceptance remains unverified. Student must preserve a genuinely pre-registered manifest and independently recorded digests, run the private CLI on an authorized NEW capture, and retain isolation/label evidence. Existing inference report continues to say `test_partition_exclusion_verified=false`.


## 2026-10-28: Optional pinned partition gate for NEW-log manual SOC triage (feature PR; CI pending)

- Reviewed `main` at `5fb75727553dc18d2b6c25005b6f75f27d5fea27`, README/PROGRESS/ROADMAP, source tree, existing manual triage and declared-partition verifier, recent green CI (#93/#94), and confirmed no open PRs before starting this feature.
- Added optional `--manifest` + independently pinned `--expected-manifest-sha256` to `scripts/triage_zeek_new_log.py`. When provided, the CLI checks all original declared TRAIN/VALIDATION/TEST capture bytes, labels, host-disjoint partitions, scope and model provenance before listing or writing a case; the write API rechecks the declared partition guard before SQLite changes. The legacy CLI remains usable but reports unverified declared TEST exclusion.
- Added synthetic-only regressions in `tests/test_zeek_new_log_partition_triage.py` for valid pinned listing/write, reserved TEST byte reuse, bad/missing pins, idempotency and direct write-boundary refusal. Updated private Windows guidance. No live capture, automatic alert, attack verdict, Red Team traffic, official UNSW benchmark change or verified student experiment.
- **At writing:** PR CI/merge and post-merge CI are unverified; only mark green after inspecting GitHub Actions. Exact-byte non-reuse depends on the completeness and historical accuracy of the operator's original manifest; no semantic non-reuse, genuine label truth or VMware isolation proof.


## 2026-10-28: Pinned manual NEW-log partition gate merged, CI verified (#95)

- [PR #95](https://github.com/tbao4151/DA_CNTT/pull/95) squash-merged as `508837164acba4b9b7cfb212a4dd57cf7053db2c`. Final-head [PR CI #40649157211](https://github.com/tbao4151/DA_CNTT/actions/runs/40649157211) and [post-merge main CI #40649354908](https://github.com/tbao4151/DA_CNTT/actions/runs/40649354908) both **passed** on Ubuntu Python 3.12.9; final PR CI **514 passed, 2 skipped, 2 existing pandas warnings**. Early intermediate-commit runs failed and were corrected before the green final-head merge.
- `scripts/triage_zeek_new_log.py` now optionally validates a separately SHA-256-pinned original experiment manifest and every declared TRAIN/VALIDATION/TEST capture before listing or manually creating an `Unclassified` case; `src/blue_team_ai/new_log_triage.py` rechecks the declared partition guard at the write boundary. Omission remains explicitly labeled unverified for backward compatibility. Synthetic regression tests and private Windows guidance were added.
- No verified student Windows/VMware Host-only capture, independent labels, semantic non-reuse, model authorship, operational AI alert or real detection accuracy. Original UNSW benchmark, Red Team traffic and live collection are unchanged. Next: student retains and tests genuine private preregistered manifest, original logs/annotations, independently pinned hashes and isolation evidence on Windows.


## 2026-10-28: Conservative normalized Zeek flow identity non-reuse screen (feature PR; CI pending)

- Reviewed main at `abed1930bd0ceba924b1b8f7773dfcb67996927e`, README/PROGRESS/ROADMAP, repository tree, recent successful #95/#96 Actions and open PRs (none at feature start). Existing optional pinned manifest triage and read-only preflight only rejected exact-byte source reuse.
- Extended `src/blue_team_ai/partition_guard.py` with an optional original-capture/new-bytes screen: reject reuse of a normalized Zeek UID + UTC timestamp + source/destination IP/port + protocol identity even when the file header/comment bytes differ. Validate original source coverage against the already checked TRAIN/VALIDATION/TEST dataset. Both `scripts/check_zeek_partition_exclusion.py` and the pinned-manifest `scripts/triage_zeek_new_log.py` now supply the original bytes; `src/blue_team_ai/new_log_triage.py` rechecks before an explicit manual SQLite case write. Legacy library callers without bytes remain exact-byte-only and are labeled accordingly.
- Added synthetic regression tests in `tests/test_zeek_flow_identity_guard.py` for re-encoded held-out TEST reuse, missing originals, source mismatch, safe read-only output and no-write manual triage refusal. Updated private Windows instructions. No new traffic, model fitting, automatic SOC alerts, Red Team execution, official UNSW benchmark change or genuine lab result.
- **At writing:** feature PR CI/merge/post-merge CI and student Windows/VMware acceptance are **not verified**. This narrow identity screen can miss flows whose UID/time/endpoints change and can reject coincidental matches; it cannot establish complete partition history, authentic labels, physical isolation or real detection accuracy. Next: inspect CI before merge, then student independently collects genuine authorized Host-only evidence and runs the private preflight and manual triage checks on Windows.


## 2026-10-28: Normalized flow identity non-reuse screen merged, CI verified (#97)

- [PR #97](https://github.com/tbao4151/DA_CNTT/pull/97) squash-merged as `5bf30ae2d911326710430d3d96b5c170c63734c5`. Final-head [PR CI #40652526062](https://github.com/tbao4151/DA_CNTT/actions/runs/40652526062) and [post-merge main CI #40652861554](https://github.com/tbao4151/DA_CNTT/actions/runs/40652861554) both **passed** on Ubuntu Python 3.12.9. Final PR CI: **519 passed, 2 skipped, 2 existing pandas warnings**. Earlier intermediate commits failed on regression expectations; corrected before final-head merge.
- Pinned private preflight and optional manifest-backed manual triage now reject normalized UID/UTC timestamp/source-destination five-tuple overlaps with any original declared TRAIN/VALIDATION/TEST flow, even if log bytes differ due to re-encoding. The manual case API repeats the check before SQLite writes. Legacy library calls without original capture bytes remain exact-byte-only. Synthetic regressions cover re-encoded TEST reuse, private read-only refusal and manual no-write refusal.
- **Not verified:** genuine student Windows/VMware Host-only captures, independent ground-truth labels, complete semantic flow non-reuse, model authorship, physical isolation, operational AI alert or real detection accuracy. Original UNSW benchmark and Red Team active traffic unchanged. Next: student runs pinned preflight and manual SOC review on independently captured authorized Host-only evidence, preserving original raw logs, SHA-256, Zeek version, scenario notes and isolation screenshots privately.


## 2026-10-28: Pinned NEW-log Blue Team read-only UI (feature PR; CI pending)

- Reviewed main `dcddcc4caaf84077dddbd5f55905388107bd1fd8`, README, PROGRESS, ROADMAP, repository tree, Zeek model/review/triage code, recent Actions and open PRs (none at start). Existing #97 normalized identity guard and main CI were green; no concurrent feature PR was found.
- Added `src/blue_team_ai/new_log_workspace.py` and separate Streamlit `pages/3_New_Log_Review.py`: local read-only review of independently SHA-256-pinned private Zeek model/original NEW log/report. Recomputes and verifies the entire report, checks CIDR, and shows first-500-row research candidates with actual log endpoints/timestamps; never writes SQLite, sends traffic or creates an alert. Held-out research trace viewer and UNSW Dataset Mode remain unchanged.
- Added synthetic-only `tests/test_zeek_new_log_workspace.py` and `docs/ZEEK_NEW_LOG_BLUE_TEAM_UI.md`. This page **does not** run the pinned manifest partition gate; users must run the separate CLI before interpreting a NEW log. Model authorship, true labels, genuine Windows/VMware capture and isolation remain unverified.
- **At feature commit:** PR CI, merge and post-merge main CI not yet confirmed. No laptop experiment or scientific performance claim. Next: verify CI, then student runs private Windows acceptance and retains hashes, partition preflight, screenshots and original logs.


## 2026-10-28: Pinned NEW-log Blue Team read-only UI merged and CI verified (#99)

- [PR #99](https://github.com/tbao4151/DA_CNTT/pull/99) squash-merged as `314f6857858e41d43321b857ae44ede47db1527a`. Final-head [PR CI #40655024380](https://github.com/tbao4151/DA_CNTT/actions/runs/40655024380) and [post-merge main CI #40655340663](https://github.com/tbao4151/DA_CNTT/actions/runs/40655340663) both **passed** on Ubuntu Python 3.12.9. PR CI: **525 passed, 2 skipped, 2 existing pandas FutureWarnings**. No concurrent open PR or merge conflict at merge time.
- New `pages/3_New_Log_Review.py` and `src/blue_team_ai/new_log_workspace.py` provide **read-only** pinned NEW-log research prediction review on local Streamlit: private model path and independent model/log SHA-256, CIDR check, complete saved-report recomputation and bounded candidate table from original Zeek bytes. Synthetic regressions include invalid hash, tampered report, wrong CIDR and startup without fabricated predictions. Documentation: `docs/ZEEK_NEW_LOG_BLUE_TEAM_UI.md`.
- This UI **does not** enforce the separate original-manifest partition guard, write SOC cases, automatically alert, verify physical VMware isolation, prove model authorship or validate attack labels. Student must run the partition preflight and genuine Windows Host-only acceptance independently. No UNSW-NB15 benchmark or Red Team active traffic changes.


## 2026-10-28: Pinned NEW-log operator-labeled evaluation (feature PR; CI pending)

- Reviewed main at e3632ab52c5615e3b5a57d6e7a9efa3ab254aa21, README, PROGRESS, ROADMAP, full tree, recent green Actions and zero open PRs before starting. Existing #99 read-only UI and #97 partition guard remain unchanged.
- Added src/blue_team_ai/new_log_evaluation.py and scripts/evaluate_zeek_new_log_labels.py: read-only recomputation of a SHA-pinned NEW-log research prediction report, strict independent per-UID annotation SHA-256 and binary-label coverage, original manifest TRAIN/VALIDATION/TEST exclusion including conservative flow identity, aggregate TP/FP/TN/FN, Precision/Recall/F1/FPR and descriptive Wilson intervals. Never retrains or selects threshold, writes SOC, or sends network traffic.
- Added synthetic-only tests/test_zeek_new_log_evaluation.py and docs/ZEEK_NEW_LOG_LABELED_EVALUATION.md. At feature commit, PR CI/merge and post-merge CI remain unverified; do not report passing until Actions confirms.
- No student Windows/VMware evidence, authenticated label truth, complete independent partition history, detection latency or operational attack detection. This is descriptive agreement with operator-supplied labels, not a measured real attack detection claim. Preserve original UNSW benchmark and Red Team safe-off state.


## 2026-10-28: NEW-log operator-labeled evaluation merged and CI verified (#101)

- [PR #101](https://github.com/tbao4151/DA_CNTT/pull/101) squash-merged as eeda3e573920f7eca692813a3d32755d51567dd0. Final-head [CI #40658718042](https://github.com/tbao4151/DA_CNTT/actions/runs/40658718042) and post-merge main [CI #40659083844](https://github.com/tbao4151/DA_CNTT/actions/runs/40659083844) both passed on Ubuntu Python 3.12.9; final-head test result: 537 passed, 2 skipped, 2 existing pandas warnings.
- Read-only src/blue_team_ai/new_log_evaluation.py and scripts/evaluate_zeek_new_log_labels.py verify independently pinned model, original NEW log, prediction report, annotation JSON and original TRAIN/VALIDATION/TEST manifest with conservative normalized flow identity non-reuse, then compute aggregate TP/FP/TN/FN, Precision/Recall/F1/FPR and descriptive Wilson intervals against **operator-supplied labels only**. No fitting, threshold selection, SOC write, active traffic, or operational alert.
- All regression fixtures synthetic; no student Windows/VMware capture, independently authenticated label truth, complete partition history, physical isolation, latency measurement or real attack detection is verified. The operator must run and archive private Windows evidence and avoid model/threshold tuning on this evaluation data.


## 2026-10-28: Mandatory declared-partition preflight for NEW-log Blue Team UI (feature branch; CI pending)

- Reviewed main `9c73f2abc9de732f36fb9b3c4c012288f7812bdb`, README/PROGRESS/ROADMAP, repository tree, no open PRs, and recent successful #101/#102 Actions before implementation. Existing manual CLI already enforced a pinned manifest; the read-only Streamlit NEW-log UI did not.
- Extended `src/blue_team_ai/new_log_workspace.py` with optional, all-or-none original dataset/manifest/captures inputs for backward-compatible callers. When supplied, it checks declared TRAIN/VALIDATION/TEST exact-byte non-reuse and conservative normalized UID/UTC timestamp/five-tuple overlap before returning any candidate rows.
- `pages/3_New_Log_Review.py` now **requires** an independently pinned private manifest path and SHA-256, loads original captures and annotations with the existing bounded loader, verifies manifest consistency and passes the validated dataset/captures to the workspace. Missing/mismatched evidence refuses the review. Existing CLI, Dataset Mode, Red Team safe-off and model threshold are unchanged.
- Added synthetic-only regression tests for accepted NEW log, missing/incorrect manifest evidence, exact TEST reuse, re-encoded TEST flow overlap and Streamlit startup. Updated `docs/ZEEK_NEW_LOG_BLUE_TEAM_UI.md`.
- **At feature commit:** PR CI, merge and post-merge CI are not yet verified. No student Windows/VMware Host-only experiment, authenticated ground truth, independent complete capture history, physical isolation or operational attack detection is claimed. The manifest is operator-supplied; normalized flow screening is conservative and can miss semantically reused flows with changed identity fields.


## 2026-10-28: NEW-log Blue Team UI mandatory pinned partition gate merged and CI verified (#103)

- [PR #103](https://github.com/tbao4151/DA_CNTT/pull/103) squash-merged as `292bd2f8af1f31a81397e160515e4bcc184816f6`. Final-head [PR CI #40661904366](https://github.com/tbao4151/DA_CNTT/actions/runs/40661904366) and [post-merge main CI #40662219929](https://github.com/tbao4151/DA_CNTT/actions/runs/40662219929) **passed** on Ubuntu Python 3.12.9. Final PR suite: **545 passed, 2 skipped, 2 existing pandas warnings**.
- `pages/3_New_Log_Review.py` now requires a private SHA-256-pinned original TRAIN/VALIDATION/TEST manifest and all declared captures/annotations before displaying research predictions. The workspace reuses existing exact-byte and conservative normalized UID/time/five-tuple non-reuse guards; incomplete/mismatched evidence fails closed. Legacy library callers without declared evidence remain supported and must not claim partition verification.
- New synthetic regressions include valid new capture, partial/incorrect manifest evidence, exact reserved TEST reuse, re-encoded reserved TEST flow identity overlap and Streamlit smoke. No SQLite write, live traffic, Red Team execution, automatic SOC alert or change to official UNSW benchmark.
- **Not verified:** student Windows/VMware capture, physical Host-only isolation, independently authenticated label truth, complete historical/semantic partition independence, operational detection accuracy or measured latency. Next: student private Windows acceptance with genuine evidence; later UI manual SOC case write must recheck pinned manifest at the SQLite boundary.


## 2026-10-28: Pinned NEW-log offline batch scoring runtime merged and CI verified (#105)

- Reviewed main at `82f44b9bed0d6b92300defa870644db03af0cce6`, README/PROGRESS/ROADMAP, full tree, latest green Actions and zero open PRs before changes. Existing pinned manifest UI (#103/#104), operator-labeled evaluation (#101), and official UNSW baseline are unchanged.
- Added `src/blue_team_ai/runtime_benchmark.py` and `scripts/benchmark_zeek_new_log_runtime.py`: require independently pinned private model, original TRAIN/VALIDATION/TEST manifest/captures and NEW log; reject declared byte/normalized-flow reuse, validate CIDR, then time bounded repeated whole-log in-memory parsing/features/scoring with `perf_counter_ns`. Aggregate median, nearest-rank p95 and batch throughput only; no private UIDs/IPs, model fitting, SQLite, network or automatic alerts.
- Added synthetic-only regression `tests/test_zeek_new_log_runtime.py` and private Windows protocol `docs/ZEEK_NEW_LOG_RUNTIME_BENCHMARK.md`. [PR #105](https://github.com/tbao4151/DA_CNTT/pull/105) squash-merged as `6d96cfea3cb055b6a3b0b4cd626faf6dc1d11483`. Final-head [CI #40665921468](https://github.com/tbao4151/DA_CNTT/actions/runs/40665921468) and post-merge main [CI #40666245219](https://github.com/tbao4151/DA_CNTT/actions/runs/40666245219) **passed** on Ubuntu Python 3.12.9; final-head suite **558 passed, 2 skipped, 2 existing pandas warnings**. Student Windows/VMware acceptance remains unverified. This measures offline batch computation only, NOT event-to-detection or capture-to-alert latency. Independent capture provenance, physical isolation, label truth and real detection accuracy remain unverified.

## 2026-10-28: Optional analyst-confirmed NEW-log UI SOC case (feature branch; CI pending)

- Inspected current main, README/PROGRESS/ROADMAP, source tree, existing manual CLI triage, pinned NEW-log UI, open PRs (none) and recent successful Actions before editing. Existing Dataset Mode and Red Team safe-off are unchanged.
- Added `create_ui_candidate_case` in `scripts/triage_zeek_new_log.py`: a bounded, explicitly consented UI write boundary reopens private pinned model/manifest, verifies original TRAIN/VALIDATION/TEST captures and labels, rechecks source/model/report hashes, CIDR and normalized flow identity non-reuse, then calls existing idempotent Unclassified SOC triage. Refuses Git-tracked SQLite destinations. Does not send traffic or create operational alerts.
- Extended `pages/3_New_Log_Review.py` with candidate selection by original Zeek row, three operator confirmations and a private SQLite destination; no case is created merely by displaying candidates. Added synthetic-only `tests/test_zeek_new_log_ui_soc.py` and updated Windows instructions.
- **At feature branch commit:** GitHub Actions PR CI and merge are not yet verified. No Windows/VMware Host-only experiment, authentic label truth, full partition history, actual detection latency or real attack detection is claimed. Manual research cases remain Unclassified; prior preview is reverified at write time.

## 2026-10-28: NEW-log UI manual Unclassified SOC triage merged (#107)

- [PR #107](https://github.com/tbao4151/DA_CNTT/pull/107) squash-merged as `bb70db6b2f6f548743cf4d01cb212196a824f2e9`. Final-head [PR CI #40670039543](https://github.com/tbao4151/DA_CNTT/actions/runs/40670039543) **passed** on Ubuntu Python 3.12.9: **566 passed, 2 skipped, 2 existing pandas FutureWarnings**. [Post-merge main CI #40670441897](https://github.com/tbao4151/DA_CNTT/actions/runs/40670441897) also **passed** on Ubuntu Python 3.12.9.
- The optional Streamlit action selects a verified research candidate by original Zeek row, requires three explicit analyst attestations and private SQLite outside Git, and reopens independently pinned model/manifest with original captures/labels at write time. The existing manual SOC core recomputes all report predictions, rechecks CIDR, exact-byte and normalized flow overlap and atomically reuses a source+UID Unclassified case. No operational alert or automatic attack confirmation.
- Synthetic-only software tests; no student Windows/VMware capture, independently authenticated attack labels, physical isolation, complete partition history or event-to-alert latency is verified. The Dataset Mode UNSW benchmark and Red Team safe-off are unchanged.


## 2026-10-28: Private Windows/VMware capture evidence inventory (feature PR, CI pending)

- Inspected current main at `9cbc210281198fbeb0d23251df17b7a2c5b6ed84`, README/PROGRESS/ROADMAP, tree, recent successful CI and no open PRs before this slice. Existing NEW-log UI manual Unclassified SOC triage (#107) remains unchanged.
- Added `src/blue_team_ai/capture_evidence.py` and `scripts/record_zeek_lab_capture.py`: a bounded **offline** private evidence inventory requiring an independently recorded original Zeek log SHA-256, declared CIDR/origin, two original screenshots, saved Zeek version output and scenario notebook. Verifies source bytes and declared IP scope; writes a new JSON outside Git with only hashes/sizes/aggregate timestamps and explicit unverified flags. No packet capture, active traffic, model fitting, labels, SOC writes or operational alert.
- Added synthetic-only `tests/test_zeek_capture_evidence.py` and Windows runbook `docs/WINDOWS_VMWARE_CAPTURE_EVIDENCE.md`. **Feature PR CI/merge are pending at the time of this entry.** No student Windows/VMware capture, physical isolation, independent label truth or detection performance is verified.
- Next: verify CI and merge only if green/no conflict; student must gather real authorized Host-only original evidence privately, record hashes independently, run this CLI and then execute the existing labeled evaluation protocol. This inventory cannot authenticate operator-supplied screenshots or scenario claims.


## 2026-10-28: Private capture evidence inventory merged and PR CI verified (#109)

- [PR #109](https://github.com/tbao4151/DA_CNTT/pull/109) squash-merged as `97addb92256133d937434ccff349bffa7a6ff4d8`. Final-head [PR CI #40674392574](https://github.com/tbao4151/DA_CNTT/actions/runs/40674392574) **passed** on Ubuntu Python 3.12.9: **575 passed, 2 skipped, 2 existing warnings**. Post-merge [main CI #40674810882](https://github.com/tbao4151/DA_CNTT/actions/runs/40674810882) started; its final result was not verified when this entry was written.
- New private offline capture evidence inventory requires original Zeek SHA-256, declared CIDR/origin, two supporting screenshots, Zeek version and scenario notes; emits hashes/sizes and bounded Zeek aggregate metadata only. No network operation, inference, SOC write or attack claim. Original UNSW benchmark and Red Team safe-off are unchanged.
- Tests use synthetic fixtures only; no student-owned VMware Host-only capture, physical isolation, authentic scenario labels, local Windows run or end-to-end detection is verified. Next: collect private evidence and run `docs/WINDOWS_VMWARE_CAPTURE_EVIDENCE.md` on the student's Windows machine, then proceed to independent labeled evaluation.


## 2026-10-28: Private NEW-log SOC read-only history browser (feature PR; CI pending)

- Reviewed `main` at `ca5a46a793e6f5939ab0234a0faebe350c6502e6`, README/PROGRESS/ROADMAP, existing UI/manual triage, source tree, latest green Actions and zero open PRs. Previous private capture inventory PR #109/#110 was already merged; no overlap with its files.
- Added `src/blue_team_ai/case_workspace.py`: strictly read-only SQLite URI/query-only access to existing private `.sqlite3` outside Git, bounded Zeek Unclassified case index and case/evidence/audit snapshot with explicit truncation metadata. No database creation, schema updates, SOC state changes, model inference, network or alert emission.
- Extended `pages/3_New_Log_Review.py` with an optional independent SOC evidence/audit viewer and private JSON snapshot download; added synthetic SQLite regression `tests/test_zeek_case_workspace.py` and Windows instructions. Locally verified the isolated helper tests with Python 3.13.5: **4 passed**; this is not the pinned 3.12.9 CI or Windows/VMware evidence.
- **At feature commit:** PR CI and merge are pending. Existing Dataset Mode UNSW baseline, research model, Red Team safe-off and private cases are untouched. Snapshot is editable SQLite evidence, not signed forensic proof; genuine Windows Host-only capture, isolation, labels and attack-detection performance remain unverified.


## 2026-10-28: Private Zeek SOC read-only case browser merged (#111)

- [PR #111](https://github.com/tbao4151/DA_CNTT/pull/111) squash-merged as `b858b15c67842ea8fad80adfa4e4348a5bf91992`. Final-head [PR CI #40677916507](https://github.com/tbao4151/DA_CNTT/actions/runs/40677916507) **passed** on Ubuntu Python 3.12.9: **579 passed, 2 skipped, 2 existing pandas warnings**. Post-merge main CI [#40678349785](https://github.com/tbao4151/DA_CNTT/actions/runs/40678349785) was queued when this note was drafted; verify its final result separately.
- The independent Blue Team viewer opens only an existing private offline Zeek Unclassified SQLite case DB in read-only mode, bounds the index/history, displays stored flow evidence and audit, and exports a private JSON snapshot. No case/DB writes, model changes, operational alerts, traffic or change to official UNSW benchmark.
- Synthetic regression and GitHub CI are **not** student Windows/VMware Host-only acceptance. Private capture provenance, physical isolation, independently verified attack labels and detection latency remain unverified. The exported snapshot is mutable SQLite evidence, not signed forensic proof.


## 2026-10-28 — Windows host network preflight evidence (feature PR; CI pending)

- Added `src/blue_team_ai/windows_host_preflight.py`, `scripts/record_windows_host_network.py`, `tests/test_windows_host_preflight.py`, and `docs/WINDOWS_HOST_NETWORK_PREFLIGHT.md`. This is a **read-only Windows host configuration snapshot**, not packet capture or proof of VMware isolation.
- Only three local, allowlisted diagnostics are invoked with `shell=False`: `ipconfig /all`, `route print -4`, and `netsh interface ipv4 show interfaces`. Original outputs stay outside Git in an explicitly selected private directory; a bounded SHA-256 JSON inventory does not embed addresses or hostnames.
- Refuses non-Windows execution, missing explicit CLI confirmation, failed/oversized outputs, existing files and in-repository destinations. Tests use mocked synthetic command output; **no student's laptop or VMware capture was tested**.
- CI and merge status **not yet verified** at time of this entry. Do not treat this as evidence of Host-only isolation, authorization, correct labels or AI attack detection.
- Next: inspect PR CI, merge only on a green final head, then have the student run the CLI on Windows 3.12.9, independently inspect each guest adapter/route, and archive the original private evidence.


## 2026-10-28 — Windows host preflight feature verified and merged

- [PR #113](https://github.com/tbao4151/DA_CNTT/pull/113) was squash-merged to `main` at `7a81bc531a725898bedcd8570c2e6b1a1cbae205` after its **final-head** [CI #40682056972](https://github.com/tbao4151/DA_CNTT/actions/runs/40682056972) passed: **586 passed, 2 skipped, 2 warnings** on Ubuntu 24.04 / Python 3.12.9. The post-merge main run #40682389167 was queued when this note was written; it must be checked separately.
- The new command is read-only Windows host network evidence capture with mock-based CI tests. No student Windows run, VMware isolation validation, Zeek capture, labels, model evaluation or SOC operational alert is claimed. Original host diagnostics are sensitive and must remain private outside Git.

## 2026-10-28 — Pinned private Windows host preflight integrity verification (feature branch; CI pending)

- Inspected main at `17dd56cd0d879facda61d28cca7978c4eec53bb5`, README/PROGRESS/ROADMAP, tree, existing Windows host preflight and capture inventory, recent green Actions and no open PRs before this slice.
- Added `src/blue_team_ai/host_preflight_verify.py`, `scripts/verify_windows_host_network.py` and synthetic regression `tests/test_windows_host_preflight_verify.py`: independently pinned report SHA-256, bounded strict JSON schema, original exact-file digest/size verification and fail-closed private paths. Purely offline read-only; no Windows commands, network, VMware changes, inference, SOC writes or alert.
- At feature-branch creation **PR CI and merge are not yet verified**. No real student Windows/VMware execution, physical isolation, independent attack labels or detection performance is claimed. The inventory itself remains operator-controlled and unauthenticated.
- Student must independently pin the report hash in a private notebook, verify original host outputs and inspect each guest adapter/route manually; then collect genuine Zeek capture evidence and run separate labeled evaluation.

## 2026-10-28 — Pinned host preflight integrity verifier merged (#115)

- [PR #115](https://github.com/tbao4151/DA_CNTT/pull/115) squash-merged to main at `ff82eb2c1bfd348ea5091e7fdf26421b5eb21a73` after its final-head [PR CI #40686152438](https://github.com/tbao4151/DA_CNTT/actions/runs/40686152438) **passed** on Ubuntu Python 3.12.9: **600 passed, 2 skipped, 2 existing warnings**. Post-merge main CI [#40686463102](https://github.com/tbao4151/DA_CNTT/actions/runs/40686463102) started and is tracked separately; do not claim its final result until verified.
- The offline verifier checks an independently recorded report SHA-256 and all three original private host diagnostics against the pinned inventory. It refuses tampering, missing originals, invalid schema, path aliases and symlinks. No commands or network are executed during verification, and no private evidence is uploaded.
- Tests use synthetic Windows command output. No student's Windows/VMware execution, physical isolation, authenticated provenance, independently verified labels, actual detection accuracy or event-to-alert latency is claimed. Dataset Mode UNSW-NB15 and Red Team safe-off remain unchanged.


## 2026-10-28: Pinned Zeek capture inventory re-verification (feature slice)

- Reviewed main README, roadmap, progress, offline Zeek capture inventory, existing pinned Windows host verifier, repository tree, open PRs (none) and latest Actions before starting. The host preflight verifier (#115) is distinct from the Zeek capture inventory; no live capture or real Windows test was available.
- Added an offline, read-only Zeek inventory verifier and CLI. It checks a separately pinned JSON SHA-256, exact five original evidence files, byte lengths/digests, file-type sanity, and recomputes CIDR scope/flow count/event bounds from original Zeek bytes. It refuses modified originals, invalid safety claims, changed CIDRs, duplicate JSON keys and malformed metadata.
- Added synthetic regression tests and Windows documentation. This is not an authenticity check, VMware isolation proof, AI model run, Red Team activity or SOC alert; Dataset Mode benchmark and SQLite are untouched.
- **At authoring:** PR CI, merge and real Windows/VMware acceptance are not yet verified. Verify the final PR-head CI and merge only if successful. Students must independently record the inventory hash and run the verifier on a genuine authorized Host-only capture, retaining originals privately.

- **Verified and merged:** [PR #117](https://github.com/tbao4151/DA_CNTT/pull/117) squash-merged as `bebe6601c249ca12d64b05c15d38cbc837c642fd`. Final PR-head [quality gates #40689613894](https://github.com/tbao4151/DA_CNTT/actions/runs/40689613894) passed Ubuntu Python 3.12.9 with **620 passed, 2 skipped, 2 warnings**. Post-merge main [quality gates #40689948085](https://github.com/tbao4151/DA_CNTT/actions/runs/40689948085) also passed with the same counts. These are synthetic tests, not Windows/VMware acceptance.


## 2026-10-28 — Zeek cross-capture normalized flow reuse guard (feature PR; verification pending)

- Inspected current `main` at `27ee9976818c20c39b09992a22ef21f09ea1985a`, README, PROGRESS, ROADMAP, repository tree, recent green Actions and zero open PRs before editing. The prior pinned capture inventory PR #117 and documentation PR #118 were merged.
- Reused one conservative normalized UID/time/five-tuple identity helper in the existing NEW-log partition guard and the offline labeled dataset builder. Re-encoded copies of a flow in distinct declared captures now fail before model training, including when raw SHA-256 differs. Existing cross-split host/session and label checks remain.
- Added synthetic regression for cross-split and within-split duplicate identities, legitimate UID reuse at different timestamps, and CLI preflight/fit fail-closed behavior. Updated the offline experiment runbook.
- **At feature-branch authoring:** GitHub PR CI and merge are not yet verified. No student Windows/VMware Host-only experiment, authenticated labels, true event-to-alert latency, live traffic, operational alert or new official UNSW-NB15 benchmark is claimed.


## 2026-10-28 — Cross-capture Zeek flow identity guard merged (#119)

- [PR #119](https://github.com/tbao4151/DA_CNTT/pull/119) squash-merged to `main` at `c6ecd06221291b77e1b7abb7f69b15038be0d877` only after its **final-head** [GitHub Actions quality gates #40694487688](https://github.com/tbao4151/DA_CNTT/actions/runs/40694487688) passed on Ubuntu Python 3.12.9: **624 passed, 2 skipped, 2 existing pandas warnings**. Earlier intermediate feature commits had failed tests due to malformed synthetic byte-literal fixtures; these were corrected and the final PR head was green.
- Shared normalized UID/time/five-tuple overlap screening now rejects re-encoded duplicate flows across any declared training, validation or test captures before offline model fitting. This is not semantic deduplication or independent ground-truth verification. The official UNSW benchmark, Red Team traffic and existing private artifacts are unchanged.
- Post-merge `main` quality gates [#40694838963](https://github.com/tbao4151/DA_CNTT/actions/runs/40694838963) started; **final status pending verification at documentation time**. No student Windows/VMware experiment, actual attack-detection rate or event-to-alert latency is claimed.


## 2026-10-28 — Independent Zeek annotation agreement (feature branch; CI pending)

- Reviewed current main README/PROGRESS/ROADMAP, source tree, existing Zeek annotation-v1 workflow, latest successful main Actions and no open PRs. This slice does not overlap the merged cross-capture flow guard (#119).
- Added `src/blue_team_ai/annotation_agreement.py`, `scripts/review_zeek_annotation_agreement.py`, synthetic tests and `docs/ZEEK_ANNOTATOR_AGREEMENT.md`. Two separately SHA-pinned complete annotation-v1 files are checked against the same original Zeek bytes and exact UID coverage; only aggregate 2x2 agreement, Cohen's kappa and limitations are exported. No UID/label list is written, no consensus generated.
- At feature authoring, PR CI/merge are **not yet verified**. Synthetic tests do not demonstrate genuine independent annotators, ground-truth authenticity, Host-only isolation, AI detection performance or Windows laptop acceptance. Official UNSW-NB15 benchmark, models, SOC SQLite and Red Team active traffic are unchanged.
- Next: verify PR CI before merge; student independently annotates a real authorized Host-only capture twice, pins all three SHA-256 values outside Git, runs the offline comparison on Windows Python 3.12.9, documents disagreements and independently adjudicates before constructing the experiment manifest.


## 2026-10-28 — Independent Zeek annotator agreement verified and merged (#121)

- [PR #121](https://github.com/tbao4151/DA_CNTT/pull/121) was squash-merged as `657cbb9ce5a4ef63a4900aaf9aac5571cbdfe6cf` only after final-head [quality gates #40698075993](https://github.com/tbao4151/DA_CNTT/actions/runs/40698075993) **passed** on Ubuntu Python 3.12.9. Post-merge main [quality gates #40698595946](https://github.com/tbao4151/DA_CNTT/actions/runs/40698595946) also **passed**. Earlier feature authoring notes marked CI pending; these links supersede that temporary state.
- Two complete annotation-v1 files are compared against original pinned Zeek bytes, exact UIDs and independently supplied SHA-256; report includes only aggregate confusion counts, observed agreement and Cohen's kappa. No labels are inferred or overwritten. This is **not** proof of independent annotators or verified attacks.
- All regression fixtures are synthetic; student Windows/VMware Host-only acceptance, actual independently documented annotation evidence, label adjudication, detection metrics and event-to-alert latency remain outstanding. Official UNSW-NB15 baseline, existing private cases and Red Team active traffic were not changed.


## 2026-10-28 — Private Zeek disagreement worksheet (feature PR; CI pending)

- Inspected main at `192b4e0eb6a10738d74953d5741f13e44e591b6d`, README, PROGRESS, ROADMAP, repository tree, the two-reviewer agreement code, latest green Actions and no open PRs. Existing PR #121 and documentation PR #122 were merged; this feature does not change their aggregate agreement report.
- Added `src/blue_team_ai/disagreement_review.py`, `scripts/prepare_zeek_disagreements.py`, `tests/test_zeek_disagreement_review.py`, and `docs/ZEEK_PRIVATE_DISAGREEMENT_REVIEW.md`. This **explicitly opt-in** offline private worksheet lists only disagreement UIDs and reviewer labels; adjudicated labels and evidence references remain null. It requires independently pinned hashes, original complete annotation-v1 inputs, private exclusive output beside the original log, and never edits source labels.
- The existing aggregate agreement CLI remains UID-free and unchanged. This new worksheet is **not** a training annotation or independent ground truth. All regression fixtures are synthetic; student Windows/VMware Host-only capture, physical isolation, annotator independence, genuine labels, model detection metrics and event-to-alert latency remain unverified.
- At feature authoring, PR-head CI and merge are **not yet verified**. Merge only after green final-head CI and no conflicts; follow up with a separate verified record. The student must manually adjudicate disagreements from independently retained scenario evidence and create a newly pinned complete annotation version outside Git.


## 2026-10-28 — Private Zeek disagreement worksheet verified and merged (#123)

- [PR #123](https://github.com/tbao4151/DA_CNTT/pull/123) squash-merged as `b9e5dbfb7bf404c412657456a4271a7f7b46c8bf` after its final-head [CI #40703014325](https://github.com/tbao4151/DA_CNTT/actions/runs/40703014325) **passed** Ubuntu Python 3.12.9: **646 passed, 2 skipped, 2 existing pandas warnings**. Post-merge main [CI #40703530003](https://github.com/tbao4151/DA_CNTT/actions/runs/40703530003) also **passed**.
- The new offline opt-in private worksheet lists only reviewer disagreements, includes sensitive UIDs, and leaves adjudication/evidence fields null. The aggregate report remains UID-free. It does not alter annotation-v1 inputs, model, SQLite, UNSW benchmark or network behavior.
- All tests used synthetic fixtures. No student Windows/VMware Host-only run, independent label adjudication, verified attack ground truth, measured detection latency or live alert is claimed. Students must keep original captures, both reviewer files, worksheet and adjudication evidence outside Git and separately pin hashes.


## 2026-10-28 — Private Zeek adjudication finalization (feature branch; verification pending)

- Read current main at `fb3cfe8433cd38202ab184d2cc4ea3c533910eb6`, README/PROGRESS/ROADMAP, repository tree, existing independent agreement and private disagreement workflow, open PRs (none), and recent green Actions (#40703530003 main; #40704016957 documentation PR). This is a follow-up to merged PR #123/#124, not a parallel duplicate.
- Added an opt-in offline finalization path for a manually completed, independently SHA-pinned private worksheet. It rebuilds the original UID disagreement template from the pinned log and two reviewer annotations, rejects changed reviewer labels, extra UIDs, unresolved decisions, missing evidence references, and writes a **new private annotation-v1** file only after explicit operator confirmation. The original inputs, manifest, model, benchmark and SQLite remain unchanged.
- Added synthetic regression tests and Windows instructions. **At feature authoring**, CI, merge and student Windows/VMware execution are not yet verified. The new binary annotation is not authenticated attack ground truth; manual evidence and preregistered independent holdout are still mandatory.


## 2026-10-28 — Private Zeek adjudication finalization merged and CI verified (#125)

- [PR #125](https://github.com/tbao4151/DA_CNTT/pull/125) was squash-merged into main at `391eac454049306a2475c3d1e69fc61032c6428f` after **final-head** [GitHub Actions #40708581003](https://github.com/tbao4151/DA_CNTT/actions/runs/40708581003) succeeded on Ubuntu Python 3.12.9: **665 passed, 2 skipped, 2 existing pandas warnings**. Main post-merge Actions run #40709168583 was queued at documentation authoring; do not assume success without checking.
- The offline opt-in finalizer reconstructs the pinned private reviewer disagreement template and requires a manual 0/1 adjudication and evidence reference for each disputed UID before exclusively writing a new private annotation-v1. It never edits originals, chooses labels using model predictions, creates SOC alerts, or runs network traffic.
- CI tests used synthetic Zeek fixtures only. Reviewer agreement and a filled evidence reference do not prove genuine ground truth, annotator independence, physical VMware isolation or Windows laptop execution. Dataset Mode benchmark, Red Team active traffic, model and existing SOC SQLite were unchanged.


## 2026-10-28 — Read-only verification of finalized private Zeek label chain (feature slice)

- Reviewed current main README, PROGRESS, ROADMAP, repository tree, open PRs (none), last successful main/PR Actions, and existing manual adjudication finalizer before choosing this independent verification slice. The preceding finalizer PR #125 was merged; post-merge main CI #40709168583 and documentation PR CI #40709276176 were successful.
- Added `src/blue_team_ai/final_label_verify.py` and `scripts/verify_zeek_final_labels.py`: read-only SHA-pinned re-verification of original log, both reviewer annotations, completed manual worksheet, and finalized annotation. Recomputes every final UID label from the existing finalizer and refuses altered output even if the altered output hash was re-pinned. CLI prints only aggregate counts and hashes, never UIDs/IPs/private paths; requires five distinct private files.
- Added synthetic regression tests and Windows runbook `docs/ZEEK_FINAL_LABEL_CHAIN_VERIFICATION.md`. At feature authoring, final-head PR CI/merge are **pending verification**; do not claim successful CI or Windows execution until verified.
- This checks byte consistency and reviewer/worksheet-derived labels, **not** ground truth, independent annotators, genuine VMware isolation, real detection metrics, or live traffic. Official UNSW-NB15 benchmark, existing SOC SQLite, model artifacts, and Red Team active traffic remain untouched.

## 2026-10-28 — Verified private final-label chain verifier merged (#127)

- [PR #127](https://github.com/tbao4151/DA_CNTT/pull/127) squash-merged as `a40759de0a35485876551fea54b8017a2f3d7e8b` after final-head [quality gates #40713687729](https://github.com/tbao4151/DA_CNTT/actions/runs/40713687729) **passed** on Ubuntu Python 3.12.9: **679 passed, 2 skipped, 2 existing pandas warnings**. Post-merge main run #40718618943 was queued at this documentation update; its result must be checked separately.
- The read-only five-input SHA-pinned verifier recomputes final UID labels from original Zeek log, both reviewer annotations and manually completed worksheet; rejects a re-pinned altered final annotation. CLI emits only aggregate counts and source hashes, with explicit unverified-ground-truth and unverified-isolation flags. No new data, model, alert, SQLite change, active traffic or UNSW benchmark change.
- CI used synthetic fixtures; no student Windows/VMware Host-only capture, authentic attack labels, independent annotator evidence, or real detection/latency results were verified. Student must run the Windows CLI with five privately pinned original files outside Git, preserve output and independent lab evidence.


## 2026-10-28 — Optional pinned annotation bytes for Zeek experiment (feature PR)

- Reviewed `main` README/PROGRESS/ROADMAP, source/tests, open PRs and recent CI. Previous blocked [PR #127](https://github.com/tbao4151/DA_CNTT/pull/127) was independently confirmed **merged** as `a40759de0a35485876551fea54b8017a2f3d7e8b`; follow-up #128 was also merged. Main quality gates [#40718618943](https://github.com/tbao4151/DA_CNTT/actions/runs/40718618943) and PR #128 [#40718698317](https://github.com/tbao4151/DA_CNTT/actions/runs/40718698317) succeeded. No open PR at the start of this slice.
- Added optional raw-byte `labels_sha256` to each offline Zeek experiment manifest capture; a supplied pin is checked before model fit, while `--require-label-sha256` rejects missing pins on **any** train/validation/test capture. Both preflight and experiment report whether all pins were required; `annotation_chain_verified=false` is explicit. Legacy commands without the flag remain supported.
- Added synthetic regression tests for pinned preflight and fit, altered annotation bytes despite matching source hash, malformed/partial pins, legacy behavior and re-pinned but unverified labels. Updated Windows runbook. **At authoring, feature PR CI and merge have not yet been verified.**
- No genuine Windows/VMware capture, independent attack labels, model improvement, new UNSW benchmark, operational alert, or Red Team traffic is claimed. SHA-256 pins alone do not establish truth or reviewer independence.


## 2026-10-28 — Pinned Zeek annotation byte integrity merged and CI verified (#129)

- [PR #129](https://github.com/tbao4151/DA_CNTT/pull/129) was squash-merged into `main` as `a65a6107ee3c350f8d39d06ecca5e1f78a226382` after final-head [quality gates #40722795229](https://github.com/tbao4151/DA_CNTT/actions/runs/40722795229) passed on Ubuntu Python 3.12.9 (**684 passed, 2 skipped, 2 existing pandas warnings**). Post-merge `main` [quality gates #40723382103](https://github.com/tbao4151/DA_CNTT/actions/runs/40723382103) also passed with the same counts. The earlier feature-authoring CI-pending note is superseded by this verified record.
- Exact raw annotation bytes are checked when a capture manifest includes `labels_sha256`. Strict `--require-label-sha256` rejects a missing pin on any train/validation/test capture before fitting or writing reports. Legacy CLI behavior is preserved without opt-in; reports distinguish strict pinning from unverified adjudication.
- Five added synthetic regression tests passed in the suite; no genuine Windows/VMware acceptance, authenticated ground truth, attack-detection improvement or operational alert is claimed. A re-pinned altered annotation can still pass a byte-integrity check, so the independent five-input final-label chain and scenario evidence remain necessary.

## 2026-10-28: Bounded offline PCAP -> Zeek import (PR #131 merged, PR CI verified)

- Added `src/blue_team_ai/offline_pcap.py` and `scripts/import_offline_pcap.py` to convert an existing, authorized classic PCAP using **Zeek -r only**, with explicit operator opt-in. No live interface capture, traffic generation, Red Team execution, AI inference or SOC write.
- Added strict private absolute paths outside Git, no-overwrite output, classic PCAP magic/size checks, bounded subprocess timeout, post-run PCAP digest recheck, Zeek ASCII `conn.log` parser and declared RFC1918 CIDR screening. Failed runs preserve partial private outputs but never produce a success report.
- Added synthetic/mocked regression tests and `docs/OFFLINE_PCAP_ZEEK_IMPORT.md`. **GitHub Actions PR CI succeeded:** run 40728220108, 698 passed, 2 skipped, 2 pandas warnings, Ubuntu Python 3.12.9. PR #131 squash-merged as 86922d6717b6b8047cfaa8753c141faa1dc1fbcf. Post-merge main CI run 40728824378 started; result not yet verified when writing this note. No real Zeek executable, VMware lab or student laptop has been exercised by this change. Mocked CI does not constitute real Zeek/Windows/VMware acceptance.
- Dataset Mode UNSW-NB15 and existing model/case data remain unchanged. Next: run actual Zeek -r on a private PCAP in a student-owned Linux VM and retain evidence; only then connect verified new telemetry to research inference/SOC.


## 2026-10-29 — Pinned read-only verification of offline PCAP import (feature PR; CI pending)

- Reviewed main at `50e05cfde9d4613aa980b9569d8ea82ed591332f`, README/PROGRESS/ROADMAP, source/tests, directory tree, recent successful CI and zero open PRs. Earlier offline PCAP importer PR #131 and documentation follow-up were merged; main CI #40728824378 and documentation PR CI #40728892713 passed. This slice verifies the existing importer output rather than duplicating import or claiming live capture.
- Added `src/blue_team_ai/offline_pcap_verify.py` and `scripts/verify_offline_pcap_import.py`: read-only verification of an independently SHA-pinned import report, exact original classic PCAP and Zeek `conn.log`, plus recalculated CIDR screening and flow counts. All three inputs must remain private outside Git; no Zeek execution, sockets, AI scoring or SQLite writes.
- Added synthetic-only tests (`tests/test_offline_pcap_verify.py`) and Windows/Linux guidance (`docs/OFFLINE_PCAP_PINNED_VERIFICATION.md`). **At feature authoring, final-head PR CI and merge have not been verified.** Do not count tests as passing until the actual GitHub run completes.
- A passing digest/scope check does **not** establish PCAP authenticity, trusted Zeek conversion, authorized use, physical Host-only isolation, correct attack labels, AI detection quality or latency. Student must independently retain original capture, adapter/routes, Zeek version and scenario evidence outside Git. UNSW official benchmark, Red Team traffic, existing SOC cases and models remain unchanged.


## 2026-10-29 — Pinned offline PCAP evidence verifier merged (#133)

- [PR #133](https://github.com/tbao4151/DA_CNTT/pull/133) squash-merged into `main` as `eea8fee6fa7ba1ba55c97b1fbee5799c1c704e87` after **final-head** [quality gates #40734466006](https://github.com/tbao4151/DA_CNTT/actions/runs/40734466006) and [#40734456078](https://github.com/tbao4151/DA_CNTT/actions/runs/40734456078) both passed on Ubuntu Python 3.12.9. Run #40734466006 reported **716 passed, 2 skipped, 2 existing pandas warnings**. An earlier CI failure (one CLI test) was fixed by restoring the global subprocess runner after mocked Zeek import; no failed head was merged.
- The new read-only verifier checks independently pinned report bytes, original classic PCAP, original Zeek ASCII `conn.log`, declared CIDR and aggregate flow count. All inputs remain private and outside Git; no network capture, Zeek execution, model inference, SOC case mutation or UNSW benchmark change.
- Post-merge main [CI #40735055379](https://github.com/tbao4151/DA_CNTT/actions/runs/40735055379) was **queued** when this documentation entry was authored; check final status separately. All added fixtures are synthetic/mocked. Genuine Linux Zeek/Windows/VMware acceptance, physical isolation, capture authenticity, independent attack labels, detection metrics and latency remain outstanding.


## 2026-10-29 — Optional pinned offline PCAP provenance gate for Zeek research scoring (feature slice)

- Read current `main` README, PROGRESS, ROADMAP, directory tree, existing PCAP importer/verifier, Zeek scorer, related synthetic tests, open PRs (none) and recent Actions. Previous PR #133 and documentation follow-up were merged; main CI #40735055379 and PR CI #40735154182 both passed. No previous open work was duplicated.
- Extended `scripts/score_zeek_new_log.py` with three **optional, all-or-none** arguments to verify a separately SHA-pinned offline import report, original classic PCAP and original Zeek `conn.log` **before** loading the research model or writing predictions. Requires the independent log digest to match the verified import. The legacy scoring command, JSON prediction schema and downstream review/case workflow remain unchanged.
- Added `tests/test_offline_pcap_scoring_gate.py` with a synthetic mocked-Zeek PCAP import, actual research-model JSON scorer subprocess, refusal cases for partial flags, tampered source, wrong scope/pins and existing output. Updated the Windows inference runbook. **At authoring, feature PR CI/merge and Windows/VMware acceptance have not been verified**; do not count these tests as passed until Actions confirms.
- No live capture, active Red Team scenario, AI alert, SOC SQLite write, UNSW-NB15 benchmark change, model retraining, authentic attack labels or student laptop execution. A successful pinned import gate is **not** evidence of Host-only isolation, genuine capture, model validity or TEST partition exclusion.


## 2026-10-29 — Pinned offline PCAP-to-Zeek research scoring gate merged (#135)

- [PR #135](https://github.com/tbao4151/DA_CNTT/pull/135) squash-merged into `main` as `8d539139ef20d9999646f3e7803e4ca5ab658133` **only after final-head** [quality gates #40737879199](https://github.com/tbao4151/DA_CNTT/actions/runs/40737879199) succeeded on Ubuntu Python 3.12.9: **717 passed, 2 skipped, 2 warnings**. This supersedes the feature-authoring pending CI note above. Post-merge `main` CI must be checked independently.
- Optional three-argument PCAP provenance gate is integrated into the existing Zeek new-log scoring CLI. It verifies original PCAP, `conn.log`, independent import-report pin and CIDR scope before loading the model or writing the prediction JSON. Existing unpinned CLI invocation and downstream JSON schema remain compatible.
- Integration regression exercised synthetic/mocked Zeek import followed by the **real offline research scorer CLI** and failure paths. No actual Zeek binary, authorized VMware capture, Windows laptop acceptance, verified labels, operational AI alerts or SOC writes were exercised. Official UNSW benchmark, Red Team active traffic, model artifacts and existing SQLite were unchanged.

## 2026-10-29 — Optional PCAP provenance recheck at independent research report review (feature PR)

- Inspected main README, PROGRESS, ROADMAP, repository tree, zero open PRs and recent green GitHub Actions; prior PCAP-to-Zeek scoring gate PR #135 and documentation PR #136 are merged. Selected an independent **review-time** check rather than repeating the existing scoring-time gate.
- Extended `scripts/verify_zeek_new_log_report.py` with optional, all-or-none original PCAP/import-report/pinned-hash arguments. Before loading the research model or re-scoring, it verifies original PCAP and Zeek bytes, import-report pin, flow count and CIDR, then checks the independently pinned log SHA-256. The existing full report recomputation and legacy CLI remain intact.
- Added `tests/test_offline_pcap_report_review_gate.py` using a mocked Zeek import and real scorer/reviewer subprocesses. Includes a post-scoring PCAP alteration that passes legacy report consistency but fails provenance recheck. Updated private Windows runbook. **Feature CI/merge status must be checked on GitHub; no passing count is claimed at authoring.**
- This is read-only, offline and synthetic-tested only; it does not establish authentic capture, physical Host-only isolation, independent ground truth, TEST exclusion, real Zeek execution, real AI detection, latency or SOC alerts. No UNSW benchmark, model, SQLite or Red Team traffic changes.

## 2026-10-29 — Verified offline PCAP provenance recheck at report review merged (#137)

- [PR #137](https://github.com/tbao4151/DA_CNTT/pull/137) squash-merged into `main` as `8dffb34f3f438c756f5ac34603c25176fa0044d5` after **final-head** [quality gates #40742422992](https://github.com/tbao4151/DA_CNTT/actions/runs/40742422992) passed on Ubuntu Python 3.12.9: **718 passed, 2 skipped, 2 existing pandas FutureWarnings**. Post-merge [main CI #40743228957](https://github.com/tbao4151/DA_CNTT/actions/runs/40743228957) also completed successfully.
- Optional three-argument pinned PCAP import gate now runs independently at **research report review**, before model loading or prediction recomputation; rejects altered original PCAP after scoring, even if log/model/prediction JSON remain consistent. Existing CLI without optional flags is backward-compatible.
- Integration test uses a mocked Zeek importer and real scorer/reviewer subprocesses. No genuine Zeek executable, Windows laptop/VMware Host-only capture, independent attack labels, operational alert or SOC write has been verified. UNSW-NB15 benchmark and Red Team network execution remain unchanged.


## 2026-10-29 — Optional original-PCAP recheck at manual NEW-log SOC case write (feature)

- Inspected `main` at `afff2e4cfe2395031331456098e6180467e03755`, README/PROGRESS/ROADMAP, source tree, recent successful CI and zero open PRs. Prior PCAP scoring and independent report-review gates (#135/#137) are merged.
- Added optional all-or-none private PCAP/import-report SHA-256 arguments to `scripts/triage_zeek_new_log.py`, and a **second verification inside** `create_new_log_candidate_case` before SQLite case creation. This checks the original PCAP, import report, Zeek log, declared CIDR and pinned source digest again at the SOC write boundary; the initial manual Unclassified audit note distinguishes verified byte integrity from legacy unverified PCAP provenance.
- Added synthetic regression `tests/test_offline_pcap_soc_triage_gate.py` for listing, manual case idempotency, tampering **after** a successful listing, partial options, wrong scope/pins and direct API write-boundary checks. Zeek import is mocked; the scorer and triage CLI run as real offline subprocesses. Updated Windows manual SOC triage documentation.
- **At feature authoring, CI/PR/merge are pending verification**; no test count, real Zeek execution, Windows laptop run, verified labels, physical isolation, operational alert, genuine detection performance or latency is claimed. UNSW-NB15 baseline, existing models/cases and Red Team traffic remain unchanged.


## 2026-10-29 — Pinned offline PCAP recheck at manual SOC write merged (#139)

- [PR #139](https://github.com/tbao4151/DA_CNTT/pull/139) squash-merged into `main` as `e32da8f5b3c66923486a8f9faabe93e0730cbc81` after **final-head** [quality gates #40748542366](https://github.com/tbao4151/DA_CNTT/actions/runs/40748542366) passed on Ubuntu Python 3.12.9: **728 passed, 2 skipped, 2 existing pandas FutureWarnings**. An earlier CI run #40747841156 failed nine synthetic CLI tests because the new test fixture omitted the mandatory `--report` flag; the fixture was corrected, rerun and final head passed before merge.
- Optional original-PCAP/import-report provenance is now rechecked at candidate listing and **again inside the manual SOC case write function**; the source Zeek bytes must match the independently pinned import. A successful manual case remains `Unclassified` and notes the integrity checks without claiming a verified attack. Legacy CLI commands still work without PCAP provenance and are explicitly marked as unverified in new case notes.
- Post-merge [main CI #40749243651](https://github.com/tbao4151/DA_CNTT/actions/runs/40749243651) was queued when this record was authored; check its final conclusion separately. All new tests use synthetic data and a mocked Zeek import, not actual Linux Zeek, Windows/VMware capture, authentic labels or real attack detection. Official UNSW-NB15 benchmark, existing SOC cases/models and Red Team network behavior remain unchanged.

## 2026-10-29 — Optional pinned PCAP provenance in Blue Team NEW-log UI (feature slice)

- Inspected main at `ec72e02ce773f40ebd3d66ad082fe9c404e6bb38`, README, PROGRESS, ROADMAP, source tree, recent successful CI, and no open PRs. PR #139/#140 had already merged; final PR #140 CI #40749536113 and post-merge #139 main CI #40749243651 were green. The CLI and core SOC write gate already checked original PCAP bytes; the Streamlit UI lacked this optional provenance path.
- Extended the Blue Team NEW-log Streamlit form with an all-or-none independently pinned PCAP/import report triple. Preview checks the original private `conn.log`, PCAP, report, CIDR and uploaded log hash; the UI manual SOC wrapper passes private originals into the existing core write-time verifier, which checks them again before SQLite mutation. No changes to the legacy UI path, official UNSW benchmark, existing models or cases.
- Added synthetic/mock-Zeek UI regression and Windows runbook guidance. **At authoring, final-head PR CI, merge and local Windows/VMware acceptance are not yet verified.** Do not count tests as passed until GitHub Actions reports success.
- Byte integrity and a private manifest do not prove genuine Host-only isolation, PCAP origin, permission, ground truth, real attack detection or event-to-alert latency. Red Team remains non-networked; SOC cases remain manually confirmed `Unclassified` research records.

## 2026-10-29 — Blue Team optional pinned original-PCAP UI gate merged (#141)

- [PR #141](https://github.com/tbao4151/DA_CNTT/pull/141) squash-merged into `main` as `e50a0fd86bc2d93d800b5411749b3a98ead504a0` after **final-head** [GitHub Actions #40752707725](https://github.com/tbao4151/DA_CNTT/actions/runs/40752707725) succeeded on Ubuntu Python 3.12.9: **736 passed, 2 skipped, 2 existing pandas FutureWarnings**. The PR was confirmed mergeable and had no competing open PR at merge. This supersedes the feature-authoring pending note above. Post-merge `main` CI must be verified separately if triggered.
- The Streamlit NEW-log Blue Team form now optionally checks the independently SHA-pinned original offline PCAP, import report and Zeek `conn.log` against the uploaded log **before showing candidates**. Its manual `Unclassified` SOC write path repeats the verification via the existing core gate. Legacy UI/CLI behavior remains available with explicit lack of PCAP provenance verification.
- All new tests use synthetic data and mocked Zeek import; no genuine Linux Zeek binary, Windows/VMware capture, independent attack labels, Host-only isolation, real detection/latency, operational auto-alert or Red Team traffic has been verified. Existing official UNSW-NB15 benchmark, model artifacts and SQLite cases remain unchanged.


## 2026-10-29 — Benign synthetic PCAP real-Zeek local acceptance harness (feature)

- Inspected main README, PROGRESS, ROADMAP, repository tree, current Blue Team offline PCAP importer/verifier, synthetic tests, latest Actions and zero open PRs at base `34f5d43e14b3df313cae08bdddc99ef747f08a5e`. The previous Blue Team pinned PCAP UI gate (#141/#142) was already merged; the PR CI and main post-merge CI were successful.
- Added a separate **opt-in** `scripts/smoke_zeek_offline.py` and `src/blue_team_ai/zeek_smoke.py`: generate a deterministic benign synthetic Ethernet/IPv4/UDP classic PCAP entirely offline, call installed `zeek --version` and real `zeek -r` via the existing importer, recheck the resulting private report/log, and retain a distinctly labeled `smoke_report.json`. Output must be a new absolute private directory outside Git; no network interface, attack traffic, model, existing dataset or SOC SQLite is touched.
- Added `tests/test_zeek_real_smoke.py` with deterministic packet/checksum validation and **mocked Zeek** success/failure tests; added `docs/REAL_ZEEK_BENIGN_SMOKE.md` for actual Linux VM acceptance. The generated report digest is computed during the smoke itself and is **not an independent trust anchor**.
- **At feature authoring, GitHub CI and PR merge are pending.** No real Zeek binary was executed in CI, and no student Windows/Linux VMware test, authentic capture, verified attack labels, detection metrics, automatic alert or event-to-alert latency is claimed. The real Zeek smoke requires a later local run with Zeek installed. Dataset Mode and Red Team network behavior remain unchanged.


## 2026-10-29 — Benign real-Zeek acceptance harness merged (#143; CI verified)

- [PR #143](https://github.com/tbao4151/DA_CNTT/pull/143) squash-merged into `main` as `2413a496b459e061012eb8f5b1ada67589fa89c2` after final-head [GitHub Actions #40757107763](https://github.com/tbao4151/DA_CNTT/actions/runs/40757107763) passed on Ubuntu Python 3.12.9: **742 passed, 2 skipped, 2 existing warnings**. Post-merge [main CI #40757667200](https://github.com/tbao4151/DA_CNTT/actions/runs/40757667200) also succeeded. This supersedes the pending CI note in the feature-authoring record.
- The CLI can generate a deterministic benign synthetic PCAP and **will invoke** an installed real Zeek binary when a student runs it; the actual GitHub CI only used a **mocked Zeek subprocess**. No actual Zeek executable, VMware host-only capture or Windows/Linux laptop acceptance was executed or verified in this work. The synthetic smoke must never be reported as attack ground truth or model detection.
- A smoke report pin generated during the same run is a consistency check, **not** independent source provenance. The official UNSW benchmark, existing model/cases and Red Team network behavior remain unchanged.


## 2026-10-29 — Benign Zeek smoke fixture-flow contract (feature; CI pending)

- Strengthened the opt-in synthetic smoke to **fail closed** unless the parsed Zeek `conn.log` contains exactly one flow matching the generated PCAP's source/destination IPs, UDP ports, protocol and first-packet UTC timestamp (1 ms tolerance). Previously, a different in-CIDR Zeek log could pass the import hashes and scope checks. This validates the specific fixture, not only file self-consistency.
- Added synthetic regression cases for mismatched in-scope addresses, ports, protocol, timestamp and duplicate flows; updated the mocked-Zeek success fixture and private runbook. Success report now explicitly records the fixture identity/time checks.
- **CI/PR and merge pending at feature authoring.** No actual Zeek binary or student Windows/VMware experiment was run; these tests use mocked Zeek. No new attack detection, independent labels, real capture, live alerts or measured latency. Official UNSW benchmark, existing model/cases and Red Team traffic unchanged.


## 2026-10-29 — Exact synthetic Zeek fixture-flow gate merged and CI verified

- [PR #145](https://github.com/tbao4151/DA_CNTT/pull/145) squash-merged as `417ac21d85c9e62b518cdcf1cea93cd3359e6651` after final-head [CI #40761458458](https://github.com/tbao4151/DA_CNTT/actions/runs/40761458458) passed: **750 passed, 2 skipped, 2 existing warnings**, Ubuntu Python 3.12.9. Post-merge [main CI #40762224232](https://github.com/tbao4151/DA_CNTT/actions/runs/40762224232) also succeeded. This supersedes the pending feature-authoring note.
- The smoke now rejects a `conn.log` whose single flow does not match the generated PCAP's IP/UDP-port/protocol/first timestamp, even when the log is within the declared CIDR. This guards against falsely accepting an unrelated file; CI tests use **mocked Zeek**, not an installed real binary.
- No laptop/VMware test, real Zeek acceptance, capture provenance, attack labels, AI detection, SOC alert latency, or physical Host-only isolation has been verified. No official UNSW benchmark, model, case, or active Red Team change.


## 2026-10-29 — Real Zeek offline container CI acceptance (feature; CI pending)

- Inspected main README/PROGRESS/ROADMAP, repository tree, zero open PRs, and recent successful quality gates (including #145 fixture-flow contract). Selected a **dedicated real Zeek binary CI check** to address the previous mocked-Zeek-only limitation; it does not alter the importer, inference, UNSW benchmark, models or SQLite cases.
- Added `.github/workflows/real-zeek-offline-smoke.yml`: an opt-in/PR-triggered Ubuntu 24.04 Python 3.12.9 job generates the existing deterministic benign classic PCAP, runs the official Zeek 9.0.1 Docker image with `--network none`, no Linux capabilities and read-only root filesystem, and verifies its actual `conn.log` against the exact fixture-flow identity, timestamp and declared private CIDR. A synthetic-only artifact contains PCAP, Zeek output/version and checksums for reproduction.
- **At authoring, the new real-Zeek workflow has not passed CI yet; no real Zeek execution is claimed.** Passing this workflow would demonstrate actual binary decoding **on GitHub's Linux runner**, not on the student's Windows/VMware machine. Docker tag is version-specific but not digest-pinned; the runner's image ID is printed for provenance. It does not verify genuine Host-only capture, attack labels, AI detection or SOC latency.
- Student still must run installed Zeek in a Linux VM and separately collect authorized Host-only traffic with independent evidence and labels. Red Team network execution stays disabled.


## 2026-10-29 — First verified real-Zeek binary smoke on GitHub-hosted Linux (PR #147, pre-merge)

- Dedicated [real Zeek workflow #40765032431](https://github.com/tbao4151/DA_CNTT/actions/runs/40765032431) **succeeded** on PR head `bb4b341d9ec9eac65eaaa13b5281cb37a738db3b`. The official `zeek/zeek:9.0.1` container actually ran `zeek -r` against the generated benign synthetic PCAP with Docker `--network none`, dropped capabilities and read-only root filesystem. Zeek reported `zeek version 9.0.1`; actual `conn.log` parsed as **exactly one** matching UDP fixture flow (addresses, ports, protocol and first timestamp). Synthetic artifact upload succeeded.
- Observed PCAP SHA-256 `745b1b4ae0d3d56f0fbb14e1b3a2f85bba4f92d0e3a02d01d1e2baf1816a5551`; generated Zeek `conn.log` SHA-256 `b26395712b16db6fe9f3bed0a243ad3492fda3a43b89fa597d8a6bfa42a2b725`. Zeek image ID and Docker pull digest are recorded in the Actions log; tag itself is not immutable.
- Initial workflow validation failed because `runner.temp` is not valid in job-level `env`; moved directory setup into a step. The first runnable attempt [#40764920011](https://github.com/tbao4151/DA_CNTT/actions/runs/40764920011) failed to write the bind mount due to container UID mismatch; fixed with the runner UID/GID, then the final real-Zeek workflow passed. **Full repository quality gate and PR merge remain pending at this writing.**
- This is the first verified real Zeek **binary** execution in CI, **not** Windows/VMware student execution, a genuine Host-only capture, independent attack ground truth, AI inference, operational SOC alert, or latency measurement. No Dataset Mode benchmark, existing models/cases or active Red Team traffic changed.


## 2026-10-29 — Real Zeek binary smoke CI merged and final-head verified (PR #147)

- [PR #147](https://github.com/tbao4151/DA_CNTT/pull/147) squash-merged into `main` as `6ae0cca55bb515386eb222dbfee445117ce39b1f` after **final-head** [real Zeek workflow #40765257813](https://github.com/tbao4151/DA_CNTT/actions/runs/40765257813) **success** and [full quality gates #40765257770](https://github.com/tbao4151/DA_CNTT/actions/runs/40765257770) **success** (**750 passed, 2 skipped, 2 existing warnings**), both on PR head `78355a061799ef063a2291c1fc631b9bd95abf2f`. PR was mergeable/clean with no competing open PR. This supersedes earlier pending CI/merge notes.
- The official Zeek 9.0.1 binary ran `zeek -r` in a Docker container with `--network none` on the benign synthetic PCAP, produced one exact-matching UDP flow and uploaded synthetic-only evidence. This is **real Zeek on a GitHub-hosted Linux runner**, not student Windows/VMware acceptance, authentic Host-only capture, independent attack labels, measured model accuracy, live alerts or SOC latency. No active Red Team traffic or official UNSW benchmark modification.
- The dedicated workflow triggers on PR paths/manual dispatch, not on main push; **no post-merge main CI result is claimed**. Local Linux VM Zeek smoke and real authorized Host-only experiments remain required.


## 2026-10-29 — Real Zeek → separate lab feature schema smoke (feature; awaiting CI)

- At base `8dc0404179bdca311f303548993e711aef006bce`, checked main README/PROGRESS/ROADMAP, repository tree, recent CI, and confirmed no open PRs. PR #147 real-Zeek binary workflow and PR #148 documentation were already merged; real Zeek 9.0.1 had been verified on a GitHub Linux runner, **not** on the student's VMware laptop.
- Added a fail-closed synthetic fixture check that passes the actual Zeek ASCII `conn.log` through the **separate** nine-column Zeek-lab feature projection, preserving missing optional measurements and excluding UID/IP/time/digest/labels from features. Both the local smoke and real-binary CI workflow call the same check. Added synthetic regression tests for schema/identity exclusion and malformed measurements; the workflow records a schema flag, **not** a model score.
- At authoring, the new feature's PR checks are **not yet verified**. No new UNSW benchmark, trusted Zeek model, real VMware capture, attack ground truth, AI detection metric, automatic alert, SOC case, or Red Team network action is claimed. Windows/VMware local acceptance remains pending.


## 2026-10-29 — Real Zeek → lab feature v1 acceptance merged and verified (#149)

- [PR #149](https://github.com/tbao4151/DA_CNTT/pull/149) squash-merged into `main` at `1e59a1dad44501f208543c9cb3907936fe995890` after the **final PR head** `fe352bbd062f2a52229c480137492b1e5945a69c` passed both [real Zeek 9.0.1 CI #40769267570](https://github.com/tbao4151/DA_CNTT/actions/runs/40769267570) and [Python 3.12.9 quality gate #40769267520](https://github.com/tbao4151/DA_CNTT/actions/runs/40769267520): **753 passed, 2 skipped, 2 existing warnings**. Post-merge [main CI #40769902214](https://github.com/tbao4151/DA_CNTT/actions/runs/40769902214) also **passed**.
- The actual Zeek binary (GitHub Linux runner, network-disabled Docker) produced a benign synthetic `conn.log` that passed the exact fixture-flow check and the separate **nine-feature Zeek lab v1 projection**. The CI log reports `feature_schema_version=1`, `feature_count=9`, `feature_projection_verified=true`. UID/IP/timestamps/source SHA-256/labels are excluded from the projected model features. Local opt-in smoke uses the same contract.
- This proves only a synthetic **PCAP → real Zeek → parser → feature projection** path in GitHub CI, not a trusted trained Zeek model, detection, alert, SOC case, student Windows/VMware acceptance, Host-only isolation or independent ground truth. Dataset Mode official UNSW-NB15 benchmark and Red Team network behavior remain unchanged.


## 2026-10-29 — Real Zeek production importer integration in isolated CI (PR #151)

- Started from `main` `e0315f2053859ce2e64a70b088922cf7b21af65d` after reviewing README, progress/roadmap, source tree, recent GitHub Actions and confirming no competing open PRs.
- [PR #151](https://github.com/tbao4151/DA_CNTT/pull/151) adds a second acceptance stage to `.github/workflows/real-zeek-offline-smoke.yml`: call the **existing** `import_offline_pcap` Python function on the deterministic benign synthetic PCAP, route only the `zeek -r` executable through a `--network none`, capability-dropped Zeek 9.0.1 Docker container, and verify the actual imported `conn.log` via `verify_offline_pcap_import` and nine-feature fixture projection. The importer implementation and official Dataset Mode benchmark are unchanged.
- CI is **pending verification** at the time of this entry; no successful importer run or merge is claimed yet. The new artifact includes `ci_importer_real_report.json`, importer `conn.log`, and `offline_import_report.json` only after success. The import report SHA-256 is computed in the same run and is not an independent provenance anchor.
- This synthetic-only Linux-runner check does not establish a real VMware capture, Host-only isolation, independent labels, AI attack detection, automatic SOC alert, student Windows acceptance or event-to-case latency. No Red Team network action was enabled.


## 2026-10-29 — Real Zeek production offline importer verified and merged (#151)

- [PR #151](https://github.com/tbao4151/DA_CNTT/pull/151) squash-merged as `c3220de30ff715d29ca52c3ea0d6e8182de8f5d8` after final PR head `657d4f528c254659728ce4c902f646dab6bffef6` passed both [real Zeek 9.0.1 workflow #40773929990](https://github.com/tbao4151/DA_CNTT/actions/runs/40773929990) and [full Python 3.12.9 quality gates #40773928870](https://github.com/tbao4151/DA_CNTT/actions/runs/40773928870). The PR was mergeable and main was still at its original base. This supersedes the pending note above.
- The actual production `import_offline_pcap` function processed a **benign synthetic PCAP** via a CI-only `zeek -r` Docker proxy with network disabled. Its output passed independent report/log consistency verification and the exact fixture nine-feature contract. The CI-only proxy is not part of the student CLI. No real VMware capture, independent attack labels, model scoring, AI alerts, SOC cases, or latency were measured.
- The dedicated real-Zeek workflow runs on PR and manual dispatch, not main push. A post-merge run is **not** claimed. Student Linux VM and Windows Host-only acceptance remain unverified; Dataset Mode official UNSW-NB15 and Red Team active traffic were not changed.


## 2026-10-29 — Real Zeek importer → pinned research scoring CI (feature, pending)

- Inspected main at `3d7ee91b58576ed97c3b8e446f505d51fa1e2170`, README/PROGRESS/ROADMAP, source tree, recent Actions and confirmed no open PRs. Selected one isolated integration slice: real Zeek importer output → **existing production** `score_zeek_new_log.py` → `verify_zeek_new_log_report.py`, with PCAP provenance options enabled.
- Added a CI-only fixture runner using an actual Logistic Regression artifact fitted on **arbitrary synthetic test labels** (not independent attack truth). It requires one exact real-Zeek fixture flow, checks that all operational/ground-truth claims remain false, independently recomputes predictions, rejects tampered probabilities and refuses an invalid model SHA-256 pin. Existing production scorer/model/SQLite and UNSW-NB15 benchmark are unchanged.
- Extended the network-disabled real-Zeek GitHub workflow to install scoring dependencies, run the pinned integration check, and upload only a **synthetic-only summary**. Hashes are generated within the same CI run and are **not independently preregistered trust anchors**.
- **At feature authoring, CI and merge are pending; no pass is claimed.** This is not student VMware execution, authorized real capture, independent labels, operational detection, automated alerts, SOC case creation, or a measured attack/latency result. The synthetic model must never be used for research claims or deployment.

- First real-Zeek feature-head workflow [#40778141537](https://github.com/tbao4151/DA_CNTT/actions/runs/40778141537) failed at the new CI-only scoring step: the test fixture module imports `pytest`, which the dedicated workflow had not installed. Zeek binary, fixture projection and production importer steps had already succeeded. The workflow now installs the explicit test dependency; **the corrected head requires new CI verification**. No successful scoring is claimed from the failed run.


## 2026-10-29 — Verified real Zeek → pinned research scoring + independent review (PR #153 merged)

- [PR #153](https://github.com/tbao4151/DA_CNTT/pull/153) squash-merged at `5d4d9acb9af75c3bc9a3c94867da09ae4256e998` after **final feature head** `c0ee61d2c704afc084c1f5fb46d32f7ca9b69369` passed [real Zeek 9.0.1 CI #40778318436](https://github.com/tbao4151/DA_CNTT/actions/runs/40778318436) and [Python 3.12.9 quality gates #40778318423](https://github.com/tbao4151/DA_CNTT/actions/runs/40778318423) (**764 passed, 2 skipped, 2 existing warnings**). Post-merge [main CI #40778687801](https://github.com/tbao4151/DA_CNTT/actions/runs/40778687801) also passed. No competing PR or merge conflict was present.
- The actual Zeek 9.0.1 binary in network-disabled GitHub Linux Docker processed a **benign synthetic PCAP** through the existing production importer. The production pinned scorer then used a CI-only Logistic Regression fitted on **arbitrary synthetic labels**, with original PCAP/import-report checks enabled. Independent recomputation succeeded; deliberately tampered probability and wrong model pin were rejected. The uploaded artifact contains only a clearly labeled synthetic summary, not the CI model or prediction JSON.
- The synthetic model is **not** a validated attack detector. Hashes were generated in the same CI run and do not establish independent trust, label accuracy or provenance. No real VMware capture, Windows laptop execution, Host-only isolation, independent attack ground truth, model performance, SOC case, operational alert, or event-to-SOC latency is claimed. Dataset Mode official UNSW-NB15 benchmark and Red Team network behavior were unchanged.


## 2026-10-29 — Real Zeek synthetic research scoring → explicit manual SOC acceptance (feature; CI pending)

- Reviewed `main` at `d5f32323999029800ee3e645de442e1a5ea0c7e6`, README/PROGRESS/ROADMAP, repository tree, no open PRs, and recent CI. Existing PR #153 real-Zeek pinned-scoring checks were green; the previous synthetic integration did not exercise a SOC write.
- Extended the **CI-only** `tests/ci_real_zeek_scoring.py` acceptance: the original fitted synthetic model remains tested, while a separate neutral-coefficient CI-only artifact (threshold 0.49) deterministically selects one research candidate from the actual Zeek-imported benign PCAP, the production `triage_zeek_new_log.py` lists it without a database, then explicit synthetic-fixture operator confirmations create one private `Unclassified` SQLite case. Exported evidence/audit, source/model/import SHA-256 references, idempotent repeated review, tampered-PCAP rejection and missing-confirmation rejection are checked. Added unit tests for false claims in exported synthetic SOC evidence.
- CI writes the disposable SQLite database only under runner temp and uploads **summary JSON only**, not the DB, synthetic model, private prediction JSON or raw SOC export. The synthetic confirmation means only that this fixture is owned and separate from the CI model's synthetic training rows; it is **not** independent evidence of authorization, Host-only isolation, ground truth or test partition independence.
- **Feature-head CI not yet verified; do not claim successful end-to-end SOC acceptance or merge.** Even after CI passes, this remains a synthetic, analyst-gated *software* integration test, **not** automated alerting, real attack detection, a real VMware capture, measured accuracy/latency, or a student Windows run. Official UNSW-NB15 benchmark and active Red Team behavior remain unchanged.

- Initial feature-head [real-Zeek CI #40782213921](https://github.com/tbao4151/DA_CNTT/actions/runs/40782213921) **failed** because the fitted synthetic model assigned probability zero to the out-of-distribution benign UDP fixture; lowering the threshold could not produce a candidate. Corrected by preserving the fitted-model acceptance and using a separate explicitly neutralized CI-only artifact for the manual-case gate. **Corrected-head CI pending.**


## 2026-10-29 — Real Zeek → synthetic manual SOC acceptance verified and merged (#155)

- [PR #155](https://github.com/tbao4151/DA_CNTT/pull/155) squash-merged as `89c5736a64b97cf80d440dba67afe4a643f810b4` after **final PR head** `451d69e76f3665aa7304de0c8c0a56d801347adf` passed [real Zeek CI #40782784754](https://github.com/tbao4151/DA_CNTT/actions/runs/40782784754) and [Python 3.12.9 quality gates #40782784659](https://github.com/tbao4151/DA_CNTT/actions/runs/40782784659) (**774 passed, 2 skipped, 2 existing warnings**). Main was unchanged and PR was mergeable/clean. Earlier pending/failing feature-head entries are superseded; no post-merge main CI result is claimed here.
- The actual Zeek 9.0.1 binary in network-disabled Linux Docker decoded an owned benign synthetic PCAP. Production importer, separate Zeek feature projection, original fitted synthetic-model research scoring, and independent report review succeeded. For the **manual-case gate only**, a separate CI-only neutralized-coefficient artifact (0.49 threshold, **not trained attack detection**) produced one candidate. Production triage CLI proved read-only listing, explicitly confirmed `Unclassified` SQLite case creation, source/model/import pins, export audit, idempotent repeated review, tampered-PCAP rejection and missing-confirmation refusal.
- The disposable SQLite database, neutral CI model and prediction JSON were **not uploaded**; only synthetic summary evidence was archived. No operational alert, verified attack, real Host-only capture, independent labels, valid holdout model performance, event-to-SOC latency or Windows/VMware student run is established. Dataset Mode official UNSW-NB15 and active Red Team network behavior remain unchanged.


## 2026-10-29: Private offline Zeek telemetry quality screen (feature PR; CI pending)

- Inspected `main` at `60e92397a8b7b3a3b1bb1de6bc888d1ffc94cea2`: no open PRs; PR #155/#156 merged, recent Python quality gate and real Zeek synthetic CI passed. Student-operated Windows/VMware captures and independent labels remain unavailable.
- Added `src/blue_team_ai/telemetry_quality.py` and `scripts/inspect_zeek_telemetry_quality.py` for a bounded, SHA-256-pinned, private **offline** Zeek conn.log quality screen. It reuses CIDR scope and nine-feature projection, refuses duplicate UIDs, and exports only aggregate missing-value/protocol/timestamp-order counts and original event-time bounds; no raw endpoints/UIDs/ports/paths or model scoring.
- Added synthetic regression tests and `docs/ZEEK_TELEMETRY_QUALITY.md` for Windows acceptance. Missing optional fields are counted, not imputed; warnings do not constitute attack labels, detection latency or proof of isolation.
- **At authoring:** feature-head CI, PR merge, post-merge CI and student Windows/VMware acceptance are NOT verified. No change to UNSW official benchmark, SOC database, model or Red Team execution.
- Next: verify PR-head Python 3.12.9 CI and conflict-free merge; students independently collect authorized Host-only PCAP/Zeek evidence, pin source hashes, run private quality screening and independent annotation/holdout evaluation.


## 2026-10-29: Offline Zeek telemetry quality screen merged and CI verified (#157)

- [PR #157](https://github.com/tbao4151/DA_CNTT/pull/157) squash-merged as `5cef10a9deddeea7cba83ade7eb28b610a99f4a7`. Final PR-head [Python 3.12.9 quality gates #40785698571](https://github.com/tbao4151/DA_CNTT/actions/runs/40785698571) and post-merge [main quality gates #40786278275](https://github.com/tbao4151/DA_CNTT/actions/runs/40786278275) **both passed**; PR head had **782 passed, 2 skipped, 2 pre-existing warnings**. This supersedes the earlier pending feature merge item.
- Verified code is a read-only, private, SHA-256-pinned Zeek log quality CLI with CIDR membership, exact nine-feature schema, duplicate-UID refusal and aggregate missingness/protocol/timestamp-order summaries. Tests are synthetic, not real student captures; no inference, operational alert, SOC write or Red Team traffic.
- Student must independently validate VMware Host-only adapter/routes, run real Zeek on an authorized genuine PCAP, record separate SHA-256 pins, then run the private quality CLI before independent annotation/host-disjoint evaluation. No genuine attack-detection metrics or Windows laptop evidence exist yet.


## 2026-10-29: Real Zeek → production telemetry-quality acceptance (feature PR; CI pending)

- Reviewed `main` at `92a96b8f432477eaa3b1528e47cb13e75a8f155f`, README/PROGRESS/ROADMAP, repository tree, latest GitHub Actions and open PRs (none). PR #157/#158 were already merged; recent Python quality gates passed. No student VMware/Windows capture is available.
- Extended the **existing** real-Zeek offline CI workflow to run the production read-only `scripts/inspect_zeek_telemetry_quality.py` against the importer-generated **real Zeek 9.0.1** `conn.log` for an owned benign synthetic UDP PCAP. It checks schema/count, privacy-safe aggregates, non-operational flags, wrong-hash and wrong-CIDR rejection, no-overwrite behavior and byte-identical source retention. Artifact contains only a clearly identified synthetic quality JSON; no model/DB/secrets changed.
- **At authoring, feature-head CI and merge are not verified.** The pin is generated in the same CI job and is not independent provenance. No authorized real capture, Host-only isolation, attack ground truth, trustworthy AI detection, event-to-SOC latency or Windows laptop test is claimed. Dataset Mode UNSW-NB15 and Red Team network behavior are unchanged.
- Next: verify both final-head Python quality gates and real-Zeek workflow, merge only if conflict-free; student runs the quality CLI on separately pinned private Windows/VMware evidence and performs independent labeling/holdout evaluation.


## 2026-10-29: Real Zeek telemetry quality CLI acceptance merged (#159)

- [PR #159](https://github.com/tbao4151/DA_CNTT/pull/159) squash-merged at `8d517fcbee9525fa5cdcfc13feb25e7c6c5da5b9` after final feature-head [real Zeek 9.0.1 workflow #40788858404](https://github.com/tbao4151/DA_CNTT/actions/runs/40788858404) and [Python 3.12.9 quality gates #40788858348](https://github.com/tbao4151/DA_CNTT/actions/runs/40788858348) both **passed** (**782 passed, 2 skipped, 2 pre-existing warnings**). No competing PR or conflict at merge. This supersedes the pending feature entry above.
- Production `inspect_zeek_telemetry_quality.py` accepted actual Zeek output from an **owned synthetic benign UDP PCAP**; wrong hash, wrong CIDR and overwrite were rejected; source bytes remained unchanged. The workflow uploaded a synthetic-only quality JSON artifact. The pin was computed in the same CI job, not independently established.
- No Windows/VMware capture, physical Host-only isolation, independently verified attack labels, Zeek model accuracy, operational alerts or event-to-SOC latency is established. UNSW-NB15 benchmark, model/SQLite state and Red Team active network behavior remain unchanged. Post-merge main CI was not verified at this documentation update.


## 2026-10-29: Optional manifest-wide Zeek telemetry quality gate (feature PR, verification pending)

- Inspected `main` at `10073589c2ee031c7e189af37fc22f900b9b36f7`, README/PROGRESS/ROADMAP, source, recent CI and open PRs (none); PR #159/#160 already merged. Existing Zeek quality CLI has real-Zeek synthetic CI acceptance, but student VMware/Windows evidence and independently verified attack labels remain absent.
- Proposed `--require-telemetry-quality` in the **existing** offline Zeek research CLI. With explicit `--cidr`, every already SHA-256-pinned TRAIN/VALIDATION/TEST capture is screened using the existing private Zeek quality contract before model fitting. Only fixed per-split aggregates are included in opt-in preflight/research output; missingness/timestamp warnings are descriptive, not labels or automatic exclusions. Legacy output remains unchanged without the flag.
- Added synthetic regression tests and Windows guidance. At authoring, **PR-head CI, merge, post-merge CI and laptop acceptance are NOT yet verified**. No operational alert, authentic Host-only capture, attack detection or measured latency is claimed; official UNSW-NB15, model/SQLite artifacts and active Red Team behavior are untouched.
- Next: confirm Python 3.12.9 PR-head CI and conflict-free merge; students run private pinned, host/session-disjoint research inputs only after genuine authorized capture and independent labeling.


## 2026-10-29: Manifest-wide Zeek telemetry quality gate merged (#161)

- [PR #161](https://github.com/tbao4151/DA_CNTT/pull/161) squash-merged at `1de58dffcc766c65cab82da2e66a07a3c9d2f31d` after final-head [Python 3.12.9 quality gates #40792521743](https://github.com/tbao4151/DA_CNTT/actions/runs/40792521743) **passed** (**786 passed, 2 skipped, 2 pre-existing warnings**). No conflicting open PR existed at merge. This supersedes the earlier feature PR pending item.
- With explicit `--require-telemetry-quality --cidr`, the production offline experiment CLI now screens all manifest captures and records only fixed aggregate quality counters by TRAIN/VALIDATION/TEST. Legacy behavior is unchanged without opt-in; synthetic tests cover privacy, missing-scope refusal, tampering and all CLI modes.
- **Post-merge main CI #40792986576 was still running at this documentation authoring point.** No Windows/VMware student capture, independent attack ground truth, real detection accuracy, operational alert or event-to-SOC latency has been verified. This is a research-input gate, not proof of lab isolation.

## 2026-10-29 — Windows Python 3.12.9 offline Zeek contract CI (PR #163, verification pending)

- Read main README/PROGRESS/ROADMAP, repository tree, recent GitHub Actions and open PRs at base `88d889ff55c198d5ff50f11ed27492b5c6e81c69`; no competing open PR at branch creation. Previous #161/#162 manifest-quality work was already merged; recent Linux quality CI was green.
- Added `.github/workflows/windows-offline-zeek.yml` and `docs/WINDOWS_OFFLINE_ZEEK_CI.md`. The dedicated GitHub-hosted Windows Server 2022 job pins Python **3.12.9** and exercises existing synthetic-only offline manifest/holdout, Zeek quality, PCAP import/provenance, research inference and analyst-confirmed SQLite SOC regression tests. No new model, dataset, database migration or attack capability.
- [PR #163](https://github.com/tbao4151/DA_CNTT/pull/163) is open. **At authoring, Windows and Linux PR-head CI, mergeability and merge are not yet verified.** No Windows test success is claimed.
- This is a Windows GitHub runner, **not** the student's Windows 11 laptop, VMware Host-only acceptance, real Zeek execution on Windows, authentic capture, independent attack labels, attack detection accuracy, operational alerts or measured event-to-SOC latency. Real-Zeek Linux synthetic CI remains separate. Official UNSW-NB15 benchmark and active Red Team behavior unchanged.

### Windows offline CI — first verified PR-head checks (#163)

- PR #163 head `edf587bfc492b1619c5a6f313dae2375be0b1dca` passed [Windows Server 2022 / Python 3.12.9 workflow #40795902419](https://github.com/tbao4151/DA_CNTT/actions/runs/40795902419): **74 passed** on existing synthetic offline Zeek/PCAP/manifest/SOC regression tests. Windows test execution took 118.93 s; real Zeek/VMware was not invoked.
- The same head passed [Ubuntu Python 3.12.9 full quality gates #40795902460](https://github.com/tbao4151/DA_CNTT/actions/runs/40795902460): **786 passed, 2 skipped, 2 existing pandas warnings**. These results were read from completed Actions job logs, not inferred from a queued status.
- This documentation commit changes the PR head, so **new final-head CI must be verified before merge**. No student Windows 11, Linux VM Zeek, genuine Host-only capture, real attack detection or latency claim.

## 2026-10-29 — Windows offline Zeek CI verified and merged (#163)

- [PR #163](https://github.com/tbao4151/DA_CNTT/pull/163) squash-merged as `103107c7d9edcd7d45f947007189b1c2702e7303` after **final PR head** `378bb06b07a61b093df8806f7bf6b488225c3afd` passed both [Windows Server 2022 / Python 3.12.9 CI #40796453742](https://github.com/tbao4151/DA_CNTT/actions/runs/40796453742) and [Ubuntu Python 3.12.9 quality gates #40796453732](https://github.com/tbao4151/DA_CNTT/actions/runs/40796453732). The PR was clean/mergeable and main remained at the reviewed base; no competing open PR at merge.
- Windows ran **74 passed** targeted synthetic-only offline Zeek manifest, telemetry-quality, PCAP/provenance, inference and manual SQLite SOC regression tests. Ubuntu full quality suite passed **786 tests, 2 skipped, 2 pre-existing warnings**. No model training on genuine lab data, no operational alerts or attacks. This is the first dedicated Windows-hosted CI gate for these offline paths, not a student laptop/VMware result.
- Dedicated Windows workflow is PR/manual-only, and the existing main quality workflow's push path filter excludes docs/new workflow files; **no post-merge main CI is claimed**. The next student acceptance still requires local Windows 11 Python 3.12.9 test execution, verified Host-only VMware network, Linux Zeek smoke, private authorized PCAP and independent labels/holdout before research metrics.


## 2026-10-29 — Optional UID-independent Zeek split-overlap screen (feature branch)

- Inspected current `main` at `48c8566a63a5f3210a460d9b68669c8204ca97a2`, README, PROGRESS, ROADMAP, repository layout, open PRs (none), and recent Windows/Linux CI. PR #163 Windows offline Zeek acceptance was already merged; latest Windows CI was green on GitHub-hosted Windows Server 2022, not the student's laptop.
- Added an **opt-in** offline research guard `--require-uid-independent-overlap` to compare timestamp/five-tuple across declared TRAIN/VALIDATION/TEST even if Zeek UID was regenerated. It rejects overlaps before fitting or writing reports and emits only aggregate counts when enabled. Added synthetic CLI regression tests and Windows research guidance; default behavior and UNSW benchmark are unchanged.
- **At authoring, PR-head CI, merge and student Windows/VMware acceptance are not yet verified.** The screen is an exact conservative overlap heuristic, not proof of independent capture, genuine labels or Host-only isolation. No active Red Team, live traffic, operational alert or real attack-detection metric is claimed.
- Next: verify final PR-head Python 3.12.9 Ubuntu/Windows CI and clean mergeability; only merge after green checks. Students still need genuine authorized Host-only PCAP/Zeek captures, independent labels and host/session-disjoint held-out evaluation.


## 2026-10-29 — UID-independent Zeek split-overlap gate merged (#165)

- [PR #165](https://github.com/tbao4151/DA_CNTT/pull/165) squash-merged as `03e2e8b6f05b612c6a5751b16c64329e2924d9dc` after **final-head** [Ubuntu Python 3.12.9 CI #40798459769](https://github.com/tbao4151/DA_CNTT/actions/runs/40798459769) passed (**788 passed, 2 skipped, 2 existing warnings**) and [Windows Server 2022 Python 3.12.9 CI #40798459757](https://github.com/tbao4151/DA_CNTT/actions/runs/40798459757) passed (**76 passed**). PR was clean/mergeable and main matched the reviewed base; earlier pending verification entry is superseded.
- New opt-in `--require-uid-independent-overlap` rejects timestamp/five-tuple reuse across TRAIN/VALIDATION/TEST even if Zeek UIDs differ, before fitting or writing output. Regression tests are synthetic and offline. The screen is conservative, can reject legitimate simultaneous flows, and cannot establish genuine capture independence, label truth, or Host-only isolation. No operational alerts, model changes, SQLite writes or Red Team traffic were added.
- **Post-merge main CI was queued at documentation authoring; not claimed passed.** Windows CI ran on GitHub infrastructure, not the student's Windows 11/VMware. Genuine authorized PCAP, independent annotation and measured held-out detection/latency remain outstanding.


## 2026-10-29 — One-switch strict offline Zeek input gates (feature PR; CI pending)

- Reviewed current `main` at `a9c1c3505505b66472881ebda6056f59fa722f93`, README/PROGRESS/ROADMAP, source tree, latest Actions and open PRs (none); #165/#166 UID-independent overlap work was already merged and prior Windows/Ubuntu CI was green.
- Added opt-in `--strict-input-gates` to the existing offline research CLI. It composes the already-implemented label SHA-256 pinning, manifest-wide Zeek telemetry quality and UID-independent cross-split overlap screens; requires explicit lab CIDR and applies equally to preflight, aggregate and private trace modes. Legacy CLI and report schema remain unchanged without opt-in.
- Added synthetic CLI regression tests for parity with the three explicit flags, successful preflight/report, missing CIDR/pins, overlap, tampered labels, privacy and no-output-on-refusal. Updated Windows guidance. No dataset, model, SOC DB, network execution or benchmark change.
- **At authoring: feature-head CI, PR merge and student Windows/VMware acceptance are not verified.** Strict input consistency cannot establish independent labels, genuine Host-only capture, detection accuracy or latency. Next: verify PR-head Windows and Ubuntu Python 3.12.9 CI, merge only when clean, then collect independent private lab evidence on the student's laptop.


## 2026-10-29 — Strict offline Zeek input gate bundle merged (#167)

- [PR #167](https://github.com/tbao4151/DA_CNTT/pull/167) squash-merged as `8e59df3c5709502febb067f4b9e68966ec18e57d` after final feature head `e388c763cf9d0db96a7e6571cc6f3e58e6962977` passed [Ubuntu Python 3.12.9 quality gates #40801801187](https://github.com/tbao4151/DA_CNTT/actions/runs/40801801187) (**791 passed, 2 skipped, 2 existing warnings**) and [Windows Server 2022 Python 3.12.9 offline CI #40801801069](https://github.com/tbao4151/DA_CNTT/actions/runs/40801801069) (**79 passed**). Both test counts were read from completed job logs; PR was clean/mergeable and main matched the reviewed base. This supersedes the feature-branch pending verification entry above.
- Opt-in `--strict-input-gates` combines existing label-byte SHA-256 pins, explicit-CIDR Zeek telemetry quality and UID-independent cross-split overlap screening for preflight, report and private trace. Windows CI now exercises the synthetic strict CLI regressions; default CLI, official UNSW benchmark, model, SOC data and active Red Team behavior are unchanged.
- **Post-merge main CI and student laptop/VMware acceptance were not verified at this documentation authoring point.** CI is synthetic/offline; it cannot establish physical Host-only isolation, independent labels, attack detection, precision/recall/FPR or measured event-to-SOC latency. Students must collect and preserve authorized private VMware/Zeek evidence and run strict preflight locally before scientific evaluation.


## 2026-10-29 — Optional independent Zeek experiment manifest pin (feature PR; verification pending)

- Inspected current `main` at `03336d3c03e0c8ea7f1d4864335c2f54b7ee92fe`, README/PROGRESS/ROADMAP, source/tree, latest GitHub Actions and open PRs (none). PR #167/#168 strict-input-gate work is merged; the preceding Windows/Ubuntu CI was green on synthetic fixtures.
- Added opt-in `--expected-manifest-sha256` to the existing offline Zeek research CLI. It validates a separately recorded **exact manifest-byte** SHA-256 before parsing, fitting or writing either report or trace; preflight and evaluation share the same pin. Successful opt-in reports only a boolean pin verification, while unpinned legacy output remains unchanged.
- Added synthetic CLI regression coverage for matching pins, metadata-only manifest edits between preflight and evaluation, malformed/unmatched hashes, output/trace refusal and privacy/no-write behavior. Updated Windows evidence procedure. No UNSW benchmark, model artifact, SQLite, network action or Red Team execution was changed.
- **At authoring: feature-head Ubuntu/Windows CI, PR merge and student Windows/VMware acceptance are not verified.** This controls byte consistency, not authorship, independent ground truth, physical isolation or genuine attack detection. Next: verify final-head cross-platform CI and conflict-free merge, then students must preserve the manifest pin independently and perform authorized Host-only/Zeek experiments with separately validated labels.


## 2026-10-29 — Independently pinned offline Zeek manifest merged (#169)

- [PR #169](https://github.com/tbao4151/DA_CNTT/pull/169) squash-merged at `a8af18d2cabfc5320bff8dbf4091f046a76872d3` after final feature head `e8bbe57a13d525e256f9d72e3e1c0dbe7bc35fa0` passed [Ubuntu Python 3.12.9 quality gates #40804453810](https://github.com/tbao4151/DA_CNTT/actions/runs/40804453810) (**799 passed, 2 skipped, 2 warnings**) and [Windows Server 2022 Python 3.12.9 offline CI #40804453793](https://github.com/tbao4151/DA_CNTT/actions/runs/40804453793) (**87 passed**). Both completed successfully and the PR was clean/mergeable with no competing PRs. This supersedes the pending feature entry above.
- Optional `--expected-manifest-sha256` now binds exact manifest bytes to a separately recorded pin across preflight, aggregate report and private trace. Synthetic tests cover changed manifest metadata after preflight, malformed/unmatched pins, refusal without writes and privacy; unpinned CLI/report behavior is unchanged. No new model, operational alert, SQLite write, network traffic, Red Team action or UNSW benchmark modification.
- **Main post-merge CI #40804908516 was queued when checked; not claimed passed.** Windows CI was GitHub-hosted, not the student's Windows 11/VMware. A manifest digest is not a signature, proof of independently authenticated labels or genuine capture; authorized student Host-only evidence, scientific held-out metrics and measured event-to-SOC latency remain outstanding.


## 2026-10-29 — Red Team offline proposal-to-feedback audit (feature PR, CI pending)

- Reviewed `main` at `adc5faeca9a5cfa8e28663510804e29bbe3c0a9c`, README, PROGRESS, ROADMAP, source/UI tree, existing Red Team planner, open PRs (none) and recent Actions. PR #169 manifest pin was already merged; post-merge main Python CI #40804908516 completed successfully. No parallel open feature work was found at the check.
- Added `src/red_team_ai/planning_audit.py`: bounded in-memory, strictly typed, reproducible policy proposal and linked manual-feedback timeline. Each proposal records policy, seed, ID and button-action UTC time. Policy decisions are recomputed from preceding linked feedback; duplicate/unlinked feedback, arbitrary scenario IDs, non-UTC/out-of-order timestamps, unsafe/executable flags and forged verified outcomes are rejected. No network access, replay, exploit, disk write, SOC case or model change.
- Updated `pages/2_Red_Team_Lab.py` to require a pending proposal before manual feedback, display/export an offline-only JSON timeline, and clear session state on stop. Added synthetic contract and Streamlit UI integration regression tests; updated the Red Team operator guide.
- **At authoring: PR-head Ubuntu Python 3.12.9 CI, merge and student Windows/VMware acceptance are not yet verified.** The event timestamps are UI action times, not event/detection latency. Feedback is operator-entered, unverified and never ground truth. The export is unsigned/editable; no active Red Team or operational alert. The official UNSW-NB15 benchmark and existing SOC data are unchanged.
- Next: verify the final PR-head full quality suite and clean mergeability before merge. Student should run the Red Team UI/test on Windows 11, then separately build and verify an authorized VMware Host-only lab and gather genuine independently labeled Zeek captures before any scientific AI-vs-AI evaluation.


## 2026-10-29 — Red Team offline planning audit verified and merged (#171)

- [PR #171](https://github.com/tbao4151/DA_CNTT/pull/171) squash-merged as `174b58eade7087d18c476fcdf45445ccedd6b235` after the final feature head `0b7bd29df670660e6aff5ef523ae34982357b598` was clean/mergeable against unchanged `main` and both required GitHub-hosted Python 3.12.9 workflows passed: [Ubuntu quality gates #40807809739](https://github.com/tbao4151/DA_CNTT/actions/runs/40807809739) (**811 passed, 2 skipped, 2 warnings**) and [Windows offline contracts #40807809829](https://github.com/tbao4151/DA_CNTT/actions/runs/40807809829) (**87 Zeek tests + 29 Red Team tests passed**). Counts were read from completed job logs.
- The Red Team UI now links every operator-entered feedback record to a single pending non-executable UCB1/random proposal, stores policy/seed/UTC UI-action chronology in bounded Streamlit session state and exports an explicitly unverified JSON timeline. A reproducible policy replay rejects forged decisions and unlinked/duplicate feedback; the stop control clears session state only.
- Main post-merge Ubuntu CI [#40808321034](https://github.com/tbao4151/DA_CNTT/actions/runs/40808321034) was queued when checked and is **not** claimed passed. Windows tests ran on GitHub-hosted Windows Server 2022, not the student's laptop. No real lab capture, replay, attack, Blue Team outcome, operational alert, detection metric or event-to-SOC latency was verified. UNSW-NB15 official benchmark, model and SQLite cases were not modified.


## 2026-10-29 — Offline Red Team exported-audit verifier (feature; CI pending)

- Reviewed main at `4c1af8d1492d05922adc7a2f146a9e12fe140b86`, README, PROGRESS, ROADMAP, tree, recent CI and open PRs (none). Latest Red Team offline planning audit #171 and documentation #172 are merged; main #171 quality gate #40808321034 succeeded. #172 only changed docs and did not trigger the code-path-filtered main CI.
- Added `src/red_team_ai/audit_verify.py` and read-only `scripts/verify_red_team_planning_audit.py` to validate exported session JSON, reject duplicate keys/non-finite values/forged envelope or events, replay all UCB1/random proposals, and optionally compare exact file SHA-256 with an independently preserved pin. Bounded private-file read, no output writes, no network, no SOC or model changes.
- Added synthetic tamper, CLI and safety regressions on Ubuntu and Windows workflow plus a private Windows procedure. **At authoring, final-head CI, merge and student laptop acceptance are pending.** A valid planning audit is NOT authenticated Blue Team evidence, a detection measurement or a real attack; operator feedback remains unverified and timestamps are UI actions only.
- Next: verify final PR-head Ubuntu/Windows CI and conflict-free merge; student exports and pins private planning timeline on Windows, then independently gathers authorized Host-only Zeek captures and adjudicated labels for scientific evaluation. UNSW-NB15 benchmark and active Red Team network-disabled state are unchanged.


## 2026-10-29 — Red Team offline audit independent verifier merged (#173)

- [PR #173](https://github.com/tbao4151/DA_CNTT/pull/173) squash-merged as `106a3cd00f486812786b254ee120a771284b7999` after final feature head `ce6948ca83134c61c364697e9f20b0133d11b452` was clean/mergeable against unchanged `main`. [Ubuntu Python 3.12.9 #40811105273](https://github.com/tbao4151/DA_CNTT/actions/runs/40811105273) completed **827 passed, 2 skipped, 2 warnings**; [Windows Server 2022 Python 3.12.9 #40811105170](https://github.com/tbao4151/DA_CNTT/actions/runs/40811105170) completed **87 offline Zeek tests + 45 Red Team tests passed**. [Post-merge main Ubuntu CI #40811595051](https://github.com/tbao4151/DA_CNTT/actions/runs/40811595051) also completed successfully (**827 passed, 2 skipped, 2 warnings**). This supersedes the earlier pending feature entry.
- Verified CLI parses private exported Red Team planning JSON, replays UCB1/random choices, rejects forged metadata, duplicate keys, invalid events, non-finite JSON and changed exact bytes against a separately recorded optional SHA-256 pin. No network, replay, attack, SQLite, model or official UNSW-NB15 benchmark change.
- GitHub-hosted Windows Server tests are NOT student Windows 11/VMware acceptance. The verifier cannot authenticate operator-entered feedback, actual Blue Team outcomes, Host-only isolation or event-to-SOC latency; no independent lab attack detection has been demonstrated. Students must preserve a private export and independent pin and separately collect genuine authorized Zeek/annotation evidence.


## 2026-10-29 — Red Team pending-proposal UI consistency (feature PR; CI pending)

- Reviewed `main` at `278ec1da8ca5efdb4502ea4135578c6550937bf3`, README/PROGRESS/ROADMAP, source and tests, latest completed Actions, and zero open PRs. PR #173/#174 offline audit verifier work is already merged; no competing open PR was observed.
- Changed `pages/2_Red_Team_Lab.py` to reconstruct the displayed pending scenario from the validated planning chronology and its recorded policy/seed, rather than a separate potentially missing or stale `red_team_last_plan` session cache. The audit remains the sole authority for linking manual feedback. Added Streamlit AppTest regression for a stale forged cache and a missing cache after rerun; updated the Red Team guide.
- **At authoring: feature-head Ubuntu/Windows Python 3.12.9 CI, merge and student laptop acceptance are pending.** No attack, replay, live traffic, verified Blue Team outcome, operational alert, VMware evidence or scientific detection metric is claimed. Dataset Mode, UNSW benchmark, model and SQLite are unchanged.
- Next: verify both final-head CI workflows, merge only if green and conflict-free, then student tests the Red Team page and audit export on Windows 11. Genuine authorized Host-only capture, independent labels and event-to-SOC timing remain necessary for research claims.


## 2026-10-29 — Red Team pending-proposal replay UI verified and merged (#175)

- [PR #175](https://github.com/tbao4151/DA_CNTT/pull/175) squash-merged as `aa0e0329565f1b9bbb9de271b8a75cb8870258ec` after final feature head `5ecf9d3a631a62fe007ef1bad4b09b9dd2d7aafc` was clean/mergeable against unchanged `main`. [Ubuntu Python 3.12.9 quality gates #40813579884](https://github.com/tbao4151/DA_CNTT/actions/runs/40813579884) succeeded (**828 passed, 2 skipped, 2 warnings**) and [Windows Server 2022 Python 3.12.9 #40813579774](https://github.com/tbao4151/DA_CNTT/actions/runs/40813579774) succeeded (**87 offline Zeek + 46 Red Team tests passed**). Counts came from completed job logs. Supersedes the preceding feature CI-pending note.
- Red Team Streamlit reconstructs a pending plan from the validated audit's recorded strategy and seed, rather than a separate stale/missing UI session cache. The regression injects a forged stale plan and then a missing cache across reruns; the UI still displays the audited pending scenario. No scenario execution, network, SOC write, model or UNSW benchmark change.
- **Post-merge main CI and student Windows 11/VMware acceptance were not verified at this documentation authoring point.** All policy feedback is operator-entered and unverified. Real authorized Host-only capture, independent labels, Blue Team outcomes, scientific policy comparison and event-to-SOC latency remain outstanding.


## 2026-10-29 — Optional Zeek ASCII declared-types gate (feature; CI pending)

- Reviewed main `4a409e8a1aee94b89c36ad280c617baccbe5784f`, README, PROGRESS, ROADMAP, source tree, no open PRs and recent green Ubuntu/Windows Actions. PR #175/#176 are already merged; latest main quality run #40814135633 succeeded.
- Added an **opt-in** Zeek `#fields`/`#types` compatibility gate to private telemetry quality CLI and manifest-wide offline preflight/evaluation. It validates seven required and six optional model-relevant Zeek types, rejects absent/duplicate/late/mismatched declarations, and exports aggregate schema counts without raw endpoints. Existing parser and `--strict-input-gates` behavior remain unchanged by default.
- Added synthetic fail-closed tests on Ubuntu/Windows and made the network-disabled **real Zeek 9.0.1** synthetic CI quality step exercise `--require-zeek-types`. At authoring, final-head CI, merge and student Windows 11/VMware acceptance are **pending**; code changes alone are not evidence of a passing run.
- Next: verify final PR-head Ubuntu/Windows and real-Zeek CI, merge only if green/conflict-free; student separately checks a genuine authorized Host-only `conn.log`, retaining independent hashes and isolation evidence. Declared types cannot authenticate provenance, ground truth or attack detection. No UNSW model, SQLite, network execution or benchmark changes.


## 2026-10-29 — Zeek declared-types gate verified and merged (#177)

- [PR #177](https://github.com/tbao4151/DA_CNTT/pull/177) squash-merged as `a3be271ebd800b7df7903ebdc8bf789c9ceb31e4` after final head `71ac0ee9bb2ac3dcabbe3528e818dac6180cb725` was clean/mergeable against unchanged main. [Ubuntu Python 3.12.9 #40816621940](https://github.com/tbao4151/DA_CNTT/actions/runs/40816621940) succeeded (**839 passed, 2 skipped, 2 warnings**); [Windows Server 2022 Python 3.12.9 #40816621786](https://github.com/tbao4151/DA_CNTT/actions/runs/40816621786) succeeded (**98 offline Zeek + 46 Red Team tests passed**). [Real Zeek 9.0.1 offline network-disabled CI #40816621990](https://github.com/tbao4151/DA_CNTT/actions/runs/40816621990) succeeded using a synthetic benign PCAP and production quality CLI with `--require-zeek-types`.
- An initial PR-head CI run failed **only** because a new test expected the wrong error-message wording; the assertion was corrected before the successful final-head checks. The implementation was not merged while CI was failing. Post-merge main CI and student Windows 11/VMware acceptance are tracked separately, not claimed passed here.
- The opt-in type gate checks declared Zeek header compatibility on a single pinned log or all pinned TRAIN/VALIDATION/TEST captures; no default parser/strict-input-gates change, UNSW benchmark change, network traffic, model deployment or SOC database write. Passing CI does **not** prove student Host-only isolation, independent attack labels, genuine attack detection or end-to-end latency.


## 2026-10-29 — Opt-in offline Zeek event-start UTC window gate (feature, CI pending)

- Reviewed main `78c41dcf08dd3acccf016cf16fd644f845cb2aa2`, README/PROGRESS/ROADMAP, source tree, recent Actions and open PRs (none). #177/#178 declared-type gate and documentation are already merged; latest observed PR-head quality workflow #40817111285 succeeded.
- Added an optional **single-log** `--event-start-utc` / `--event-end-utc` check to the pinned offline Zeek telemetry-quality CLI. Both canonical UTC bounds are required; invalid, reversed or out-of-window Zeek connection-start timestamps fail before report creation. Existing unflagged CLI behavior, UNSW benchmark, models, SOC data and network-disabled Red Team are unchanged.
- Added synthetic unit/CLI regressions, Windows Python 3.12.9 CI inclusion and a private evidence procedure. The output records only that the operator-declared window was checked; it does not expose the declared bounds, raw IPs or UIDs and does not calculate latency.
- **At authoring: final PR-head Ubuntu/Windows CI, merge and student laptop/VMware acceptance are pending.** Operator-declared bounds and Zeek `ts` cannot authenticate actual capture time, clock accuracy, physical Host-only isolation, independent labels or event-to-SOC latency.
- Next: verify both PR-head workflows and mergeability before merge; student records the genuine capture window and independent hashes privately, tests the gate on their own Windows 11/VMware Zeek log and retains original evidence. Real labeled held-out Zeek evaluation remains outstanding.


## 2026-10-29 — Zeek event-start UTC window gate verified and merged (#179)

- [PR #179](https://github.com/tbao4151/DA_CNTT/pull/179) squash-merged as `997bef7774daa6b2f405854fd30b59f8671eb9e1` after final feature head `4fd53fc083dd5e36411dc4af9dc1b1f9718aa6bc` was clean/mergeable against unchanged `main`. [Ubuntu Python 3.12.9 quality CI #40819653212](https://github.com/tbao4151/DA_CNTT/actions/runs/40819653212) passed (**852 passed, 2 skipped, 2 warnings**), [Windows Server 2022 Python 3.12.9 CI #40819653198](https://github.com/tbao4151/DA_CNTT/actions/runs/40819653198) passed (**111 offline Zeek + 46 Red Team tests**), and [real Zeek synthetic offline CI #40819653215](https://github.com/tbao4151/DA_CNTT/actions/runs/40819653215) succeeded. The latter is existing Zeek smoke, not a real-world capture or event-window experiment.
- The initial Ubuntu PR-head CI failed because the added interpretation text contained the word `latency`, violating an existing regression asserting the quality report makes no latency claim. Corrected both report wording and new test before the successful final-head runs. No failure was merged.
- New optional paired canonical UTC bounds constrain every **Zeek connection-start timestamp** in a single pinned offline `conn.log` quality check; legacy mode is unchanged. This is not actual capture-clock attestation, an operational alert, an event-to-SOC latency measurement, or a manifest-wide validation. No new attack detection, independent labels, VMware Host-only verification or student laptop acceptance is claimed. UNSW benchmark, model, SQLite and network-disabled Red Team unchanged.
- **Post-merge main CI is not yet verified at documentation authoring.** Student must independently pin genuine authorized capture window, PCAP/log SHA-256, Zeek version, VM/host clocks and isolation evidence and test on Windows 11 before reporting local acceptance.


## 2026-10-29 — Manifest-wide pinned Zeek UTC event-start gate (feature PR; CI pending)

- Read current `main` at `c2d40c321c6fc3f35889ecd777cb5daf084b79df`, README/PROGRESS/ROADMAP, tree, offline experiment and quality code, recent GitHub Actions and open PRs (none). #179/#180 are merged; latest observed main quality run #40820133193 succeeded. No competing open work at inspection.
- Added opt-in paired `--event-start-utc` / `--event-end-utc` to `scripts/evaluate_zeek_lab.py`: all already-pinned TRAIN/VALIDATION/TEST Zeek logs must have connection-start timestamps inside the same operator-declared canonical UTC interval before research fit or report write. Uses the existing single-log quality validator, requires explicit lab CIDRs, rejects missing/malformed/reversed/out-of-range bounds and preserves legacy unflagged behavior.
- Added synthetic preflight, report, refusal/no-output and Windows-targeted CLI regressions; documented private Windows procedure. No attack, replay, live network, operational alert, SOC DB write, model/benchmark change or claim of genuine laptop testing.
- **At authoring, final PR-head Ubuntu/Windows CI and merge are not yet verified.** The gate checks log consistency only, not authentic collection time, host clock, physical isolation, independent attack labels, or event-to-SOC timing. Student must record real authorized capture windows and independent PCAP/log hashes privately and evaluate genuine host/session-disjoint labels before any scientific detection claim.


## 2026-10-29 — Manifest-wide Zeek UTC event-start gate verified and merged (#181)

- [PR #181](https://github.com/tbao4151/DA_CNTT/pull/181) squash-merged at `f37d9d2d0ad3127c8720e2f722d2a288ab424013` after final feature head `6d809419fce7dcd441b3849e3f260af6e4d6a5d3` was clean/mergeable against unchanged `main`. [Ubuntu Python 3.12.9 quality CI #40821573729](https://github.com/tbao4151/DA_CNTT/actions/runs/40821573729) passed (**861 passed, 2 skipped, 2 warnings**); [Windows Server 2022 Python 3.12.9 #40821573777](https://github.com/tbao4151/DA_CNTT/actions/runs/40821573777) passed (**120 offline Zeek + 46 Red Team tests**); [real Zeek 9.0.1 network-disabled synthetic smoke #40821573782](https://github.com/tbao4151/DA_CNTT/actions/runs/40821573782) passed. The real-Zeek workflow covers existing synthetic PCAP smoke, **not** a manifest-wide real-capture experiment.
- All pinned manifest captures can now be checked against one optional operator-declared canonical UTC connection-start interval before preflight or evaluation. Synthetic tests cover valid intervals, missing/malformed/reversed/out-of-range bounds, fail-before-output, legacy behavior and privacy. No live capture, attack, operational alert, SQLite write, model deployment or UNSW-NB15 benchmark change.
- **Post-merge main CI #40822084346 was queued when inspected, not claimed passed.** GitHub-hosted Windows Server tests are not the student's Windows 11/VMware run. The operator window does not attest capture clocks, independent labels, physical Host-only isolation or actual event-to-alert/SOC timing. Student must independently archive genuine authorized PCAP/Zeek captures, hashes, clock/isolation evidence and held-out labels.



## 2026-10-29 — Optional Zeek originator-address split screen (feature; CI pending)

- Reviewed main at `e3a9541daabc44339bef046e6b24b3ef10135801`, README, PROGRESS, ROADMAP, Zeek manifest/holdout implementation, recent #181/#182 merges, no open PRs, and the previously queued main quality job #40822084346 (completed successfully when inspected). No overlapping open work was observed.
- Added opt-in `--require-originator-ip-disjoint` to the **offline** pinned Zeek manifest preflight, evaluation and private trace paths. It rejects any normalized Zeek `id.orig_h` reused between TRAIN/VALIDATION/TEST even when operator `host_group` labels and Zeek UIDs differ, while permitting shared destination servers. The report contains only aggregate unique-originator counts and explicit non-attestation flags. Legacy behavior and the existing `--strict-input-gates` bundle are unchanged.
- Added synthetic fail-closed/acceptance tests, Windows Python 3.12.9 targeted CI coverage and a private Windows acceptance guide at `docs/ZEEK_ORIGINATOR_SPLIT_SCREEN.md`. At feature authoring, **PR-head CI, merge and student laptop/VMware testing are pending**. The screen is conservative: NAT, DHCP address reuse, directionality and shared clients can cause false refusals; passing does not prove host identity, independent ground truth, physical isolation or attack detection.
- Next: verify final PR-head Ubuntu and Windows checks and mergeability before merging. Student should independently record real Host-only capture, clocks, hashes, split policy and labels, then run private preflight on Windows 11. No UNSW benchmark, model, SOC database, network capture, active Red Team behavior or scientific metric was changed.



## 2026-10-29 — Originator-address split screen verified and merged (#183)

- [PR #183](https://github.com/tbao4151/DA_CNTT/pull/183) squash-merged as `6ec18f9a9a72d6d846164d01df65968388d77f6b` after final feature head `47ebefd0ad7f3adfd3a5748735cc4347181efb55` was mergeable against unchanged `main`. [Ubuntu Python 3.12.9 quality CI #40825228591](https://github.com/tbao4151/DA_CNTT/actions/runs/40825228591) **passed: 864 passed, 2 skipped, 2 warnings**. [Windows Server 2022 Python 3.12.9 offline CI #40825228683](https://github.com/tbao4151/DA_CNTT/actions/runs/40825228683) **passed: 123 Zeek + 46 Red Team tests**. Both are synthetic software checks, not genuine laptop experiments.
- The optional screen is available for pinned manifest preflight, private evaluation and trace. It checks Zeek connection-originator IP separation across research splits; shared destination servers are permitted. It exports only counts and non-attestation flags. The existing `--strict-input-gates` and legacy CLI behavior remain unchanged. No UNSW benchmark, model, SQLite, network execution or Red Team action was changed.
- **Post-merge main CI and student Windows 11/VMware acceptance are not yet verified at documentation authoring.** A clean originator-IP screen cannot establish physical host identity, capture authenticity, independent ground truth, physical isolation or attack detection; NAT/DHCP/shared clients can cause false refusals. Student must privately archive authorized real capture, hashes, host/network evidence, independent annotations and actual event-to-SOC timing before scientific claims.


## 2026-10-29 — Paired Zeek port-feature ablation (feature, CI pending)

- Reviewed main `12e033487dde70a3ee5fb5fdd62eb644cba9475f`, README/PROGRESS/ROADMAP, source tree, #183/#184 merge history, completed recent GitHub Actions and no open PRs before branching. The existing real-Zeek synthetic CI already exercises pinned scoring and a manually confirmed Unclassified SOC case; it is not a real detection experiment.
- Added `src/blue_team_ai/port_ablation.py` to compare the existing nine-feature Zeek-only Logistic Regression with a **true two-port-column exclusion**, on the identical declared host/session-disjoint TRAIN/VALIDATION/TEST data. Each variant fits preprocessing and model on TRAIN, chooses threshold on VALIDATION, and scores TEST only after selection. This does **not** alter the official UNSW-NB15 model, benchmark or production scoring artifact.
- Added opt-in `scripts/evaluate_zeek_lab.py --port-ablation-output` requiring independently pinned manifest SHA-256, strict input gates, explicit CIDR and a new private output path. Added synthetic regression for actual port exclusion, test-label non-leakage, privacy and refusal; included the new test in Windows CI and documented the private experiment protocol.
- **At authoring, final-head Ubuntu/Windows CI, PR merge and student Windows 11/VMware acceptance are pending.** All fixtures are synthetic. No genuine host-only capture, independent ground truth, measured Zeek detection performance, automated alert, SOC case write, live traffic or event-to-SOC timing is claimed.
- Next: verify both final-head CI workflows and mergeability before merge. Student must obtain independently labeled, authorized Host-only Zeek sessions, preregister split/variants, preserve PCAP/labels/hashes/clock evidence and run this optional sensitivity analysis privately; do not select a winner on TEST.


## 2026-10-29 — Zeek port-feature ablation verified and merged (#185)

- [PR #185](https://github.com/tbao4151/DA_CNTT/pull/185) squash-merged at `9cbe8d44d31c9c1d93ed5b25e4a16504218162dd` after final feature head `2e3c42614f0cb15acbf8bef13329934dc9930171` was conflict-free against unchanged `main`. Final-head [Ubuntu Python 3.12.9 CI #40828870693](https://github.com/tbao4151/DA_CNTT/actions/runs/40828870693) succeeded (**871 passed, 2 skipped, 2 warnings**); [Windows Server 2022 Python 3.12.9 CI #40828870679](https://github.com/tbao4151/DA_CNTT/actions/runs/40828870679) succeeded (**130 offline Zeek + 46 Red Team tests passed**). Counts were read from completed job logs.
- Earlier feature-head CI failed on a synthetic CLI fixture that reused the same five-tuple across research splits, which the existing strict overlap guard correctly rejected. After making the fixture split-disjoint, a second test-only Windows failure was due to calling `.decode()` on `subprocess.run(text=True).stderr`; both test defects were corrected before final-head green CI and merge. The safety gate was **not** relaxed.
- This opt-in research comparison fits full nine-column and portless seven-column Zeek Logistic Regression variants on the same declared splits, selects thresholds using validation only and evaluates TEST after selection. It does not replace the existing Zeek research model, alter official UNSW-NB15 metrics or create operational alerts, SOC cases or traffic.
- **Post-merge main CI #40829543357 was queued when checked, not claimed passed.** GitHub Windows CI is not student Windows 11/VMware acceptance. Synthetic fixture scores are not empirical attack-detection results. Student must independently pin real authorized Host-only PCAP/Zeek/annotation evidence, preregister variants/splits and report actual held-out class supports and uncertainty before drawing scientific conclusions.


## 2026-10-29 — Paired Zeek ablation: anonymized host-group variability (feature; CI pending)

- Reviewed current `main` at `90a30ce2cc11ff44d180295d5c74b4c4c9bccd34`, README/PROGRESS/ROADMAP, source tree, recently merged #185/#186, recent Actions and open PRs (none at inspection). Existing post-merge quality CI for #185 completed successfully; no new student capture or model evidence was present.
- Extended the **offline-only** paired full-nine-feature versus portless-seven-feature Zeek experiment to include existing anonymized host-group confusion/rate summaries for VALIDATION and held-out TEST **for both variants**. Report schema version increases from 1 to 2; the existing CLI flag, default Dataset Mode, trained models, SOC cases, benchmark and safety boundaries are unchanged. These are descriptive host-group diagnostics; they are not cluster-adjusted uncertainty estimates or independently authenticated host identities.
- Added synthetic regression tests for aggregate-to-host confusion consistency, privacy/no raw host IDs, small/single-group warnings, and held-out label changes not affecting validation-selected thresholds or validation host summaries. Updated the private Windows research guide.
- **At feature authoring, PR-head Ubuntu/Windows CI, merge and student Windows 11/VMware acceptance remain unverified.** Synthetic labels and declared host groups are not evidence of actual attack detection, physical isolation, or real event-to-alert/SOC latency. Next: verify CI and conflict-free merge, then student collects authorized independently labeled Host-only captures and privately examines host-level variation without selecting a winner on TEST.


## 2026-10-29 — Paired Zeek host-group diagnostics verified and merged (#187)

- [PR #187](https://github.com/tbao4151/DA_CNTT/pull/187) squash-merged at `8cba08a1809f39e0840e1cd93f92f9253058a807` after final feature head `7ecf8233fb20e746f72051b6e67d1dfc819f30dd` was conflict-free against unchanged `main`. [Ubuntu Python 3.12.9 quality CI #40830565924](https://github.com/tbao4151/DA_CNTT/actions/runs/40830565924) **passed: 873 passed, 2 skipped, 2 warnings**; [Windows Server 2022 Python 3.12.9 offline CI #40830565922](https://github.com/tbao4151/DA_CNTT/actions/runs/40830565922) **passed: 132 Zeek + 46 Red Team tests**. Counts were checked from completed job logs.
- The opt-in private port-feature ablation report v2 now provides anonymized VALIDATION/TEST host-group confusion counts, rates and small/single-group warnings for both prespecified variants. Existing thresholds remain validation-selected; held-out TEST is descriptive only. No model artifact, benchmark, SOC case, network activity or Red Team execution changed.
- **Post-merge main CI and student Windows 11/VMware acceptance were not verified when this documentation was authored.** CI synthetic fixtures do not authenticate operator labels, actual physical isolation, host identities or event-to-SOC latency. Students must retain authorized original PCAP/log/annotation hashes and host/session evidence privately and avoid selecting a variant using held-out TEST.

## 2026-10-29 — Paired Zeek port-ablation TEST correctness (feature PR pending)

- Added an aggregate per-row paired correctness contingency for the two already-prespecified full/portless Zeek research variants, including operator-label class breakdowns. It reuses the identical held-out TEST order after TRAIN-only fitting and VALIDATION-only threshold selection; does not expose per-flow predictions or add a significance claim.
- Added synthetic unit/regression tests for confusion-matrix consistency, input refusal and test-label invariance of the two validation-selected thresholds. CI/PR merge and student Windows 11/VMware experiment are **pending at authoring**; do not treat local fixtures as real detection evidence.
- No change to official UNSW-NB15 benchmark, active Red Team traffic, operational alerts, SOC database, or model deployment. Next: verify final-head Ubuntu and Windows CI, then preregister a genuine independently labeled Host-only evaluation with multiple independent sessions.

- Reconciled this feature with merged #187 and #189 on current `main` while preserving host-group diagnostics and report schema v2. Earlier green CI #40830683345 (Ubuntu) and #40830683244 (Windows) was for the pre-reconciliation head only; **new merged-head CI must pass before merge**.


## 2026-10-29 — Paired Zeek held-out correctness reconciled and merged (#188)

- [PR #188](https://github.com/tbao4151/DA_CNTT/pull/188) was reconciled with merged #187/#189 using feature merge commit `2a60ff538aac81d7f730de51cc78158f6d0801d1`; it preserved report schema v2, anonymized VALIDATION/TEST host-group diagnostics and all existing regression tests. The conflict-free PR was squash-merged into `main` as `f9ef8ef511e60a263ef6434dbd2a9fcc7d27e43d` after both final-head checks passed.
- [Ubuntu Python 3.12.9 CI #40834231739](https://github.com/tbao4151/DA_CNTT/actions/runs/40834231739) **success: 876 passed, 2 skipped, 2 warnings**; [Windows Server 2022 Python 3.12.9 CI #40834231718](https://github.com/tbao4151/DA_CNTT/actions/runs/40834231718) **success: 135 offline Zeek + 46 Red Team tests passed**. Counts were read from completed job logs. Earlier green CI on the pre-reconciliation feature head is not used as merge evidence.
- The optional offline Zeek port-ablation JSON now adds `paired_test_correctness` with aggregate same-row correctness cells and operator-label breakdowns, alongside the existing host-group diagnostics. Both variants use TRAIN-only fitting and VALIDATION-only thresholds. No per-flow prediction/UID/IP export, model deployment, operational alert, SOC write, Red Team execution or official UNSW-NB15 benchmark change.
- **Post-merge `main` CI and student Windows 11/VMware acceptance were not independently verified when this documentation was written.** Synthetic fixtures and GitHub runner tests do not prove authentic attack detection, independent annotations, actual Host-only isolation, or event-to-alert/SOC latency. Student must privately collect authorized PCAP/Zeek/annotation evidence, independently pin checksums, preregister host/session-disjoint splits and preserve actual timing before making empirical claims.


## 2026-10-29 — Paired Zeek correctness by anonymous TEST host group (feature PR; verification pending)

- Inspected main `63b97950080b703784d1b00725d9fe0f018ebaa3`, README, PROGRESS, ROADMAP, tree, recent Actions and open PRs (none). Confirmed #188 merged, with #190 documentation merge and prior Ubuntu/Windows CI green; no student VMware evidence was found in repository.
- Extended existing offline paired TEST correctness with **optional** operator-declared host grouping, anonymous per-host four-cell correctness and discordant counts. When any host group has fewer than 30 flows, all host-level cells are suppressed to avoid recovering small-group counts by subtraction from the existing overall totals. Legacy three-argument summarizer behavior and report schema version 2 remain compatible.
- Added synthetic regression for group/overall count consistency, privacy suppression, malformed metadata and tiny-fixture behavior. Updated the private Windows research guide. The feature is descriptive, not an independent-label, significance, real-VMware or live-attack claim.
- **At authoring, PR-head CI, merge and student Windows 11/VMware acceptance are pending.** No official UNSW-NB15 benchmark, model, SQLite SOC case, active Red Team network action or existing source evidence was changed. Next: check final-head Ubuntu/Windows CI and mergeability; student must independently collect genuine authorized Host-only PCAP/Zeek, labels, hashes, isolation and timing evidence before empirical claims.
