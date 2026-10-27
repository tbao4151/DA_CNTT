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
