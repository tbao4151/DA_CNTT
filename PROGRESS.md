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
