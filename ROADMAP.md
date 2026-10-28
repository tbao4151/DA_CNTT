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
- [x] Script tải kiểm tra SHA-256 trên tệp tạm trước khi đưa vào tên CSV chính thức; không ghi đè dữ liệu hiện có khi checksum sai (kiểm thử hồi quy synthetic, trạng thái CI xem PROGRESS).
- [x] Cấu trúc MVP Mini-SIEM bằng Streamlit, thư viện phân tích, SQLite.
- [x] Script Random Forest train/test không đưa nhãn vào features.
- [x] CLI huấn luyện kiểm tra checksum SHA-256 và số dòng của cả hai tệp UNSW-NB15 trước khi fit; sáu kiểm thử hồi quy tổng hợp đã qua CI trên PR #35.
- [x] CI khởi tạo (trạng thái chạy cần xác minh).
- [x] CI syntax và unit tests đã chạy thành công (GitHub Actions); đã có Chromium E2E cho luồng SOC chính trên Windows, còn thiếu độ bao phủ thao tác và trường hợp biên.
- [x] Kiểm thử luồng chính Streamlit **bằng Chromium trên Windows** sử dụng mô hình UNSW-NB15 chính thức: tạo case từ cảnh báo AI và tải báo cáo JSON thành công (PR #25, Actions 40442408258).
- [x] Kiểm thử trình duyệt Windows: cập nhật trạng thái SOC `New` → `Investigating`, lưu ghi chú, tải lại ứng dụng và đối chiếu JSON/audit trail (PR #26, Actions 40443155381).
- [ ] Kiểm thử mở rộng trên trình duyệt Windows: **đã có** Chromium smoke cho upload CSV hợp lệ, từ chối header trùng và bộ lọc Threat Hunting theo giao thức (PR #31, Actions 40464307137); **còn thiếu** trường hợp biên mở rộng, file lớn và thao tác thủ công trên máy nhóm.
- [x] Huấn luyện Random Forest trên train/test chính thức, lưu metrics thật và artifact (GitHub Actions).
- [ ] Tái lập benchmark độc lập trên môi trường sạch và xác minh artifact chạy với giao diện.
- [x] Có script kiểm chứng artifact và hướng dẫn thu thập minh chứng local (chưa đồng nghĩa nhóm đã chạy trên máy Windows; cần tự thực nghiệm và lưu ảnh/JSON).
- [x] Có phân tích mô tả FP/FN theo nhóm tấn công và giao thức trong báo cáo kiểm chứng local; **chỉ xuất khi chạy verifier**, chưa có kết quả thực nghiệm máy cá nhân và không dùng tập test để chọn ngưỡng/mô hình.
- [x] Xây dựng và chạy chính sách chọn ngưỡng chỉ trên validation từ tập training: Actions 40366465257 thành công, ứng viên 0,55. Workflow đánh giá ứng viên đã khóa trên official test đã thành công (Actions 40373007093): FP giảm 1.265 nhưng FN tăng 342; chưa tích hợp tự động vào dashboard.
- [ ] Bổ sung so sánh Logistic Regression / Random Forest / Gradient Boosting.
- [x] Thêm global MDI importance gộp one-hot theo cột network flow, kèm UI và kiểm thử hồi quy. Đã chạy và xác minh workflow tạo báo cáo **MDI thực nghiệm trên UNSW-NB15** (Actions 40377900643, 42 cột gốc / 194 chiều mã hóa, báo cáo `reports/official_global_feature_importance.json` trên PR); chưa có permutation importance trên validation và chưa xác minh giao diện trên Windows với model thật.
- [ ] Nâng UX demo (đã bổ sung phân tích ngưỡng, bằng chứng flow, xuất JSON hồ sơ SOC kèm audit trail và bộ lọc Threat hunting đa chiều; vẫn cần kiểm thử trải nghiệm demo trên Windows và cải thiện điều tra SOC).
- [ ] Kiểm thử an toàn tệp đầu vào và giới hạn tài nguyên (đã bổ sung CSV formula injection protection, giới hạn 15 MiB, kiểm tra header và số trường từng dòng trên toàn bộ CSV giới hạn 15 MiB (PR #38, CI thành công); còn thiếu kiểm thử browser upload, hiệu năng tệp lớn và tải tài nguyên).
- [ ] Tài liệu kiến trúc, threat model, kịch bản demo và câu hỏi hội đồng.
- [ ] Đề nghị GVHD xác nhận phạm vi Network Flow Logs và nghiệp vụ SOC.

Giữ scope khả thi: UNSW-NB15 train/test thiếu IP và timestamp gốc; chức năng correlation theo IP/thời gian chỉ triển khai khi có dữ liệu nguồn phù hợp.

## Đồng bộ môi trường Python (27/10/2026)

- [x] Ghim **Python 3.12.9** cho toàn bộ 8 GitHub Actions workflows trên Ubuntu 24.04 / Windows 2022: PR #40 đã hợp nhất, CI (`158 passed`) và official-model Windows/Ubuntu E2E đã qua kiểm thử trên PR. Chưa khẳng định benchmark cũ bất biến ở môi trường mới; các workflow ghi dữ liệu/benchmark đã chuyển sang chạy thủ công.
- [ ] Người dùng trực tiếp chạy Python 3.12.x trên Windows, huấn luyện và tạo `artifacts/local_verification.json`; GitHub CI không thay thế minh chứng này.

## Kiểm chứng cặp artifact cục bộ (27/10/2026)

- [x] Ghi SHA-256 manifest sau khi thay thế cả model và metrics; local verifier từ chối cặp có manifest không khớp trước khi nạp joblib (PR #41 CI đã thành công (163 passed, 2 skipped)).
- [ ] Chạy huấn luyện và verifier trên máy Windows của nhóm; giữ JSON và ảnh chụp thực tế làm minh chứng, không thay thế bằng CI.

## Giao diện & khả năng sử dụng (27/10/2026)

- [x] Thiết kế lại dashboard hoàn tất và hợp nhất (PR #42): high-contrast light theme, hướng dẫn 5 tab, KPI/biểu đồ đọc rõ, trạng thái AI; CI PR + kiểm thử Chromium trên Windows/Ubuntu thành công, artifact ảnh giao diện có thể tải từ Actions run 40538948167. Cần tiếp tục đánh giá thực tế trên laptop.
- [ ] Người dùng thử giao diện mới trên laptop ở các độ phân giải khác nhau; ghi nhận nhận xét thực tế để tinh chỉnh phần SOC workflow và thứ tự thông tin.

## Cyber Lab Mode — offline telemetry foundation (28/10/2026)

- [x] Implement a bounded offline Zeek ASCII `conn.log` parser with provenance, original timestamps/IPs, missing-value handling and synthetic regression tests (see PR/CI status in `PROGRESS.md`).
- [x] Implement a separate offline Zeek preview in Cyber Lab UI with synthetic tests and green PR CI (#44, run 40552641827). Merge/post-merge CI and Windows acceptance are tracked separately; no UNSW Random Forest inference or lab attack detection is claimed.
- [ ] Capture and validate an authorized Zeek log from student-owned VMware Host-only lab; archive genuine local evidence, Zeek version, timestamps and isolation checks.
- [ ] Define feature parity or train a separate model on lab schema with labeled holdout, calibrated alerting and reproducible precision/recall/FPR.
- [ ] Add safe scenario policy, operator opt-in, allowlist, rate limit, kill switch, Blue Team SOC flow and independent Red Team interface; no active traffic before isolation approval.

## Cyber Lab Mode — manual offline SOC triage (28/10/2026)

- [x] Add explicit operator-triggered `Unclassified` SOC case creation for a parsed Zeek flow, with separate Cyber Lab SQLite storage, original log SHA-256 in evidence and JSON audit export (PR #45 merged; PR and post-merge quality gates passed, see PROGRESS).
- [ ] Verify Windows manual UI selection/export with a genuine authorized Zeek `conn.log`; preserve original log and SHA-256, no claim of AI attack detection.
- [ ] Replace the shared string-only evidence snapshot with a versioned, typed Cyber Lab schema preserving missing values, then validate independent labels/holdout and lab-compatible AI inference.

## Cyber Lab — verified typed evidence export (28/10/2026)

- [x] Add a versioned, type-preserving Zeek case JSON export, revalidated against original offline log bytes and the existing SOC snapshot (PR #47 merged; PR and main CI passed, see PROGRESS). This does **not** yet make SQLite typed, immutable, or forensic-grade.
- [ ] Verify real Windows/VMware capture and manually test the export against an authorized original `conn.log`.

## Cyber Lab — Zeek-only lab feature contract (28/10/2026)

- [x] Validate and merge a versioned v1 projection of offline Zeek records to nine typed, explicitly allowed feature columns; reject extra/leaky fields, preserve nulls, and keep IP/UID/timestamps/digests out of model inputs (PR #48 merged; PR CI passed, see PROGRESS).
- [ ] Design independent labels, collection-session/host-aware train/validation/test separation, imputation fit only on training data, and baseline classifier on Zeek schema; report held-out precision/recall/FPR and provenance before any AI attack alert.
- [ ] Validate extraction and later model on a genuine authorized Windows VMware Host-only capture; keep raw log and SHA-256 separately.


## Cyber Lab — independent labels and leakage-safe splits (28/10/2026)

- [ ] Validate and merge the offline labeled Zeek dataset contract: raw source SHA-256, strict UID-to-binary-label mapping, independently declared label provenance, host/session-disjoint train/validation/test, no source reuse, both classes in each split, separate feature/label/provenance outputs. Synthetic tests only; PR/CI status is recorded in `PROGRESS.md`.
- [ ] Collect **genuine** student-owned VMware Host-only captures and annotation evidence for at least three distinct host groups, reserve an untouched test partition, document Zeek version, physical isolation and session-to-host assignment. The code does not verify the authenticity of user-provided labels.
- [ ] Train a separate Zeek-schema classifier using train-only preprocessing, choose hyperparameters/thresholds using validation only, evaluate once on held-out test and report Precision/Recall/FPR and model/source provenance. No attack-detection claim until real labeled data and reproducible evaluation exist.
- [ ] Add an offline annotation workflow and, only after verified model evaluation, connect Cyber Lab AI inference to alert and SOC Case. Active Red Team scenarios and live capture remain disabled until authorized isolation controls exist.


## Cyber Lab — offline baseline on independently labeled Zeek (28/10/2026)

- [x] PR #51 merged; final PR and post-merge main quality gates passed: train-only preprocessing and Logistic Regression,
  validation-only threshold selection and one-time held-out test report;
  synthetic regression tests and CI are verified in PROGRESS. This is not a genuine lab evaluation.
- [ ] Obtain independently annotated, authorized Zeek logs with at least three
  host-disjoint groups, pre-register the holdout and retain original log SHA-256,
  scenario notes and Zeek/VMware versions. No synthetic score is a lab metric.
- [ ] Build an offline annotation/experiment CLI and assess model calibration,
  false positives, scenario/host shift and repeatability before any automated
  AI-to-SOC alert integration; keep live capture and Red Team disabled.


## Cyber Lab — offline experiment CLI (28/10/2026)

- [x] Verify and merge the bounded private-manifest Zeek experiment CLI (`scripts/evaluate_zeek_lab.py`) and synthetic regression tests; PR #53 and post-merge CI verified (260 passed, 2 skipped); evidence in PROGRESS. The CLI only runs the already-existing offline baseline on operator-supplied labels, never live capture or AI alerts.
- [ ] Run the CLI with genuine independently labeled VMware Host-only logs from at least three host groups; archive Zeek version, isolation proof, original SHA-256, labeling evidence and untouched held-out test. No such local evidence has been verified.
- [ ] Assess calibration, scenario/host shift, false-positive rates and repeatability before saving a trusted Zeek model or wiring AI alerts into SOC.

## Cyber Lab — offline probability diagnostics (28/10/2026)

- [x] Report v2 with Brier score, fixed five-bin ECE and reliability counts for validation and held-out test merged in PR #55; PR and post-merge main CI passed (278 passed, 2 skipped). No test-based calibration or threshold tuning; synthetic regression tests only (see PROGRESS.md).
- [ ] Collect genuine authorized host-disjoint Zeek captures with independently documented ground truth; examine sample size, class prevalence, probability quality, host/scenario shift and false positives before considering any trusted model artifact or automated SOC alert.

## Cyber Lab — uncertainty diagnostics (28/10/2026)

- [x] Add 95% Wilson score intervals for validation/test flow-level Attack Precision, Recall and FPR, with null for undefined precision and explicit denominators (PR #57 merged; final PR-head and post-merge main CI passed, see PROGRESS.md).
- [ ] Collect independently labeled Host-only captures and report host/scenario-level variation; Wilson intervals assume independent flows and are not cluster-adjusted.
- [ ] After independent lab evaluation, design trusted Zeek model persistence, inference, AI-to-SOC alert integration and bounded Red Team controls. Do not deploy synthetic-only models.

## Cyber Lab — host-group variability diagnostics (28/10/2026)

- [x] Report v4 with per-host-group confusion counts, defined Precision/Recall/FPR, descriptive macro ranges and small-group warnings, without exporting host IDs; PR #59 merged and PR/main CI passed (313 passed, 2 skipped), see PROGRESS.md.
- [ ] Collect genuine independently annotated VMware Host-only captures with multiple independent host groups **within** each evaluation split; current synthetic fixtures have only one group per split. Record scenario-level variability, prevalence and labeling limitations before interpreting any group differences.
- [ ] Keep model fitting on train and threshold selection on validation; do not use held-out test group summaries for tuning. Host-group descriptive ranges are not cluster-adjusted confidence intervals or verified deployment reliability.

## Red Team AI — offline scenario planner (28/10/2026)

- [x] Verified PR #61 and post-merge main CI (330 passed, 2 skipped): merged the independent `src/red_team_ai/` UCB1/random **non-executing** scenario selector and `pages/2_Red_Team_Lab.py` UI; see `docs/RED_TEAM_OFFLINE_PLANNER.md` and `PROGRESS.md`. Only synthetic operator-entered feedback exists; no measured AI-versus-AI outcomes.
- [ ] Verify the Red Team UI on Windows Python 3.12.9 and confirm it sends no traffic; save screenshots separately. The session reset is not a real network kill switch.
- [ ] Before any active scenario runner: document authorization, verify VMware Host-only isolation, enforce explicit opt-in, allowlisted lab targets, rate limits, audit, emergency stop and owned fixture provenance. Do not silently activate traffic or claim Blue Team detection from operator-entered observations.
- [ ] Later compare UCB1 versus random on independently verified Blue Team outcomes using a preregistered protocol; keep test data separate and label all synthetic demonstrations clearly.


## Cyber Lab — private Zeek annotation workflow (28/10/2026)

- [x] Verified PR #63 and post-merge main CI (342 passed, 2 skipped): merged the offline UID annotation helper `scripts/prepare_zeek_annotations.py`: create `null`-only private templates with original source SHA-256, validate exact UID coverage and independently supplied binary labels. Synthetic tests and GitHub CI passed; **Windows laptop acceptance remains unverified**.
- [ ] Student collects authorized VMware Host-only `conn.log` captures, archives raw SHA-256, isolation/Zeek version and independent scenario evidence, and assigns every UID label without inferring ground truth from AI or protocol/port. Keep private UIDs and labels outside GitHub.
- [ ] Check each completed private annotation, pre-register host-disjoint train/validation/test in manifest v1 and run `scripts/evaluate_zeek_lab.py` once on untouched test. Validate sample size and host/scenario variation before any trusted Zeek inference, automated SOC alert or active Red Team runner.

## Red Team AI — paired synthetic policy comparison (28/10/2026)

- [x] [PR #65](https://github.com/tbao4151/DA_CNTT/pull/65) merged the offline UCB1 versus seeded Random simulator and UI; PR-head [CI #40603700957](https://github.com/tbao4151/DA_CNTT/actions/runs/40603700957) and post-merge [CI #40603879260](https://github.com/tbao4151/DA_CNTT/actions/runs/40603879260) passed (355 passed, 2 skipped). All outcomes and probabilities remain explicitly hypothetical, never real attack/detection evidence.
- [ ] Run the Red Team comparison UI on the student Windows laptop and check JSON export, layout and that no traffic is generated; GitHub CI does not replace this acceptance step.
- [ ] After authorized, independently recorded Host-only experiments and Blue Team event-level predictions exist, define a pre-registered scenario-to-evidence link and reward protocol; compare policies on **genuine** observations without using simulated rewards as ground truth.

## Cyber Lab — private Zeek input preflight (28/10/2026)

- [x] PR #67 merged; PR-head and post-merge Python 3.12.9 CI passed (360 passed, 2 skipped). The `--preflight` option validates private source/annotation hashes and split contracts, prints aggregate counts without fitting/scoring a model, and preserves the existing `--output` experiment path. See PROGRESS.md for links.
- [ ] On student Windows + VMware Host-only, run preflight on **genuine** independently annotated captures and archive a private run transcript, original hashes, Zeek version, isolation screenshots and pre-registered host-disjoint split assignment. Structural validation cannot authenticate ground truth or isolation.
- [ ] Only after independent evidence and a held-out evaluation: assess deployable Zeek model trust, safe offline inference and AI-to-SOC alerts. Do not turn synthetic-only scores into attack-detection claims.


## Cyber Lab — offline declared network scope screen (28/10/2026)

- [x] [PR #69](https://github.com/tbao4151/DA_CNTT/pull/69) merged the offline-only `check_zeek_lab_scope.py` CLI: strict RFC1918 IPv4 membership for both endpoints of every parsed Zeek flow, bounded source input, exclusive private aggregate/hash report and synthetic regression tests. Final PR and post-merge Python 3.12.9 CI passed (377 passed, 2 skipped); see `PROGRESS.md`.
- [ ] On the student Windows/VMware Host-only lab, record physical/virtual isolation configuration and Zeek version separately; run scope screening on genuine authorized `conn.log` using the **actual** configured lab CIDR, preserving original bytes and SHA-256 outside GitHub. Passing membership is not proof of isolation.
- [ ] Independently annotate the captured UIDs, pre-register host-disjoint partitions and run private structural preflight/evaluation before interpreting AI results. No automatic Zeek alert or Red Team traffic until evidence and safety gates are satisfied.

## Cyber Lab — declared CIDR screening in experiment CLI (28/10/2026)

- [x] Verified/merged the optional all-capture `--cidr` gate for both Zeek `--preflight` and `--output` (PR #71, final PR and post-merge Python 3.12.9 CI passed: 384 passed, 2 skipped). Scope screening checks only operator-declared IPv4 endpoint membership; no network activity, model deployment or automatic SOC alert. See PROGRESS for PR/CI status.
- [ ] Student-run Windows/VMware Host-only experiment: verify actual virtual network isolation separately, preserve private source hashes and scenario/label evidence, and pass the explicit scope gate on every pre-registered train/validation/test capture. Never claim a passing CIDR screen proves isolation or detection.


## Cyber Lab — private held-out Zeek prediction trace (28/10/2026)

- [x] [PR #73](https://github.com/tbao4151/DA_CNTT/pull/73) merged; final PR-head [CI #40616820490](https://github.com/tbao4151/DA_CNTT/actions/runs/40616820490) and post-merge [CI #40616997285](https://github.com/tbao4151/DA_CNTT/actions/runs/40616997285) passed (388 passed, 2 skipped). Optional private, non-deployable `--trace-output` provides per-test-flow SHA/UID, probability, validation-selected prediction and operator-supplied label; aggregate reports unchanged. Synthetic tests are not evidence of genuine detection.
- [ ] On student Windows/VMware Host-only: preserve independent capture/label/isolation evidence, preregister test split, then inspect the private trace **once** without reusing held-out test for tuning. Keep UIDs and per-flow labels outside GitHub.
- [ ] Only after genuine validated detection results: design separately audited AI inference → alert → SOC Case, without treating private test labels or synthetic policy rewards as live observations.

## Cyber Lab — private research prediction review in Blue Team UI (28/10/2026)

- [x] [PR #75](https://github.com/tbao4151/DA_CNTT/pull/75) merged read-only `trace_review.py` and optional Blue Team research candidate table; final PR-head [CI #40619319844](https://github.com/tbao4151/DA_CNTT/actions/runs/40619319844) and post-merge [CI #40619489913](https://github.com/tbao4151/DA_CNTT/actions/runs/40619489913) passed (403 passed, 2 skipped). No model deployment, operational alerts or genuine attack detection.
- [ ] Student runs the optional trace upload against a **genuine** authorized Host-only `conn.log` and a pre-registered private held-out `--trace-output`; preserve original source, hashes, independent labels and isolation screenshots outside GitHub. Review candidate FP/FN privately without test-set tuning.
- [ ] Only after independent detection evidence: design trusted model persistence/inference and explicitly gated AI-to-SOC alerts, with source provenance, confidence semantics and audit controls. Keep Red Team traffic disabled until isolation/authorization verified.


## Cyber Lab — analyst-confirmed research trace to manual SOC case (28/10/2026)

- [x] [PR #77](https://github.com/tbao4151/DA_CNTT/pull/77) merged with final-head [CI #40622139148](https://github.com/tbao4151/DA_CNTT/actions/runs/40622139148) and post-merge [CI #40622287624](https://github.com/tbao4151/DA_CNTT/actions/runs/40622287624) green (416 passed, 2 skipped). Explicit analyst-selected source/UID-matched research candidates (first 500 Zeek rows) create Unclassified cases with initial audit provenance. No model deployment, auto-alert or live capture.
- [ ] Student verifies this flow on Windows/VMware Host-only with genuine authorized, independently labeled data and an untouched held-out trace; preserve original source, private labels and network isolation evidence. CI synthetic fixtures are not a lab detection result.
- [ ] Later, after authentic lab evaluation, design trusted Zeek inference on *new* telemetry, gated alert generation, deduplication and measured end-to-end latency. Do not reinterpret research test predictions as operational alerts.


## Cyber Lab — deduplicate explicit research SOC triage (28/10/2026)

- [x] [PR #79](https://github.com/tbao4151/DA_CNTT/pull/79) merged the narrowly scoped source-SHA/Zeek-UID idempotency change for **manual research** candidates. Concurrent clicks reuse one original Unclassified case and initial audit event; ordinary manual and Dataset Mode case creation remain unchanged. Final PR and post-merge Ubuntu Python 3.12.9 CI passed (421 passed, 2 skipped); synthetic tests only. See PROGRESS.
- [ ] Validate on Windows with genuine authorized Host-only evidence; an idempotent case is not proof of model provenance, attack authenticity or network isolation.
- [ ] Do not use held-out research traces as live alerts. Trusted Zeek model deployment, new-log inference and operational AI-to-SOC alerts remain future work.


## Cyber Lab — private research trace provenance consistency (28/10/2026)

- [x] Verified and merged the fail-closed held-out source-set/flow-count check in PR #81; final PR and post-merge main CI passed (428 passed, 2 skipped, 2 warnings). Original source SHA-256 and UID coverage remain checked; this is internal consistency only, not genuine lab detection. See `PROGRESS.md`.
- [ ] Student runs an authorized VMware Host-only experiment with preserved original logs, independently documented labels, isolation screenshots and preregistered splits; verify the trace review on Windows without tuning on test.
- [ ] Build trusted Zeek model persistence and new-log inference only after authentic lab evaluation; internal JSON consistency does not establish model provenance or real-world detection.


## Cyber Lab — non-executable private Zeek model artifact (28/10/2026)

- [x] [PR #83](https://github.com/tbao4151/DA_CNTT/pull/83) merged: TRAIN-only Zeek Logistic Regression JSON research export with validation-locked threshold, fitted numeric/categorical parameters, explicit CIDR gate and SHA-256 output. Final PR-head [CI #40630943857](https://github.com/tbao4151/DA_CNTT/actions/runs/40630943857) and post-merge [CI #40631126434](https://github.com/tbao4151/DA_CNTT/actions/runs/40631126434) passed (442 passed, 2 skipped). Synthetic tests only; see `docs/ZEEK_PRIVATE_MODEL_EXPORT.md`.
- [ ] Student Windows/VMware Host-only acceptance: collect authorized raw logs, independently document labels and isolation, run export outside Git, preserve artifact SHA-256 and private evidence. GitHub synthetic CI is not proof of genuine attack detection.
- [ ] Later add independently pinned SHA-256 loader and bounded inference on **new** Zeek logs, then SOC alert controls and latency measurement. Do not treat held-out TEST predictions or this research artifact as a trusted operational detector.
