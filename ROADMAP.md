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


## Cyber Lab — independently pinned private Zeek model verifier (28/10/2026)

- [x] [PR #85](https://github.com/tbao4151/DA_CNTT/pull/85) merged: independently SHA-256-pinned, bounded, strict JSON-only loader and read-only verification CLI. Final PR-head [CI #40633769315](https://github.com/tbao4151/DA_CNTT/actions/runs/40633769315) and post-merge [CI #40633974947](https://github.com/tbao4151/DA_CNTT/actions/runs/40633974947) passed (461 passed, 2 skipped, 2 warnings on PR). Synthetic software tests only; see `docs/ZEEK_PRIVATE_MODEL_EXPORT.md`.
- [ ] Student Windows/VMware Host-only verification: preserve independent model SHA-256, original authorized Zeek logs, label records and isolation screenshots; run the verifier locally. Passing a digest does not authenticate model authorship or detection quality.
- [x] Bounded offline inference on **new** privately collected Zeek logs with scope checks and research-only output was merged in PR #87 (synthetic CI passed); no automatic SOC alerts, independent lab evaluation or Windows acceptance is claimed.


## Cyber Lab — pinned NEW-log offline inference (28/10/2026)

- [x] PR #87 merged; final PR and post-merge main CI passed (464 passed, 2 skipped, 2 warnings on PR). Bounded, separately pinned new Zeek capture inference (`src/blue_team_ai/new_log_inference.py`, `scripts/score_zeek_new_log.py`, `tests/test_zeek_new_log_inference.py`). PR/CI details are in PROGRESS.
- [ ] Student runs private Windows Python 3.12.9 acceptance on a **new** authorized VMware Host-only `conn.log` not used for TRAIN, VALIDATION or held-out TEST; independently preserve capture/model SHA-256, physical isolation and scenario evidence. CI synthetic fixtures do not satisfy this.
- [ ] Only after real independent holdout evaluation, add an explicit analyst-reviewed AI-to-SOC research alert pipeline with model provenance and detection latency; do not silently treat research candidates as confirmed attacks. Keep Red Team active traffic disabled until isolation and safety controls are validated.


## Cyber Lab — verify private NEW-log research predictions (28/10/2026)

- [x] [PR #89](https://github.com/tbao4151/DA_CNTT/pull/89) merged: `src/blue_team_ai/new_log_review.py`, `scripts/verify_zeek_new_log_report.py` and synthetic regression tests recompute and compare the entire saved new-log research prediction report against independently pinned original capture/model bytes. Final PR-head [CI #40639277298](https://github.com/tbao4151/DA_CNTT/actions/runs/40639277298) and post-merge [CI #40639475020](https://github.com/tbao4151/DA_CNTT/actions/runs/40639475020) passed (486 passed, 2 skipped on PR). See `docs/ZEEK_NEW_LOG_REPORT_REVIEW.md`. This is read-only consistency validation, not operational detection or a lab capture.
- [ ] Student Windows/VMware Host-only acceptance: retain private original `conn.log`, model JSON, hashes, report, isolation evidence, and pre-registered TRAIN/VALIDATION/TEST split; verify a genuinely new authorized capture outside all splits. Preserve the verification result in a private lab notebook.
- [ ] Only after independently labeled held-out evaluation and confirmed isolation, design analyst-reviewed research candidate-to-SOC workflow with provenance, deduplication and latency measurement. Never automatically turn this private research report into an operational alert or attack verdict.


## Cyber Lab — explicit pinned NEW-log manual SOC research triage (28/10/2026)

- [x] [PR #91](https://github.com/tbao4151/DA_CNTT/pull/91) merged the offline manual triage path: separately pinned original Zeek log/model, full recomputation of saved predictions, read-only candidate listing, explicit operator confirmations, private SQLite `Unclassified` case, source+UID idempotency and audit provenance. Final-head [CI #40642225873](https://github.com/tbao4151/DA_CNTT/actions/runs/40642225873) and post-merge [CI #40642495700](https://github.com/tbao4151/DA_CNTT/actions/runs/40642495700) passed (503 passed, 2 skipped, 2 existing warnings on PR). Synthetic tests only; see `docs/ZEEK_NEW_LOG_MANUAL_SOC_TRIAGE.md`.
- [ ] Student performs authorized Windows Python 3.12.9 / VMware Host-only acceptance with independently retained log/model SHA-256, capture version, scenario and physical isolation evidence, proof the new log is outside TRAIN/VALIDATION/TEST, and manually checks case history/export. No such evidence has been verified in GitHub CI.
- [ ] Only after credible independent evaluation, design an explicitly gated operational AI-to-alert/SOC pipeline and latency measurements. Research candidates remain `Unclassified` manual records; no automatic alert or verified attack is claimed.


## Cyber Lab — pinned declared-partition non-reuse preflight (28/10/2026)

- [x] [PR #93](https://github.com/tbao4151/DA_CNTT/pull/93) merged the read-only `check_zeek_partition_exclusion.py` gate; final-head and post-merge main Python 3.12.9 CI passed (**508 passed, 2 skipped**). It compares independently pinned new capture bytes with **all** declared TRAIN/VALIDATION/TEST source digests, checks model/manifest linkage and refuses mismatches. Synthetic regressions are not a student lab result.
- [ ] Student runs this tool on Windows with a genuinely pre-registered private experiment manifest, all original annotated captures, separately recorded SHA-256 references, actual VMware Host-only CIDR and an independently captured NEW log. Preserve screenshots, Zeek version and scenario/label evidence outside GitHub.
- [ ] Do not claim this exact-byte screen proves semantic flow non-reuse, authentic partition history, physical isolation or detection accuracy. Existing new-log inference reports remain research-only and do not gain an automatic alert or operational confidence claim.


## Cyber Lab — optional pinned partition gate for manual NEW-log SOC triage (28/10/2026)

- [x] [PR #95](https://github.com/tbao4151/DA_CNTT/pull/95) merged after green final-head [CI #40649157211](https://github.com/tbao4151/DA_CNTT/actions/runs/40649157211) and green post-merge main [CI #40649354908](https://github.com/tbao4151/DA_CNTT/actions/runs/40649354908) (514 passed, 2 skipped on PR): optional independently pinned manifest check on NEW-log candidate listing and manual Unclassified case creation; fail closed on declared TEST exact-byte reuse and recheck inside the case-write boundary. Legacy CLI remains compatible and must not claim a TEST exclusion check when the manifest is omitted.
- [ ] Student Windows/VMware Host-only acceptance: preserve the original preregistered manifest, all original capture/annotation files, independently recorded model/manifest/new-log SHA-256, physical isolation screenshots and scenario evidence; exercise both valid and refusal paths with private data.
- [ ] Exact-byte partition exclusion cannot prove semantic non-reuse, honest experiment history, authentic ground truth or model generalization. Do not activate operational alerts or Red Team traffic on the strength of this gate.


## Cyber Lab — normalized flow identity non-reuse preflight (28/10/2026)

- [x] [PR #97](https://github.com/tbao4151/DA_CNTT/pull/97) merged the conservative UID/UTC timestamp/five-tuple overlap screen against original pinned TRAIN/VALIDATION/TEST captures in read-only preflight and manual SOC case write path. Final-head [CI #40652526062](https://github.com/tbao4151/DA_CNTT/actions/runs/40652526062) and post-merge main [CI #40652861554](https://github.com/tbao4151/DA_CNTT/actions/runs/40652861554) passed (519 passed, 2 skipped on PR). Synthetic-only; not semantic non-reuse or genuine detection evidence.
- [ ] Student verifies on Windows with real authorized Host-only Zeek captures, original private annotated manifest, independently pinned hashes, physical isolation evidence and manual SOC audit. Synthetic CI is not an experiment on the student laptop.
- [ ] Continue independent labeled holdout evaluation and measured latency before considering explicitly gated operational AI alerts. Do not activate Red Team traffic on the strength of a digest or identity match check.


## Cyber Lab — pinned NEW-log Blue Team read-only UI (28/10/2026)

- [x] PR #99 merged, final-head CI #40655024380 and post-merge main CI #40655340663 passed (525 passed, 2 skipped, 2 existing warnings on PR) for the separate `pages/3_New_Log_Review.py` interface: strict independently SHA-pinned model, source/report recomputation, authorized CIDR, bounded candidate table, synthetic regression and no automatic case write. See PROGRESS for status.
- [ ] Student tests the page on Windows Python 3.12.9 using genuine authorized Host-only Zeek capture, original private model/report, separately recorded hashes and independently pinned TRAIN/VALIDATION/TEST partition preflight. Save screenshots and negative-test evidence outside Git.
- [ ] After verified independent lab evaluation, integrate optional explicit analyst-confirmed SOC triage into UI with full pinned manifest guard and evidence; no operational auto-alert or Red Team active traffic is authorized by this read-only page.


## Cyber Lab — independently pinned NEW-log descriptive label evaluation (28/10/2026)

- [x] [PR #101](https://github.com/tbao4151/DA_CNTT/pull/101) merged after green final-head [CI #40658718042](https://github.com/tbao4151/DA_CNTT/actions/runs/40658718042) and post-merge [CI #40659083844](https://github.com/tbao4151/DA_CNTT/actions/runs/40659083844) (537 passed, 2 skipped on PR): read-only pinned model/log/report/annotation evaluation, original manifest and declared split non-reuse gate, fixed validation threshold, aggregate TP/FP/TN/FN, Precision/Recall/F1/FPR and flow-level Wilson intervals. Synthetic tests are not genuine lab measurements; see docs/ZEEK_NEW_LOG_LABELED_EVALUATION.md.
- [ ] Student captures a genuinely new authorized VMware Host-only Zeek conn.log, independently annotates every UID with documented evidence, retains all pinned original partition captures and hashes, runs the Windows CLI and archives the aggregate output privately.
- [ ] Establish label reliability, independent capture history, host/session-aware uncertainty and measured inference latency before claiming validated AI detection or adding gated operational alerts. Keep Dataset Mode UNSW benchmark and Red Team traffic unchanged.


## Cyber Lab — mandatory declared-partition gate in read-only NEW-log UI (28/10/2026)

- [ ] Validate and merge the NEW-log UI change requiring a private SHA-256-pinned original TRAIN/VALIDATION/TEST manifest, all original captures and annotation files, and conservative flow-identity non-reuse check before showing research candidates. Synthetic-only tests; feature PR/CI/merge status is tracked in PROGRESS.
- [ ] Student tests both accepted and refused paths on Windows Python 3.12.9 using genuine authorized VMware Host-only capture, preregistered private manifest, original annotated split captures and independently recorded hashes. Preserve screenshots and source evidence outside Git.
- [ ] Add an explicitly analyst-confirmed SOC case action to the Blue Team UI only after rechecking the same pinned manifest at the SQLite write boundary; no operational alert or automatic attack confirmation.


## Cyber Lab — verified mandatory NEW-log UI partition gate (28/10/2026)

- [x] [PR #103](https://github.com/tbao4151/DA_CNTT/pull/103) merged: read-only NEW-log UI now requires a SHA-256-pinned private manifest and all original TRAIN/VALIDATION/TEST captures/annotations, rejecting exact-byte or normalized flow identity overlap before displaying AI research candidates. Final-head [CI #40661904366](https://github.com/tbao4151/DA_CNTT/actions/runs/40661904366) and post-merge main [CI #40662219929](https://github.com/tbao4151/DA_CNTT/actions/runs/40662219929) passed (545 passed, 2 skipped, 2 existing warnings on PR).
- [ ] Student verifies the UI and refusal paths on Windows Python 3.12.9 with genuine authorized VMware Host-only captures, independent hashes, preserved original manifest/annotations and isolation screenshots outside Git. CI synthetic fixtures do not establish attack detection.
- [ ] Add optional explicitly analyst-confirmed `Unclassified` SOC case creation in UI with a fresh pinned-manifest check at the SQLite write boundary. No operational auto-alert or Red Team traffic.


## Cyber Lab — pinned offline batch runtime measurement (28/10/2026)

- [x] [PR #105](https://github.com/tbao4151/DA_CNTT/pull/105) merged with final-head [CI #40665921468](https://github.com/tbao4151/DA_CNTT/actions/runs/40665921468) and post-merge main [CI #40666245219](https://github.com/tbao4151/DA_CNTT/actions/runs/40666245219) passed (558 passed, 2 skipped, 2 existing warnings on PR). Keep official Dataset Mode and Red Team safe-off unchanged. See `docs/ZEEK_NEW_LOG_RUNTIME_BENCHMARK.md`.
- [ ] Student collects genuine authorized VMware Host-only Zeek captures and independently pinned model/manifest/log SHA-256; runs benchmark on Windows Python 3.12.9 with documented hardware, Zeek version and capture duration. Store outputs privately and distinguish synthetic CI from student measurements.
- [ ] Only after verified real capture and independent labels, design event arrival/ingest/alert timestamp instrumentation to measure actual end-to-end detection latency. Offline batch runtime is not detection latency or operational throughput.

## Cyber Lab — optional analyst-confirmed NEW-log UI SOC triage (28/10/2026)

- [x] [PR #107](https://github.com/tbao4151/DA_CNTT/pull/107) merged after final-head [CI #40670039543](https://github.com/tbao4151/DA_CNTT/actions/runs/40670039543) passed (566 passed, 2 skipped, 2 existing warnings); [post-merge main CI #40670441897](https://github.com/tbao4151/DA_CNTT/actions/runs/40670441897) also passed. Verified UI manual Unclassified SOC case slice: independently pinned private model/manifest/log/report, full fresh TRAIN/VALIDATION/TEST exclusion and CIDR checks at the SQLite write boundary, explicit analyst authorization/new-capture confirmations, original-row selection, idempotent research case and synthetic regression tests. Feature PR/CI status is recorded in PROGRESS; do not mark merged before green final-head CI.
- [ ] Student runs Windows Python 3.12.9 acceptance on genuine authorized VMware Host-only captures; archive original private evidence, hashes, independent labels and physical isolation checks, and verify refusal/repeated-case behavior. GitHub synthetic CI is not laptop evidence.
- [ ] Later measure true event-to-alert latency and evaluate independently labeled host/session-disjoint data before considering operational AI alerts. Manual Unclassified SOC records do not prove attack detection. Keep Red Team active traffic disabled and official UNSW benchmark unchanged.


## Cyber Lab — private Windows capture evidence inventory (28/10/2026)

- [x] Verified and merged the offline private evidence inventory (`src/blue_team_ai/capture_evidence.py`, `scripts/record_zeek_lab_capture.py`, synthetic regression tests and `docs/WINDOWS_VMWARE_CAPTURE_EVIDENCE.md`); PR #109 merged after green final-head CI #40674392574 (575 passed, 2 skipped); post-merge main CI tracked separately in PROGRESS. The tool only records independently pinned log checksum, supporting-file digests, declared CIDR and aggregate Zeek timestamps; it does **not** prove Host-only isolation or attack detection.
- [ ] Student gathers real authorized VMware Host-only original `conn.log`, VMware network and host adapter screenshots, actual Zeek version output and independent scenario notebook in a private directory; runs the inventory CLI on Windows Python 3.12.9, archives the JSON and original files outside Git, and verifies guest adapters/routes manually.
- [ ] Collect host/session-disjoint independently labeled captures and evaluate the separate Zeek Blue Team model on an untouched partition. Do not treat synthetic CI, inventory hashes, manual Unclassified SOC cases or batch runtime as verified operational attack detection. Keep Dataset Mode benchmark and Red Team active traffic unchanged.


## Cyber Lab — private SOC read-only evidence browser (28/10/2026)

- [ ] Verify final-head Python 3.12.9 CI and merge the bounded private SQLite read-only Zeek Unclassified case/evidence/audit viewer. Synthetic-only regression and local Python 3.13.5 helper tests are not student Windows acceptance. PR and CI state recorded in PROGRESS.
- [ ] Student tests a genuine authorized Host-only Zeek case on Windows 3.12.9, checks original UID/SHA-256, audit events, JSON export and missing-DB refusal, storing screenshots and source evidence privately. Do not claim operational detection from an editable SOC case.
- [ ] Evaluate independently labeled host/session-disjoint captures and genuine event-to-alert latency before operational AI alerting; leave Dataset Mode benchmark and Red Team active traffic unchanged.


## Cyber Lab — read-only SOC case browser merged (28/10/2026)

- [x] [PR #111](https://github.com/tbao4151/DA_CNTT/pull/111) merged after final-head [CI #40677916507](https://github.com/tbao4151/DA_CNTT/actions/runs/40677916507) passed (579 passed, 2 skipped, 2 existing warnings). Private bounded SQLite Zeek Unclassified case list/evidence/audit viewer and JSON snapshot download are implemented; post-merge main CI is tracked separately in PROGRESS.
- [ ] Student runs Windows 3.12.9 acceptance with authorized Host-only Zeek capture and private SOC DB: verify original UID/source digest, history, JSON export, missing-file refusal and no DB mutation. Retain private screenshots, captures and independent hashes.
- [ ] Independently label host/session-disjoint captures and measure genuine event-to-alert latency before claiming operational attack detection. Keep official UNSW Dataset Mode and Red Team traffic unchanged.


## Cyber Lab — Windows host-only read-only network preflight (28/10/2026)

- [ ] Verify final-head CI and merge the read-only Windows host network evidence helper; code and synthetic mocked tests are on a feature branch. Do not claim Windows/VMware acceptance from Ubuntu CI.
- [ ] Student runs `scripts/record_windows_host_network.py` on Windows 3.12.9 with explicit confirmation, privately archives host diagnostics and checks every VMware guest adapter/route against approved Host-only configuration. Record authorization and original Zeek capture evidence separately.
- [ ] Independently label genuine host/session-disjoint captures and measure actual event-to-alert latency before operational AI alerting. Dataset Mode benchmark and Red Team active traffic remain unchanged.


## Cyber Lab — Windows host preflight feature merged (28/10/2026)

- [x] [PR #113](https://github.com/tbao4151/DA_CNTT/pull/113) merged after final-head [CI #40682056972](https://github.com/tbao4151/DA_CNTT/actions/runs/40682056972) passed (586 passed, 2 skipped, 2 warnings). Post-merge main CI #40682389167 was queued at documentation time; track it separately. This is only read-only host network evidence, not isolation proof.
- [ ] Student performs Windows 3.12.9 acceptance, inspects all VMware guest adapters and routes, and archives private original outputs and SHA-256 independently. Keep Red Team active traffic off and Dataset Mode benchmark unchanged.

## Cyber Lab — pinned host network preflight integrity verification (28/10/2026)

- [ ] Verify final-head CI and merge the offline private host-preflight verifier; see PROGRESS for pending feature PR status. It checks a separately recorded SHA-256 of the host inventory plus the three original command outputs and fails closed on modified/missing evidence; synthetic tests only.
- [ ] Student runs the verifier on Windows Python 3.12.9 using an independently recorded hash from the private lab notebook. Inspect VMware guest adapters, routes and authorization separately; hashes cannot prove Host-only isolation.
- [ ] Obtain genuine authorized Host-only Zeek logs with independent scenario labels and host/session-disjoint evaluation before operational detection or Red Team active traffic. Preserve official Dataset Mode benchmark.

## Cyber Lab — pinned host preflight verifier merged (28/10/2026)

- [x] [PR #115](https://github.com/tbao4151/DA_CNTT/pull/115) merged after green final-head [CI #40686152438](https://github.com/tbao4151/DA_CNTT/actions/runs/40686152438) (600 passed, 2 skipped, 2 warnings). Offline SHA-pinned private host inventory and three original diagnostics are verified for integrity only; main CI is tracked in PROGRESS.
- [ ] Student independently pins the report SHA-256 and runs the verifier on Windows Python 3.12.9, manually checks all VMware guest adapters/routes and archives original private evidence outside Git. The tool cannot prove isolation or authorization.
- [ ] Gather genuinely new, authorized Host-only Zeek captures with independent scenario labels and evaluate on host/session-disjoint partitions before claiming operational attack detection. Keep Dataset Mode official benchmark and Red Team active traffic unchanged.


## Cyber Lab — pinned original Zeek capture evidence re-verification (28/10/2026)

- [x] [PR #117](https://github.com/tbao4151/DA_CNTT/pull/117) merged after final-head [CI #40689613894](https://github.com/tbao4151/DA_CNTT/actions/runs/40689613894) and post-merge main [CI #40689948085](https://github.com/tbao4151/DA_CNTT/actions/runs/40689948085) passed (620 passed, 2 skipped, 2 existing warnings). The offline verifier re-reads all five private originals and recomputes declared Zeek scope; synthetic regression is not student Windows acceptance.
- [ ] Student runs the verifier on an authorized Host-only Zeek capture, with an independently recorded inventory SHA-256 and original evidence; inspect all VMware guest adapters/routes and approval manually. Do not publish private logs, screenshots or notebook entries.
- [ ] Collect independently labeled, host/session-disjoint real captures and evaluate model generalization and event-to-alert latency before claiming attack detection. No automatic alerts or active Red Team traffic.


## Cyber Lab — conservative cross-capture flow identity exclusion (28/10/2026)

- [x] [PR #119](https://github.com/tbao4151/DA_CNTT/pull/119) merged after final-head [CI #40694487688](https://github.com/tbao4151/DA_CNTT/actions/runs/40694487688) passed (624 passed, 2 skipped, 2 warnings on Ubuntu Python 3.12.9). Shared normalized UID/time/five-tuple overlap screening rejects re-encoded flow reuse across labeled captures before training; synthetic tests only. Post-merge main CI is tracked separately in PROGRESS.
- [ ] Student records independently pinned original Host-only captures, separate annotations, sessions and hosts, then runs `evaluate_zeek_lab.py --preflight` on Windows 3.12.9 before any fit. A passing exact-identity screen does not prove semantic non-reuse, authorization, label truth or physical isolation.
- [ ] Evaluate on genuinely independent, host/session-disjoint captures and report FPR, recall and event-to-alert latency only with independently documented experimental evidence. Red Team active traffic remains disabled.


## Cyber Lab — two-annotator label quality review (28/10/2026)

- [ ] Verify final-head CI and merge the optional SHA-pinned offline annotation agreement feature; see PROGRESS for pending PR state. The aggregate agreement report includes 2x2 counts and Cohen's kappa, never creates or alters labels, models, alerts or cases.
- [ ] Student collects an authorized genuine VMware Host-only Zeek capture, obtains two blind independent UID annotations with separately recorded evidence and hashes, runs the agreement CLI on Windows Python 3.12.9, and documents disagreements/adjudication privately. Software agreement does not establish attack ground truth or independent reviewers.
- [ ] Pre-register host/session-disjoint splits, freeze held-out TEST, evaluate a separately trained Zeek model with independently substantiated labels and measure event-to-alert latency. Keep official UNSW benchmark and active Red Team unchanged.


## Cyber Lab — independent annotation agreement merged (28/10/2026)

- [x] [PR #121](https://github.com/tbao4151/DA_CNTT/pull/121) merged after final-head [CI #40698075993](https://github.com/tbao4151/DA_CNTT/actions/runs/40698075993) and post-merge main [CI #40698595946](https://github.com/tbao4151/DA_CNTT/actions/runs/40698595946) succeeded. The earlier pending checkbox above reflects feature authoring and is superseded by this verified record. No operational alert, model or consensus label is produced.
- [ ] Student completes blind independent annotations of a genuine authorized Host-only capture, independently pins original log and both annotation hashes, runs the private agreement CLI on Windows Python 3.12.9 and records adjudication evidence. Software cannot prove annotator independence, attack ground truth or isolation.
- [ ] Run preregistered host/session-disjoint evaluation and measure actual event-to-alert latency after independent lab evidence; do not tune the reserved test set. Keep Dataset Mode baseline and active Red Team unchanged.


## Cyber Lab — private disagreement adjudication worksheet (28/10/2026)

- [ ] Verify final-head CI and merge the optional offline UID-level disagreement worksheet. The existing aggregate two-reviewer agreement report remains UID-free. This new opt-in private file contains only disagreements with null adjudication/evidence fields; it does not infer consensus, prove ground truth or modify reviewer annotations. Track verified PR/CI in PROGRESS.
- [ ] Student independently labels a genuine authorized Host-only Zeek capture twice, pins original and reviewer hashes, runs the aggregate check and private worksheet on Windows Python 3.12.9, and documents independent scenario evidence for every disagreement. Keep UIDs, labels and evidence outside Git.
- [ ] Create a separately versioned complete annotation-v1 after manual adjudication; pre-register host/session-disjoint splits, keep TEST untouched and measure model generalization and event-to-alert latency only on genuine verified lab evidence. Do not enable active Red Team or alter official UNSW-NB15 benchmark.


## Cyber Lab — private disagreement worksheet merged (28/10/2026)

- [x] [PR #123](https://github.com/tbao4151/DA_CNTT/pull/123) merged after final-head [CI #40703014325](https://github.com/tbao4151/DA_CNTT/actions/runs/40703014325) and post-merge main [CI #40703530003](https://github.com/tbao4151/DA_CNTT/actions/runs/40703530003) passed (646 passed, 2 skipped, 2 existing warnings). The earlier pending checkbox is superseded by this verified entry. The separate UID-bearing worksheet is opt-in and private, never a consensus or model-training annotation.
- [ ] Student runs the aggregate and private disagreement tools on independently labeled authorized VMware Host-only captures using Windows Python 3.12.9, then manually documents evidence and adjudicates unresolved UIDs without inferring labels from AI. Keep all sensitive data outside Git.
- [ ] Freeze separately versioned complete annotation-v1 inputs and host/session-disjoint TEST; evaluate genuine Zeek detection and event-to-alert latency before any operational alerts or active Red Team scenario runner.


## Cyber Lab — manually finalized private Zeek labels (28/10/2026)

- [ ] Verify final-head PR CI before merging the private adjudication finalizer; see PROGRESS for feature status. It accepts only a separately SHA-pinned, fully manually decided worksheet, rejects changed original reviewer labels and writes a new annotation-v1 beside the private log without touching existing labels.
- [ ] Student must complete genuine Host-only capture and independent annotations, document scenario evidence for each disputed UID, record worksheet/output hashes outside Git and run finalization plus annotation verifier on Windows Python 3.12.9. Agreement and evidence references are not proof of ground truth.
- [ ] Freeze host/session-disjoint TRAIN/VALIDATION/TEST, evaluate the separate Zeek model on actual labeled captures, measure event-to-alert latency, and connect approved AI candidates to SOC. Keep Dataset Mode benchmark unchanged and active Red Team traffic disabled.


## Cyber Lab — verified private adjudication finalization (28/10/2026)

- [x] [PR #125](https://github.com/tbao4151/DA_CNTT/pull/125) merged after final-head [CI #40708581003](https://github.com/tbao4151/DA_CNTT/actions/runs/40708581003) passed (665 passed, 2 skipped, 2 warnings). The earlier pending feature checklist above is superseded by this verified record; only a private manual-review annotation-v1 converter is complete.
- [ ] Student manually adjudicates all disputed UIDs against independently retained scenario evidence and verifies a newly SHA-pinned annotation-v1 on Windows Python 3.12.9. An unresolved disagreement must block finalization; private labels and evidence remain outside Git.
- [ ] Capture genuine authorized VMware Host-only logs, freeze independent TRAIN/VALIDATION/TEST partitions, evaluate separate Zeek AI on external labels, and measure event-to-alert latency. Do not claim actual attack detection from synthetic CI or activate Red Team network scenarios yet.


## Cyber Lab — verify finalized private labels before independent evaluation (28/10/2026)

- [ ] Verify final-head PR CI and merge the offline read-only five-input final-label chain verifier; implementation and synthetic tests are on a feature branch. Check `PROGRESS.md` and GitHub Actions for the final status. It does not authenticate attacks or create new labels.
- [ ] Student runs `scripts/verify_zeek_final_labels.py` on Windows Python 3.12.9 with a genuinely authorized Host-only `conn.log`, two independently annotated originals, completed manually adjudicated worksheet, finalized annotation, and five independently recorded SHA-256 values. Keep all five private files and the aggregate output outside Git.
- [ ] Pre-register and freeze host/session-disjoint TRAIN/VALIDATION/TEST; independently verify scenario evidence and actual lab isolation, then evaluate the Zeek model on held-out real captures with FPR/Recall and event-to-alert latency. Do not use synthetic CI or reviewer agreement as ground truth. Leave Dataset Mode benchmark and active Red Team traffic unchanged.

## Cyber Lab — final-label chain verification merged (28/10/2026)

- [x] [PR #127](https://github.com/tbao4151/DA_CNTT/pull/127) merged after final-head [CI #40713687729](https://github.com/tbao4151/DA_CNTT/actions/runs/40713687729) passed (**679 passed, 2 skipped, 2 existing pandas warnings**). This supersedes the earlier pending feature checkbox; offline consistency checking does not authenticate labels or physical events.
- [ ] Student runs `scripts/verify_zeek_final_labels.py` on Windows Python 3.12.9 with five independently SHA-pinned private files from an authorized VMware Host-only capture. Keep original Zeek, reviewer annotations, worksheet, finalized annotation, and separate scenario/isolation evidence outside Git.
- [ ] Freeze host/session-disjoint TRAIN/VALIDATION/TEST, independently validate actual scenario ground truth and isolation, then measure held-out Zeek Precision/Recall/FPR and event-to-alert latency. Red Team active traffic and operational auto-alerts remain disabled until authorized safety and research gates are satisfied.


## Cyber Lab — frozen annotation byte integrity before Zeek fitting (28/10/2026)

- [ ] Verify final-head CI and merge the optional `labels_sha256` manifest guard with strict `--require-label-sha256` preflight/fit; see PROGRESS for pending feature PR status. This protects exact annotation bytes, not their scientific validity.
- [ ] Student records independent SHA-256 for every finalized private annotation file, runs five-input final-label chain verification where applicable, then runs strict pinned preflight on Windows Python 3.12.9 before training/evaluation. Preserve original evidence outside Git and freeze the test partition before model selection.
- [ ] Validate real VMware Host-only isolation, authorization and scenario ground truth independently; assess held-out Zeek FPR/Recall and event-to-alert latency only after genuine host/session-disjoint captures exist. Do not enable active Red Team traffic or change official UNSW-NB15 benchmark.


## Cyber Lab — verified Zeek annotation byte pins merged (28/10/2026)

- [x] [PR #129](https://github.com/tbao4151/DA_CNTT/pull/129) merged after final-head [CI #40722795229](https://github.com/tbao4151/DA_CNTT/actions/runs/40722795229) and post-merge `main` [CI #40723382103](https://github.com/tbao4151/DA_CNTT/actions/runs/40723382103) both passed (**684 passed, 2 skipped, 2 existing warnings**). This supersedes the pending checkbox above. Strict annotation-byte pinning is implemented, but authentic labeling remains unverified.
- [ ] Student independently freezes each `labels.json` SHA-256, performs five-input chain verification where applicable, then runs `evaluate_zeek_lab.py --require-label-sha256 --preflight` on Windows Python 3.12.9 using authorized genuine Host-only captures. Keep sensitive evidence outside Git.
- [ ] Evaluate a separate Zeek model on independently validated, host/session-disjoint held-out data and measure real event-to-alert latency; preserve official UNSW benchmark, offline-only default and inactive Red Team network execution.

## Cyber Lab — offline classic PCAP import (28/10/2026)

- [x] PR #131 merged after successful PR CI (run 40728220108, 698 passed, 2 skipped): bounded offline classic PCAP -> Zeek `conn.log` importer and synthetic tests. Main CI run 40728824378 was still pending when documented; see `PROGRESS.md`. No active traffic, live capture, AI scoring or SOC write.
- [ ] Run `scripts/import_offline_pcap.py` with a **genuine authorized** classic PCAP inside a Linux VM with Zeek installed; archive original PCAP, `conn.log`, both SHA-256 values, Zeek version, VMware Host-only adapter/route screenshots and session notes outside Git. The tool's CIDR screening does not prove physical isolation or authenticity.
- [ ] Validate the resulting Zeek flow schema against existing offline Blue Team pipeline and independently annotated labels before making any detection claim. Preserve official UNSW-NB15 benchmark.


## Cyber Lab — independently pinned offline PCAP import evidence (29/10/2026)

- [ ] Verify final-head CI and merge the read-only `offline_pcap_verify.py` and `verify_offline_pcap_import.py` slice. The tool rechecks original PCAP, generated Zeek `conn.log`, import report and CIDR aggregate from a separately recorded report SHA-256; no network traffic or AI inference is performed. See PROGRESS for current PR status.
- [ ] Student runs **actual** Zeek `-r` on an authorized classic PCAP inside a Linux VM, independently pins the resulting report, then runs the verifier with original PCAP, `conn.log` and declared Host-only CIDR. Preserve Zeek version, screenshots, routing table, timestamps, scenario notes and three private files outside Git. Successful verification does not prove capture origin or physical isolation.
- [ ] Only after independent lab evidence and human-reviewed labels, validate a separate Zeek model on host/session-disjoint held-out captures and measure Precision/Recall/FPR plus event-to-alert latency. Preserve official UNSW-NB15 benchmark and keep active Red Team network execution disabled.


## Cyber Lab — verified offline PCAP import pin gate merged (29/10/2026)

- [x] [PR #133](https://github.com/tbao4151/DA_CNTT/pull/133) merged after final-head [CI #40734466006](https://github.com/tbao4151/DA_CNTT/actions/runs/40734466006) and [CI #40734456078](https://github.com/tbao4151/DA_CNTT/actions/runs/40734456078) succeeded (716 passed, 2 skipped, 2 warnings). This supersedes the pending CI checkbox above; no live capture or real Zeek execution is claimed.
- [ ] Student uses an authorized classic PCAP, runs actual Zeek `-r` inside Linux VMware Host-only, separately pins `offline_import_report.json`, verifies all original files and scope, and archives Zeek version, routes, adapter screenshots and scenario notes outside Git.
- [ ] Build evidence-backed host/session-disjoint Zeek evaluation and measure actual detection latency. No operational alert or Red Team active traffic until independent lab evidence is available. Preserve UNSW-NB15 official benchmark.
