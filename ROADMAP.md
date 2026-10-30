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


## Cyber Lab — optional PCAP evidence gate before research inference (29/10/2026)

- [ ] Verify final-head CI and merge the opt-in all-or-none pinned PCAP provenance gate in `scripts/score_zeek_new_log.py`; see PROGRESS for current feature status. The unchanged prediction report remains **research candidates only**, not operational alerts.
- [ ] Student runs actual Zeek `-r` on a genuinely authorized Host-only PCAP in Linux VMware, separately records the import report/model/log hashes, then exercises the optional gate and scoring CLI on Windows Python 3.12.9 or Linux. Preserve original PCAP, Zeek output, VMware adapter/routes, Zeek version, operator authorization and scenario notebook outside Git.
- [ ] Independently verify source/session/host-disjoint partitions and attack labels, then measure held-out Zeek Precision/Recall/FPR and event-to-alert latency; only after that consider analyst-approved SOC integration. Never infer physical isolation, capture authenticity or attack detection from checksum/CIDR verification. Keep active Red Team traffic disabled and official UNSW-NB15 benchmark unchanged.


## Cyber Lab — verified PCAP-to-Zeek research scoring gate merged (29/10/2026)

- [x] [PR #135](https://github.com/tbao4151/DA_CNTT/pull/135) merged after final-head [CI #40737879199](https://github.com/tbao4151/DA_CNTT/actions/runs/40737879199) passed (**717 passed, 2 skipped, 2 warnings**). The earlier pending feature checklist is superseded by this verified record. The new optional gate checks pinned PCAP import evidence before existing Zeek research scoring; it does not create operational alerts.
- [ ] Student runs genuine authorized `zeek -r` on a private classic PCAP inside isolated Linux VMware, independently pins PCAP/import report/log/model, verifies adapter/routes and runs the gated scorer on Windows Python 3.12.9 or Linux. Preserve screenshots, Zeek version, authorization and scenario notebook outside Git.
- [ ] Validate independently labeled host/session-disjoint holdout, assess FPR/Recall/Precision and real event-to-alert latency, then consider evidence-backed analyst-approved SOC case integration. No inference from synthetic CI about physical isolation, PCAP authenticity or attack detection; Red Team active traffic remains disabled.

## Cyber Lab — repeat pinned PCAP verification at research report review (29/10/2026)

- [ ] Verify final-head CI and merge the optional all-or-none pinned PCAP provenance recheck in `verify_zeek_new_log_report.py`; this detects a changed original PCAP after the scorer generated its prediction report. See PROGRESS for feature CI status.
- [ ] Student performs a genuine authorized Zeek `-r` import in isolated Linux VMware, separately pins the PCAP/import-report/Zeek/model hashes and runs both gated scoring and independent gated review on Windows Python 3.12.9. Retain original files, VMware adapter/routes, Zeek version and scenario evidence privately.
- [ ] Independently verify host/session-disjoint held-out labels and measure actual Precision/Recall/FPR and event-to-alert latency before enabling operational alerts. Synthetic CI does not establish physical isolation, PCAP authenticity, real attack detection or SOC operation; active Red Team network execution stays disabled.

## Cyber Lab — verified PCAP provenance recheck at report review merged (29/10/2026)

- [x] [PR #137](https://github.com/tbao4151/DA_CNTT/pull/137) merged after final-head [CI #40742422992](https://github.com/tbao4151/DA_CNTT/actions/runs/40742422992) and post-merge [main CI #40743228957](https://github.com/tbao4151/DA_CNTT/actions/runs/40743228957) passed (**718 passed, 2 skipped, 2 warnings**). This supersedes the feature-authoring pending checkbox; optional read-only PCAP recheck now guards independent report review.
- [ ] Student runs actual Zeek `-r` on a private, authorized Host-only PCAP in Linux VMware, pins PCAP/import report/log/model hashes and executes both gated scoring and review on Windows Python 3.12.9. Keep physical isolation, Zeek version, scenario and annotation evidence outside Git.
- [ ] Establish genuine independent labels and host/session-disjoint held-out evaluation, then measure Precision/Recall/FPR and event-to-alert latency. No operational attack detection claim or active Red Team traffic from synthetic CI.


## Cyber Lab — pinned original-PCAP recheck before manual SOC case (29/10/2026)

- [ ] Verify final-head CI and merge the optional original-PCAP provenance recheck at `triage_zeek_new_log.py` and the core `create_new_log_candidate_case` write boundary. Preserve existing legacy commands and SQLite records. See PROGRESS for feature verification status.
- [ ] Student runs actual authorized Zeek `-r` on private Host-only PCAP in Linux VMware; separately pins PCAP/import report/log/model, then runs gated scoring, independent review, candidate listing and manual SOC case creation. Preserve adapter/routes, Zeek version, scenario authorization and independently reviewed labels outside Git.
- [ ] Validate held-out host/session-disjoint labels and measure real Precision/Recall/FPR and event-to-alert latency before any operational alert claims. Synthetic CI cannot prove capture authenticity, Host-only isolation, attack ground truth or live detection; Red Team network actions remain disabled.


## Cyber Lab — verified optional PCAP recheck at manual SOC write merged (29/10/2026)

- [x] [PR #139](https://github.com/tbao4151/DA_CNTT/pull/139) merged after final-head [CI #40748542366](https://github.com/tbao4151/DA_CNTT/actions/runs/40748542366) passed (**728 passed, 2 skipped, 2 warnings**). Earlier pending feature checklist is superseded; original PCAP/import/Zeek integrity is now optionally rechecked at manual SOC write, with legacy mode preserved.
- [ ] Student runs actual authorized Zeek `-r` on a private Host-only PCAP in Linux VMware, separately records SHA-256 pins, and runs gated scoring, review, listing and explicit SOC case creation on Windows Python 3.12.9. Preserve VMware adapter/routes, Zeek version, authorization, scenario notebook and original private evidence.
- [ ] Independently label and evaluate host/session-disjoint Zeek holdout, measure Precision/Recall/FPR and event-to-alert latency, then decide whether operational alerting is scientifically justified. Synthetic CI does not establish genuine capture, isolation, ground truth or detection performance; active Red Team network actions remain disabled.

## Cyber Lab — optional original-PCAP provenance in Blue Team UI (29/10/2026)

- [ ] Verify final-head CI and merge the Streamlit NEW-log UI optional three-field pinned PCAP gate, including a second verification at manual SOC write; see PROGRESS for authoring status. Existing no-PCAP UI/CLI and official UNSW benchmark must remain compatible.
- [ ] Student runs a genuine authorized Zeek `-r` import from a private Host-only PCAP, records independent hashes, and performs UI preview and manual SOC case creation on Windows Python 3.12.9. Retain original files, capture consent, VMware adapter/routes and Zeek version privately; test altered **copies** of source PCAP.
- [ ] Obtain independently labeled host/session-disjoint held-out captures, report Precision/Recall/FPR and measured event-to-alert latency. No real detection or physical isolation is established by synthetic CI; active Red Team traffic and automatic operational alerts remain disabled.

## Cyber Lab — verified optional original-PCAP gate in Blue Team UI merged (29/10/2026)

- [x] [PR #141](https://github.com/tbao4151/DA_CNTT/pull/141) merged after final-head [CI #40752707725](https://github.com/tbao4151/DA_CNTT/actions/runs/40752707725) passed (**736 passed, 2 skipped, 2 existing warnings**). This supersedes the pending feature checklist. Preview and manual SOC write now optionally recheck original PCAP/import/Zeek bytes while preserving legacy behavior.
- [ ] Student runs real authorized Zeek `-r` on a private VMware Host-only PCAP, independently pins the import report and completes Blue Team UI candidate review/manual SOC case creation on Windows Python 3.12.9. Preserve original evidence, adapter/routes, Zeek version and permissions outside Git; only tamper with copies.
- [ ] Independently evaluate host/session-disjoint labeled captures and event-to-alert latency before operational attack claims or active Red Team network execution. Synthetic CI and byte integrity do not prove capture authenticity or Host-only isolation.


## Cyber Lab — local real-Zeek benign offline acceptance (29/10/2026)

- [ ] Verify PR-head CI and merge the opt-in `scripts/smoke_zeek_offline.py` slice; it generates a deterministic **benign synthetic** classic PCAP, invokes an installed Zeek binary in offline `-r` mode, and verifies private import bytes. CI regression tests mock Zeek and cannot be counted as real-binary acceptance; see PROGRESS.
- [ ] Student runs the new CLI in the Linux VMware VM with real Zeek installed, preserves `benign_synthetic.pcap`, `conn.log`, importer report, smoke report and Zeek version privately; document actual result. This tests only the local offline toolchain and is not attack evidence or isolation proof.
- [ ] Separately capture **genuine authorized** Host-only traffic after checking adapters/routes and isolation; pin source/session hashes independently, prepare independent labels, and evaluate held-out Zeek AI Precision/Recall/FPR and end-to-end latency before operational alerts. Keep synthetic smoke fixtures out of the research dataset, preserve UNSW-NB15 official benchmark, and keep active Red Team disabled.


## Cyber Lab — verified benign synthetic Zeek smoke harness merged (29/10/2026)

- [x] [PR #143](https://github.com/tbao4151/DA_CNTT/pull/143) merged after final-head [CI #40757107763](https://github.com/tbao4151/DA_CNTT/actions/runs/40757107763) and post-merge [main CI #40757667200](https://github.com/tbao4151/DA_CNTT/actions/runs/40757667200) succeeded (**742 passed, 2 skipped, 2 existing warnings**). This supersedes the pending merge checkbox above. The tests mock Zeek and verify only the synthetic fixture format and offline harness control flow.
- [ ] Student runs `scripts/smoke_zeek_offline.py` with a **real** Zeek installation inside the Linux VM and saves actual `conn.log`, Zeek version and private report. Do not use the synthetic benign smoke as a captured attack, verified Host-only experiment or AI accuracy metric.
- [ ] Next, separately collect genuine authorized VMware Host-only traffic with independent session/host labels and evaluate held-out Zeek inference and SOC response latency. Keep active Red Team disabled until explicit isolation and authorization controls are verified.


## Cyber Lab — synthetic Zeek smoke exact-flow acceptance (29/10/2026)

- [ ] Verify PR-head CI and merge the fixture-flow guard. Require exactly one parsed UDP flow with the generated PCAP's addresses, ports and first-packet timestamp; reject unrelated in-scope Zeek logs. Tests use synthetic/mock Zeek only.
- [ ] Student runs the offline smoke with an installed real Zeek in a Linux VM and records `smoke_report.json`, Zeek version, original PCAP/conn.log and SHA-256 privately. This checks local binary decoding, **not** genuine Host-only capture or attack detection.
- [ ] Collect authorized, independently labeled Host-only captures separately; establish holdout metrics and end-to-end event-to-SOC latency before claiming real-world attack detection.


## Cyber Lab — exact synthetic Zeek fixture-flow gate verified (29/10/2026)

- [x] [PR #145](https://github.com/tbao4151/DA_CNTT/pull/145) merged; final-head [CI #40761458458](https://github.com/tbao4151/DA_CNTT/actions/runs/40761458458) and post-merge [main CI #40762224232](https://github.com/tbao4151/DA_CNTT/actions/runs/40762224232) succeeded (**750 passed, 2 skipped, 2 existing warnings**). This supersedes the earlier pending merge item. CI used mocked Zeek.
- [ ] Student runs installed Zeek with `scripts/smoke_zeek_offline.py` on a Linux VM and archives the private fixture PCAP, Zeek `conn.log`, version, reports and checksums. This is only synthetic benign toolchain acceptance, not actual VMware capture or attack detection.
- [ ] Independently validate real authorized Host-only capture and labels, then measure held-out Zeek AI precision/recall/FPR and end-to-end alert/SOC latency before making operational claims.


## Cyber Lab — real Zeek binary CI on synthetic offline PCAP (29/10/2026)

- [ ] Confirm the new `real-zeek-offline-smoke.yml` PR-head workflow runs **real Zeek 9.0.1** in a network-disabled Docker container and verifies the exact synthetic benign UDP flow; merge only after both new workflow and existing quality gate are green. At feature authoring this remains pending.
- [ ] Record the successful Actions run, Zeek version/image ID and synthetic-only artifact provenance; do not present runner CI as student laptop/VMware testing or as attack-detection evidence.
- [ ] Student executes `scripts/smoke_zeek_offline.py` on installed Zeek in Linux VMware, then separately obtains genuine authorized Host-only PCAP with adapter/routes evidence, independent labels, host/session-disjoint evaluation and measured event-to-SOC latency. Preserve UNSW official benchmark; keep Red Team network execution disabled.


## Cyber Lab — real Zeek binary smoke verified in PR CI (29/10/2026)

- [x] [Real-Zeek CI #40765032431](https://github.com/tbao4151/DA_CNTT/actions/runs/40765032431) passed with **Zeek 9.0.1 actually executing offline** on a deterministic benign synthetic PCAP and producing one correctly matched UDP flow. Synthetic-only artifact uploaded. This is distinct from mocked unit tests.
- [ ] Confirm the full quality gate on the **final PR #147 head**, ensure no merge conflicts or competing PRs, then merge; check post-merge CI separately. This item remains pending until verified.
- [ ] Student runs real installed Zeek in Linux VMware and archives local output, then separately captures authorized Host-only traffic with independent labels and measures held-out model Precision/Recall/FPR and event-to-SOC latency. Runner CI does not establish laptop/VMware acceptance, authentic capture or attack detection.


## Cyber Lab — real Zeek CI merged, local VMware acceptance remains (29/10/2026)

- [x] [PR #147](https://github.com/tbao4151/DA_CNTT/pull/147) merged at `6ae0cca55bb515386eb222dbfee445117ce39b1f` after final-head [real-binary Zeek CI #40765257813](https://github.com/tbao4151/DA_CNTT/actions/runs/40765257813) and [full quality gate #40765257770](https://github.com/tbao4151/DA_CNTT/actions/runs/40765257770) passed (750 passed, 2 skipped, 2 existing warnings). This supersedes the pending merge checkbox above.
- [ ] Student executes actual installed Zeek on Linux VMware, saves the benign synthetic smoke output and independently verifies Host-only adapters/routes before collecting genuine authorized PCAP. Keep synthetic CI evidence separate from research captures.
- [ ] Evaluate an independently labeled, host/session-disjoint Zeek holdout and event-to-SOC latency before claiming real attack detection. No active Red Team network actions, automatic operational alerts or changes to UNSW official benchmark.


## Cyber Lab — real Zeek to lab feature boundary (29/10/2026)

- [ ] Verify both full Python 3.12.9 quality gate and real Zeek 9.0.1 offline workflow on the final PR head, then merge only if conflict-free. New check should confirm the actual synthetic Zeek log projects onto exactly nine separate lab features without UID/IP/time/label leakage. See PROGRESS for the feature's pending status.
- [ ] Student runs the benign offline smoke with installed Zeek inside Linux VMware and retains version, PCAP, `conn.log`, feature-schema result, hashes and screenshots privately. This is not an attack experiment or evidence of Host-only isolation.
- [ ] Independently collect authorized genuine Host-only PCAP and labels, keep host/session-disjoint holdout, and evaluate Zeek-specific AI Precision/Recall/FPR and event-to-SOC latency before operational claims. Keep Red Team network execution disabled and UNSW-NB15 official benchmark unchanged.


## Cyber Lab — real Zeek feature projection CI verified (29/10/2026)

- [x] [PR #149](https://github.com/tbao4151/DA_CNTT/pull/149) merged after final-head [real Zeek #40769267570](https://github.com/tbao4151/DA_CNTT/actions/runs/40769267570) and [quality gate #40769267520](https://github.com/tbao4151/DA_CNTT/actions/runs/40769267520) passed (**753 passed, 2 skipped**); post-merge [main CI #40769902214](https://github.com/tbao4151/DA_CNTT/actions/runs/40769902214) also passed. The earlier pending item is superseded. Real Zeek on GitHub Linux now validates the separate nine-feature lab schema, **not** AI detection.
- [ ] Student executes the same benign smoke in a Linux VMware VM and records local Zeek version, hashes and artifacts privately; independently document Host-only adapters/routes and authorized capture provenance before collecting real traffic.
- [ ] Obtain independent labels and host/session-disjoint holdout; evaluate real Zeek-specific model metrics and event-to-SOC latency before claiming operational alerts. Do not treat synthetic fixture as attack ground truth; keep active Red Team disabled.


## Cyber Lab — production offline importer against real Zeek CI (29/10/2026)

- [ ] Verify both full Python 3.12.9 quality gates and dedicated real-Zeek workflow on the **final** [PR #151](https://github.com/tbao4151/DA_CNTT/pull/151) head before conflict-free merge. The new CI stage uses the actual offline importer with a `-r`-only network-disabled Zeek 9.0.1 Docker proxy, then re-verifies the imported `conn.log` and nine-feature projection; synthetic-only evidence, not a lab experiment.
- [ ] Student runs `scripts/smoke_zeek_offline.py` using installed Zeek inside Linux VMware and archives PCAP, `conn.log`, import report, Zeek version, checksums and screenshots privately. Independently inspect Host-only adapter and routes before any genuine capture.
- [ ] Obtain independently documented, authorized VMware Host-only PCAP with session/host-disjoint labels; evaluate Zeek-specific model Precision/Recall/FPR and event-to-SOC latency. Do not report synthetic smoke as attack detection; preserve UNSW benchmark and leave active Red Team disabled.


## Cyber Lab — real Zeek production importer CI verified (29/10/2026)

- [x] [PR #151](https://github.com/tbao4151/DA_CNTT/pull/151) merged after final-head [real Zeek CI #40773929990](https://github.com/tbao4151/DA_CNTT/actions/runs/40773929990) and [full quality gates #40773928870](https://github.com/tbao4151/DA_CNTT/actions/runs/40773928870) passed. This supersedes the pending merge item above. Actual `import_offline_pcap` ran with Zeek 9.0.1 inside a network-disabled container and produced independently verified **synthetic-only** log evidence.
- [ ] Student executes installed Zeek in a Linux VMware VM and saves local private evidence, then verifies actual Host-only adapter/routes and collects a separately authorized genuine PCAP. CI evidence is not laptop evidence.
- [ ] Evaluate independently labeled, host/session-disjoint lab data and measure model accuracy and event-to-SOC latency. No claim of real attack detection, operational alerting or Red Team active traffic is supported by the synthetic CI check.


## Cyber Lab — real Zeek to pinned research scoring acceptance (29/10/2026)

- [ ] Verify final-head real-Zeek CI **and** full Python 3.12.9 quality gates for the feature PR, ensure mergeability/no competing PR, then merge only when both are green. CI must execute the actual Zeek binary offline, production PCAP importer, pinned scorer and independent prediction review with deliberate tamper/pin rejection.
- [ ] Treat the CI-only Logistic Regression fitted on arbitrary synthetic labels strictly as an integration fixture; never publish its candidate count as accuracy, ground truth, or verified detection. Keep the model and predictions out of the uploaded artifact, retain only an explicitly labeled summary.
- [ ] Student must run real Zeek on Linux VMware and separately collect authorized Host-only traffic with independently verified adapter/routes, session/host-disjoint labels and true holdout; then measure Precision/Recall/FPR and event-to-SOC latency before operational alert claims. Preserve official UNSW benchmark, disable active Red Team.


## Cyber Lab — real Zeek pinned scoring CI verified and merged (29/10/2026)

- [x] [PR #153](https://github.com/tbao4151/DA_CNTT/pull/153) merged after final-head [real-Zeek #40778318436](https://github.com/tbao4151/DA_CNTT/actions/runs/40778318436) and [quality gates #40778318423](https://github.com/tbao4151/DA_CNTT/actions/runs/40778318423) succeeded (**764 passed, 2 skipped**). Post-merge [main CI #40778687801](https://github.com/tbao4151/DA_CNTT/actions/runs/40778687801) succeeded. This supersedes the earlier pending feature gate.
- [x] CI-only synthetic training artifact exercised production PCAP importer → pinned Zeek research scorer → independent report verification, including tampered-probability and wrong-model-hash rejection. The synthetic model/labels are not research ground truth or detection evidence; no SOC write or active network attack occurred.
- [ ] Student must run the offline Zeek smoke in Linux VMware and retain PCAP/conn.log/versions/hashes, then separately verify Host-only isolation, collect genuine authorized captures, establish independent labels and session/host-disjoint holdout, and measure actual model Precision/Recall/FPR and event-to-SOC latency. Keep Red Team network execution disabled; do not reuse CI-only synthetic model.


## Cyber Lab — synthetic real-Zeek to manual SOC acceptance (29/10/2026)

- [ ] Verify both Python 3.12.9 quality gates and the dedicated **real Zeek** workflow on the final feature head. Merge only if green and conflict-free. The new CI path must exercise the production PCAP importer → pinned research scorer → independent report review → explicitly confirmed manual `Unclassified` SOC case, then prove idempotency and fail-closed behavior when PCAP or confirmation is invalid.
- [ ] Keep the separate neutralized-coefficient CI-only model (threshold 0.49) and disposable CI case strictly outside research results. Never call this an operational AI alert, verified attack, or independent evaluation. Upload only a clearly labeled synthetic summary, not model/DB/UID/IP evidence.
- [ ] Student runs Zeek locally inside Linux VMware, verifies actual Host-only isolation and collects authorized real PCAP with independently established labels/host-disjoint holdout; only then measure model Precision/Recall/FPR and event-to-SOC latency. Red Team active network actions remain disabled.


## Cyber Lab — verified synthetic real Zeek → manual SOC CI (#155, 29/10/2026)

- [x] [PR #155](https://github.com/tbao4151/DA_CNTT/pull/155) merged after [real Zeek CI #40782784754](https://github.com/tbao4151/DA_CNTT/actions/runs/40782784754) and [Python 3.12.9 quality gates #40782784659](https://github.com/tbao4151/DA_CNTT/actions/runs/40782784659) passed (**774 passed, 2 skipped**). This supersedes the earlier pending feature checklist. The synthetic PCAP passed real Zeek importer → separate feature schema → research scoring/review → explicit manual `Unclassified` SOC case, with idempotency and fail-closed regression. **No operational alert or verified attack**.
- [ ] Student runs actual Zeek on Linux VMware and archives PCAP, conn.log, Zeek version, checksums and screenshots; independently verifies Host-only adapter/routes before any authorized genuine capture.
- [ ] Collect independently labeled, host/session-disjoint lab captures, evaluate Zeek-specific model Precision/Recall/FPR and measure event-to-SOC latency. Keep the CI-only neutral fixture out of research metrics, leave Red Team active traffic disabled, and preserve the official UNSW-NB15 benchmark.


## Cyber Lab — private offline Zeek telemetry quality acceptance (29/10/2026)

- [ ] Verify final feature PR-head Python 3.12.9 quality gates and merge only when green and conflict-free. New read-only quality CLI must reject altered SHA-256, malformed/out-of-scope logs and duplicate UIDs, while preserving private identifiers and original data.
- [ ] Student runs `scripts/inspect_zeek_telemetry_quality.py` against genuine authorized Zeek `conn.log` in a private Windows folder and archives original PCAP/log, separately recorded hashes, Zeek version, Host-only adapter/routes evidence and quality JSON. Synthetic CI tests are not student lab evidence.
- [ ] Independently annotate multiple host/session-disjoint captures and evaluate held-out Zeek-specific Precision/Recall/FPR and event-to-SOC latency; do not infer attack labels or physical isolation from aggregate quality checks. Keep UNSW-NB15 official benchmark and Red Team network-disabled.


## Cyber Lab — private Zeek telemetry quality CLI verified (29/10/2026)

- [x] [PR #157](https://github.com/tbao4151/DA_CNTT/pull/157) merged after final-head [CI #40785698571](https://github.com/tbao4151/DA_CNTT/actions/runs/40785698571) and post-merge [main CI #40786278275](https://github.com/tbao4151/DA_CNTT/actions/runs/40786278275) passed (**782 passed, 2 skipped, 2 warnings**). Earlier pending CI/merge checklist is superseded; regression fixtures are synthetic only.
- [ ] Student runs real authorized Zeek `conn.log` through the private quality CLI on Windows Python 3.12.9, retaining original PCAP/log, separate hashes, Zeek version, VMware Host-only adapter/routes and authorization evidence outside Git.
- [ ] Independently label multiple host/session-disjoint genuine captures, evaluate Precision/Recall/FPR and event-to-SOC latency with measured boundaries. Aggregate data-quality checks cannot prove capture authenticity, ground truth or attack detection; Red Team network execution stays disabled.


## Cyber Lab — real Zeek telemetry quality acceptance (29/10/2026)

- [ ] Verify final-head **real Zeek 9.0.1** workflow and Python 3.12.9 quality gates for the feature PR before merging; the new CI stage must invoke the production private telemetry-quality CLI on actual synthetic Zeek output and reject wrong SHA-256, wrong CIDR and overwrite attempts without changing the source.
- [ ] Student runs installed Zeek inside Linux VMware and separately records source hashes, Host-only adapters/routes, capture authorization, private PCAP/conn.log and quality JSON. A synthetic CI-generated pin is not independent capture provenance or Windows acceptance.
- [ ] Establish independent attack labels and host/session-disjoint holdout, evaluate Zeek-specific Precision/Recall/FPR and event-to-SOC latency; preserve UNSW-NB15 baseline and keep Red Team network execution disabled. The quality screen does not establish attack detection.


## Cyber Lab — verified real Zeek telemetry quality CI (#159, 29/10/2026)

- [x] [PR #159](https://github.com/tbao4151/DA_CNTT/pull/159) merged after [real Zeek workflow #40788858404](https://github.com/tbao4151/DA_CNTT/actions/runs/40788858404) and [Python 3.12.9 quality gates #40788858348](https://github.com/tbao4151/DA_CNTT/actions/runs/40788858348) passed (**782 passed, 2 skipped**). This supersedes the earlier pending feature checklist; only the synthetic offline integration was verified.
- [ ] Student collects separate Windows/Linux VMware evidence with independently recorded hashes, Host-only adapter/routes and authorized PCAP; run private quality CLI on genuine `conn.log` before annotation.
- [ ] Independently label host/session-disjoint real captures and measure Precision/Recall/FPR plus event-to-SOC latency. A synthetic Zeek quality pass is not detection, and active Red Team traffic remains disabled.


## Cyber Lab — optional per-split pinned telemetry quality gate (29/10/2026)

- [ ] Verify final-head Python 3.12.9 CI for the feature branch implementing `--require-telemetry-quality` in `scripts/evaluate_zeek_lab.py`; merge only if green and conflict-free. The opt-in must require explicit `--cidr`, screen **every** pinned capture before fitting, and expose only fixed aggregate quality counters by split; legacy reports must remain unchanged.
- [ ] Student independently verifies VMware Host-only adapters/routes, captures authorized genuine traffic, records separate PCAP/Zeek SHA-256, and runs both private quality preflight and independent host/session-disjoint annotation evaluation on Windows. Warnings are not attack labels or proof of isolation; no real detection performance or event-to-SOC latency has been measured.
- [ ] Continue trustworthy lab-specific model evaluation and measured SOC workflow before operational alerts. Preserve UNSW official benchmark and keep active Red Team traffic disabled.


## Cyber Lab — verified opt-in manifest quality gate (#161, 29/10/2026)

- [x] [PR #161](https://github.com/tbao4151/DA_CNTT/pull/161) merged after final-head [Python 3.12.9 CI #40792521743](https://github.com/tbao4151/DA_CNTT/actions/runs/40792521743) passed (**786 passed, 2 skipped**); previous pending merge item superseded. Post-merge main CI #40792986576 was still running when this entry was authored.
- [ ] Students validate private Windows/VMware Host-only captures with separately recorded SHA-256, adapter/routes evidence and independently assigned labels. Then run `--require-telemetry-quality --cidr ... --preflight` and held-out evaluation. Missing-value warnings cannot be used as labels or to tune held-out test metrics.
- [ ] Independently evaluate real Zeek-specific Precision/Recall/FPR and event-to-SOC latency before operational alerts or active Red Team. Preserve official UNSW benchmark.

## Cyber Lab — Windows offline contract CI acceptance (29/10/2026; PR #163)

- [ ] Verify final PR-head Windows Server 2022 / Python 3.12.9 offline test job and Ubuntu quality gates; check that PR #163 is mergeable and main has not advanced incompatibly before merge. Record actual run links and test counts; do not infer CI success from workflow creation.
- [ ] Student runs the documented offline tests on their own Windows 11 Python 3.12.9 machine and retains console output/screenshots. Separately verify VMware Host-only adapters/routes and execute real Zeek on authorized captures in a Linux VM.
- [ ] Obtain independently labeled, host/session-disjoint genuine Zeek captures before measuring Precision/Recall/FPR and event-to-SOC latency. Windows synthetic CI is not attack-detection evidence; preserve official UNSW-NB15 benchmark and keep active Red Team network actions disabled.

### Windows offline CI — observed green checks, final-head gate pending

- [x] PR #163 earlier head `edf587bfc492b1619c5a6f313dae2375be0b1dca`: [Windows CI #40795902419](https://github.com/tbao4151/DA_CNTT/actions/runs/40795902419) **74 passed**; [Ubuntu CI #40795902460](https://github.com/tbao4151/DA_CNTT/actions/runs/40795902460) **786 passed, 2 skipped**.
- [ ] Recheck final documentation head and clean mergeability before merging PR #163. GitHub-hosted Windows acceptance is software-only; real student Windows/VMware validation and independently labeled Zeek detection research remain open.

## Cyber Lab — Windows offline CI final-head verified and merged (#163, 29/10/2026)

- [x] [PR #163](https://github.com/tbao4151/DA_CNTT/pull/163) merged after final-head [Windows CI #40796453742](https://github.com/tbao4151/DA_CNTT/actions/runs/40796453742) **74 passed** and [Ubuntu CI #40796453732](https://github.com/tbao4151/DA_CNTT/actions/runs/40796453732) **786 passed, 2 skipped**. This supersedes earlier pending verification entries; the checked workflows are synthetic/offline software tests only.
- [ ] Student runs the same offline regression on their Windows 11 Python 3.12.9 laptop, then separately validates VMware Host-only adapter/routes, runs Zeek in Linux VM, archives authorized PCAP/conn.log and independently pinned hashes. GitHub Windows CI is not local hardware acceptance.
- [ ] Establish independently labeled host/session-disjoint Zeek captures, calculate Precision/Recall/FPR and event-to-SOC latency with explicit measurement boundaries. Do not use synthetic CI model or artificial candidate selection for detection claims. Preserve official UNSW-NB15 benchmark and keep Red Team active network actions disabled.


## Cyber Lab — optional UID-independent cross-split flow overlap (29/10/2026)

- [ ] Verify final feature-head Python 3.12.9 Ubuntu quality gates **and** Windows offline Zeek CI; merge only after both pass and GitHub reports a clean, conflict-free PR. The opt-in guard rejects same timestamp/five-tuple reused across TRAIN/VALIDATION/TEST despite different Zeek UIDs; default research behavior remains unchanged.
- [ ] Student repeats strict preflight with `--require-uid-independent-overlap` on separately pinned authorized captures in Windows 11, retaining private results and investigating possible exact-key collisions without modifying original evidence. Exact overlap checks can have false positives and cannot establish genuine capture independence.
- [ ] Independently verify VMware Host-only adapter/routes, run real Zeek on authorized genuine traffic, obtain independent labels and evaluate held-out Precision/Recall/FPR and event-to-SOC latency. Preserve UNSW official benchmark; active Red Team network actions stay disabled.


## Cyber Lab — UID-independent Zeek overlap gate verified (#165, 29/10/2026)

- [x] [PR #165](https://github.com/tbao4151/DA_CNTT/pull/165) merged after final-head [Ubuntu Python 3.12.9 #40798459769](https://github.com/tbao4151/DA_CNTT/actions/runs/40798459769) (**788 passed, 2 skipped**) and [Windows Python 3.12.9 #40798459757](https://github.com/tbao4151/DA_CNTT/actions/runs/40798459757) (**76 passed**) succeeded; conflict-free. Supersedes the pending feature gate above.
- [ ] Student runs strict preflight on genuine, separately pinned, authorized Zeek captures on Windows 11 and privately investigates any exact timestamp/five-tuple collisions. GitHub CI is synthetic software verification, not local capture evidence.
- [ ] Verify VMware Host-only isolation independently, obtain independent labels and host/session-disjoint holdout, then measure Zeek-specific Precision/Recall/FPR and event-to-SOC latency. Preserve UNSW benchmark and keep active Red Team network-disabled.


## Cyber Lab — one-switch strict offline research input gates (29/10/2026)

- [ ] Verify final PR-head Ubuntu Python 3.12.9 quality gates and Windows offline Zeek CI, then merge the `--strict-input-gates` convenience option only if both pass and GitHub reports no conflicts. This bundles existing label SHA-256, telemetry quality and UID-independent cross-split overlap screens; it is not a new model or live sensor.
- [ ] Student runs strict `--preflight` with an independently established Host-only CIDR and fully pinned private Zeek/label files, then only after review runs held-out research evaluation. Archive separate checksums, scenario notes, independent annotations and VMware/Zeek evidence outside public GitHub.
- [ ] Evaluate genuine independently labeled, host/session-disjoint lab captures and measured event-to-SOC latency. A passing strict preflight is only internal consistency, not verified isolation, attack detection or scientific accuracy. Keep Red Team active traffic disabled and preserve the UNSW-NB15 official benchmark.


## Cyber Lab — strict offline Zeek input gate verified (#167, 29/10/2026)

- [x] [PR #167](https://github.com/tbao4151/DA_CNTT/pull/167) merged conflict-free after final-head [Ubuntu Python 3.12.9 CI #40801801187](https://github.com/tbao4151/DA_CNTT/actions/runs/40801801187) (**791 passed, 2 skipped**) and [Windows Python 3.12.9 CI #40801801069](https://github.com/tbao4151/DA_CNTT/actions/runs/40801801069) (**79 passed**) succeeded. Supersedes the earlier pending gate item; synthetic regressions only.
- [ ] Student runs strict `--preflight` on independently pinned authorized Host-only Zeek captures and labels in Windows 11, preserving original PCAP/log, Zeek version, independent checksum records, network-isolation screenshots and adjudication notes outside public GitHub.
- [ ] Establish authentic independent labels and host/session-disjoint holdout; evaluate Zeek-specific Precision/Recall/FPR and measured event-to-SOC latency. A strict input gate cannot prove scientific validity or operational attack detection; keep Red Team active traffic disabled and UNSW official benchmark unchanged.


## Cyber Lab — independent manifest byte pin for strict offline experiments (29/10/2026)

- [ ] Verify final PR-head Ubuntu Python 3.12.9 quality gates and Windows offline Zeek CI for optional `--expected-manifest-sha256`; merge only after both pass and the PR is conflict-free. Confirm the pin applies before parsing/fitting/writing in `--preflight`, `--output` and private `--trace-output` modes; legacy CLI behavior remains unchanged.
- [ ] Students record the manifest SHA-256 in an **independent private lab notebook before evaluating** (alongside original PCAP/Zeek/label pins, capture authorization and VMware Host-only adapter/routes evidence), then reuse that same value with `--strict-input-gates` for preflight and held-out evaluation. A changed manifest must trigger investigation, not silent re-pinning.
- [ ] Obtain independently verified labels and host/session-disjoint authorized real captures, then report Zeek-specific Precision/Recall/FPR and measured event-to-SOC latency. SHA-256 pins cannot prove scientific validity or physical isolation; UNSW benchmark stays unchanged and active Red Team traffic remains disabled.


## Cyber Lab — manifest byte pin verified and merged (#169, 29/10/2026)

- [x] [PR #169](https://github.com/tbao4151/DA_CNTT/pull/169) merged after final-head [Ubuntu Python 3.12.9 #40804453810](https://github.com/tbao4151/DA_CNTT/actions/runs/40804453810) (**799 passed, 2 skipped**) and [Windows Python 3.12.9 #40804453793](https://github.com/tbao4151/DA_CNTT/actions/runs/40804453793) (**87 passed**) succeeded; no conflict. This supersedes the pending feature-merge gate above. Synthetic/offline tests only.
- [ ] Students independently archive the exact manifest SHA-256 **before** final held-out evaluation and reuse the recorded value with `--expected-manifest-sha256 --strict-input-gates` for both preflight and final report. Keep original PCAP/log/labels, authorization, Zeek version, Windows/VMware Host-only adapter/routes and annotation decisions in a private evidence bundle.
- [ ] Measure held-out Zeek Precision/Recall/FPR and event-to-SOC latency on genuine authorized captures with independently established ground truth and host/session separation. Manifest integrity cannot certify authorship, isolation, label validity or real attack detection; Red Team active network actions stay disabled and UNSW-NB15 benchmark remains unchanged.


## Red Team — linked offline proposal audit acceptance (29/10/2026)

- [ ] Verify final PR-head Python 3.12.9 quality gates and Streamlit AppTest for the in-memory proposal/feedback timeline. Merge only if the PR is conflict-free and all required CI passes; record exact workflow URLs and counts.
- [ ] Student runs `tests/test_red_team_planning_audit.py` and `tests/test_red_team_scenario_policy.py` on Windows 11 and checks proposal → explicit unverified feedback → timeline JSON export → stop/clear in the Red Team UI. Preserve local screenshots without publishing private lab information.
- [ ] Before using observations for research, independently establish authorized Host-only capture provenance, real Zeek telemetry, independent Blue Team outcomes and host/session-disjoint evaluation. Session-only policy chronology is not a replay runner, attack-detection proof, secure audit store or event-to-SOC latency measurement. Keep active Red Team traffic disabled and the UNSW-NB15 official benchmark unchanged.


## Red Team — verified offline planning audit (#171, 29/10/2026)

- [x] [PR #171](https://github.com/tbao4151/DA_CNTT/pull/171) merged conflict-free after final-head [Ubuntu Python 3.12.9 #40807809739](https://github.com/tbao4151/DA_CNTT/actions/runs/40807809739) (**811 passed, 2 skipped**) and [Windows Python 3.12.9 #40807809829](https://github.com/tbao4151/DA_CNTT/actions/runs/40807809829) (**87 Zeek + 29 Red Team passed**). Supersedes the earlier pending CI/merge checklist. All new observations are synthetic/manual and unverified.
- [ ] Student validates proposal → linked manual feedback → JSON timeline → stop/clear on their own Windows 11 laptop, retaining local screenshots and a private export. Do not interpret UI-action UTC timestamps as network/detection latency or operator-entered feedback as authenticated Blue Team outcomes.
- [ ] Build authorized VMware Host-only evidence, independent scenario and Blue Team annotation records, holdout by host/session, and real Zeek-specific Precision/Recall/FPR plus event-to-SOC timing before claiming AI-vs-AI performance. Keep Red Team network execution disabled and preserve official UNSW-NB15 benchmark.


## Red Team — independently verify offline planning export (29/10/2026)

- [ ] Verify Ubuntu Python 3.12.9 full quality CI and Windows offline Red Team tests for the read-only JSON export verifier; merge only when final-head checks pass and no conflicts.
- [ ] Student exports the Red Team UI session chronology to a private Windows path, records SHA-256 independently, and runs `scripts/verify_red_team_planning_audit.py --audit ... --expected-sha256 ...`. Test a modified copy to confirm rejection; do not repin the changed copy silently.
- [ ] Keep operator-entered observations explicitly unverified; acquire independently labeled authorized Host-only Zeek capture, Blue Team outcome and event-to-SOC timing evidence before claiming AI-vs-AI effectiveness. No replay, attack, network access or official UNSW benchmark change is included.


## Red Team — offline planning export verifier verified (#173, 29/10/2026)

- [x] [PR #173](https://github.com/tbao4151/DA_CNTT/pull/173) merged cleanly after final-head [Ubuntu Python 3.12.9 #40811105273](https://github.com/tbao4151/DA_CNTT/actions/runs/40811105273) (**827 passed, 2 skipped**) and [Windows Python 3.12.9 #40811105170](https://github.com/tbao4151/DA_CNTT/actions/runs/40811105170) (**87 Zeek + 45 Red Team passed**) succeeded. Post-merge [main CI #40811595051](https://github.com/tbao4151/DA_CNTT/actions/runs/40811595051) succeeded. Supersedes the preceding pending CI/merge checklist.
- [ ] Student validates private exported JSON on their Windows 11 machine using an independently preserved SHA-256, including tampering with a copy to verify rejection. Preserve the source and screenshot privately; GitHub-hosted Windows CI is not laptop acceptance.
- [ ] Independently establish authorized VMware Host-only capture provenance, adjudicated Blue Team labels, session/host-separated evaluation and event-to-SOC latency before claiming genuine detection or AI-vs-AI advantage. Planning feedback remains unverified, no active Red Team traffic, official UNSW benchmark unchanged.


## Red Team — pending-proposal UI audit consistency (29/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 full quality gates and Windows offline Red Team/AppTest checks for pending-scenario reconstruction from the audited strategy/seed; merge only when both pass and the PR is conflict-free. The separate stale UI cache must never determine which scenario the operator sees.
- [ ] Student tests Red Team proposal, Streamlit rerun/navigation, pending feedback, JSON export and stop/reset on their own Windows 11 laptop; retain screenshots privately. GitHub-hosted tests are not local acceptance.
- [ ] Independently collect authorized VMware Host-only Zeek evidence, adjudicated labels and measured event-to-SOC latency before comparing UCB1 with random using real Blue Team outcomes. The offline planner does not send traffic; preserve UNSW-NB15 official benchmark.


## Red Team — pending-plan UI reconstruction merged (#175, 29/10/2026)

- [x] [PR #175](https://github.com/tbao4151/DA_CNTT/pull/175) merged after final-head [Ubuntu CI #40813579884](https://github.com/tbao4151/DA_CNTT/actions/runs/40813579884) (**828 passed, 2 skipped**) and [Windows CI #40813579774](https://github.com/tbao4151/DA_CNTT/actions/runs/40813579774) (**87 Zeek + 46 Red Team passed**) succeeded; mergeability and unchanged base were checked. This supersedes the earlier pending PR verification checklist.
- [ ] Student tests Red Team pending proposal and manual feedback after rerun/navigation on their own Windows 11 machine, exports a private audit and independently records SHA-256. GitHub-hosted Windows CI does not prove laptop acceptance.
- [ ] Build independently labeled, authorized VMware Host-only Zeek experiments and measure genuine Blue Team outcomes and event-to-SOC latency before any AI-vs-AI effectiveness claim. Offline Red Team execution remains disabled and official UNSW-NB15 benchmark unchanged.


## Cyber Lab — Zeek ASCII declared-type provenance (29/10/2026)

- [ ] Verify and merge the optional `--require-zeek-types` quality/manifest gate only after final-head Ubuntu, Windows and network-disabled real Zeek synthetic CI pass without conflict. Missing, conflicting, duplicate or late `#types` must fail before experiment output.
- [ ] On Windows 11/VMware, run the private typed-header gate on a genuine authorized Zeek `conn.log`, recording PCAP/log SHA-256, Zeek version and Host-only isolation proof separately. Header correctness alone does not establish capture authenticity or label validity.
- [ ] Continue independently labeled host/session-disjoint experiments, measured event-to-alert/SOC latency and held-out Zeek Precision/Recall/FPR. No synthetic metric is real detection evidence. Red Team active traffic stays disabled; Dataset Mode remains unchanged.


## Cyber Lab — declared Zeek types gate verified (#177, 29/10/2026)

- [x] [PR #177](https://github.com/tbao4151/DA_CNTT/pull/177) merged after final-head [Ubuntu CI #40816621940](https://github.com/tbao4151/DA_CNTT/actions/runs/40816621940) (**839 passed, 2 skipped**), [Windows CI #40816621786](https://github.com/tbao4151/DA_CNTT/actions/runs/40816621786) (**98 Zeek + 46 Red Team passed**) and [real Zeek synthetic CI #40816621990](https://github.com/tbao4151/DA_CNTT/actions/runs/40816621990) passed. Supersedes the pending CI/merge item above. No student laptop experiment was performed.
- [ ] Student independently pins and validates genuine authorized Zeek `conn.log` headers on Windows 11/VMware Host-only, preserving original PCAP/log, Zeek version, network isolation screenshots, ground truth and session/host split evidence privately. Use `--require-zeek-types` for both preflight and evaluation when appropriate.
- [ ] Measure held-out Zeek Precision/Recall/FPR and event-to-SOC latency on genuine independently labeled captures; passing declared type checks cannot establish scientific validity, live collection or attack detection. Red Team active network execution remains disabled.


## Cyber Lab — operator-declared UTC event-start guard (29/10/2026)

- [ ] Verify final PR-head Ubuntu Python 3.12.9 full suite and Windows offline Zeek suite for the opt-in **single-log** `--event-start-utc` / `--event-end-utc` guard. Merge only when both CI workflows pass and the PR is conflict-free.
- [ ] On Windows 11, independently record actual authorized VMware Host-only experiment time bounds in UTC, Zeek version, source PCAP/log SHA-256 and VM/host clock evidence. Run the private pinned-log quality CLI with both bounds, preserving original bytes and rejecting unexpected event-start times instead of broadening the window.
- [ ] Do not interpret Zeek connection-start `ts` or an operator-entered window as independently verified capture time or event-to-SOC latency. Gather real event/alert/SOC timestamps, independently adjudicated labels and host/session-disjoint held-out captures for scientific Precision/Recall/FPR and latency. Keep active Red Team network execution disabled and UNSW-NB15 official benchmark unchanged.


## Cyber Lab — UTC event-start gate merged (#179, 29/10/2026)

- [x] [PR #179](https://github.com/tbao4151/DA_CNTT/pull/179) merged conflict-free after final-head [Ubuntu #40819653212](https://github.com/tbao4151/DA_CNTT/actions/runs/40819653212) (**852 passed, 2 skipped**), [Windows #40819653198](https://github.com/tbao4151/DA_CNTT/actions/runs/40819653198) (**111 Zeek + 46 Red Team passed**) and [real Zeek synthetic #40819653215](https://github.com/tbao4151/DA_CNTT/actions/runs/40819653215) succeeded. This supersedes the pending feature merge gate above; no actual Windows 11/VMware run occurred.
- [ ] Student records independently verified authorized Host-only capture start/end and clock configuration, preserves private PCAP/log SHA-256 and Zeek version, then runs the opt-in single-log UTC gate without changing source bytes or broadening the recorded window. Review legitimate long-lived flows that begin before a capture window.
- [ ] Obtain genuine host/session-disjoint labeled Zeek captures and independently measured event-to-alert/SOC timestamps. A passing timestamp guard is only operator-declared log consistency, not evidence of real attack detection, isolation or latency. Keep Dataset Mode baseline and Red Team active-network-disabled state unchanged.


## Cyber Lab — manifest-wide UTC event-start gate (29/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 full suite and Windows offline Zeek CI for opt-in `evaluate_zeek_lab.py --event-start-utc ... --event-end-utc ...` across every manifest capture; merge only if checks pass and the PR is conflict-free. This extends the previously merged single-log check, without changing Dataset Mode.
- [ ] Student records independent approved UTC capture windows, PCAP/log hashes, Zeek/VMware versions, network isolation and host clock evidence for genuine Host-only sessions; test the new gate on Windows 11 and retain private reports. A single broad window is not proof that sessions are independent.
- [ ] Obtain genuine, independently labeled host/session-disjoint Zeek data and measure actual event-to-alert/SOC timing. Operator-declared Zeek start times cannot establish authentic capture or detection performance; Red Team active traffic stays disabled.


## Cyber Lab — verified manifest-wide UTC event-start gate (#181, 29/10/2026)

- [x] [PR #181](https://github.com/tbao4151/DA_CNTT/pull/181) merged conflict-free after [Ubuntu CI #40821573729](https://github.com/tbao4151/DA_CNTT/actions/runs/40821573729) (**861 passed, 2 skipped**), [Windows CI #40821573777](https://github.com/tbao4151/DA_CNTT/actions/runs/40821573777) (**120 Zeek + 46 Red Team passed**) and [real Zeek synthetic CI #40821573782](https://github.com/tbao4151/DA_CNTT/actions/runs/40821573782) succeeded. Supersedes the feature CI-pending item above; no student VMware experiment is claimed.
- [ ] Student verifies a genuine approved Host-only experiment on Windows 11 using independently recorded UTC session bounds, original Zeek/PCAP SHA-256, Zeek version, clock and network isolation evidence; run pinned manifest preflight and preserve private output. One broad interval does not prove session independence.
- [ ] Collect independently adjudicated host/session-disjoint labels, evaluate real held-out Precision/Recall/FPR and independently measure event-to-alert/SOC timing before any detection claim. Active Red Team traffic remains disabled and Dataset Mode benchmark unchanged.



## Cyber Lab — optional originator-address split separation (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 quality gates and Windows offline Zeek targeted tests for `--require-originator-ip-disjoint`, then merge only if both pass and GitHub reports no conflicts. This screen is optional, **not** part of the existing strict bundle; it compares normalized Zeek connection originator addresses across TRAIN/VALIDATION/TEST and allows shared responder servers.
- [ ] Student establishes a justified originator/host split policy **before** seeing held-out results, documents NAT/DHCP/shared-client limitations, pins real authorized Host-only Zeek/PCAP and annotations independently, and runs the private Windows preflight. Keep all raw evidence outside public Git.
- [ ] Collect independently adjudicated, genuinely host/session-disjoint data and measured event-to-alert/SOC timestamps before reporting Zeek Precision/Recall/FPR or Red Team AI effectiveness. Originator-address disjointness is not physical host identity, capture authenticity, independent label verification or network isolation; UNSW benchmark and Red Team active traffic remain unchanged.



## Cyber Lab — originator-address split screen verified (#183, 29/10/2026)

- [x] [PR #183](https://github.com/tbao4151/DA_CNTT/pull/183) merged conflict-free after final-head [Ubuntu CI #40825228591](https://github.com/tbao4151/DA_CNTT/actions/runs/40825228591) (**864 passed, 2 skipped**) and [Windows CI #40825228683](https://github.com/tbao4151/DA_CNTT/actions/runs/40825228683) (**123 Zeek + 46 Red Team passed**) succeeded. Supersedes the preceding pending merge item. No actual student VMware capture was performed.
- [ ] Student chooses and documents an originator/host split policy before held-out evaluation, verifies authorized VMware Host-only network and genuine Zeek capture on Windows 11, independently pins original PCAP/log/annotation hashes, then runs private `--require-originator-ip-disjoint --preflight` as appropriate. Investigate NAT/DHCP/shared-client refusals; do not alter evidence to force a pass.
- [ ] Establish independently adjudicated, host/session-disjoint held-out labels and real event-to-alert/SOC timing. This address-level screen does not authenticate hosts or ground truth, and does not establish attack-detection effectiveness. Dataset Mode UNSW benchmark and active Red Team disabled state remain unchanged.


## Blue Team — Zeek port-feature ablation research (29/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 full CI and Windows offline Zeek test suite for the opt-in full-nine-feature versus no-src/dst-port comparison; merge only if both pass and the PR remains conflict-free. This is not a production model change.
- [ ] Student preregisters both variants and host/session-disjoint TRAIN/VALIDATION/TEST split, independently pins the manifest and annotation hashes, verifies real VMware Host-only capture scope/isolation, and runs `--strict-input-gates --port-ablation-output` privately on Windows 11. Keep the original PCAP/Zeek/label evidence outside public Git.
- [ ] Report actual class supports, Precision/Recall/FPR and uncertainty across independent captures only after label adjudication. The paired test difference is descriptive, not causal, and cannot be used to choose a winner on held-out TEST. Event-to-alert/SOC latency and authorized live collection remain unverified; Red Team active network execution remains disabled and official UNSW-NB15 benchmark unchanged.


## Blue Team — Zeek port-feature ablation verified (#185, 29/10/2026)

- [x] [PR #185](https://github.com/tbao4151/DA_CNTT/pull/185) merged after final-head [Ubuntu Python 3.12.9 CI #40828870693](https://github.com/tbao4151/DA_CNTT/actions/runs/40828870693) (**871 passed, 2 skipped**) and [Windows Python 3.12.9 CI #40828870679](https://github.com/tbao4151/DA_CNTT/actions/runs/40828870679) (**130 Zeek + 46 Red Team passed**) succeeded. Supersedes the earlier pending feature-merge item; no student laptop run is claimed.
- [ ] Student independently validates a genuine authorized Host-only Zeek manifest on Windows 11, pins source and annotation hashes, preregisters two variants and split assignments, and runs the private `--strict-input-gates --port-ablation-output` workflow. Preserve PCAP, Zeek version, labels, clock and network-isolation evidence outside Git.
- [ ] Confirm actual held-out Precision/Recall/FPR with adjudicated labels and host/session-independent replication, then separately measure event-to-alert/SOC latency. The paired port ablation cannot establish causality or justify choosing a variant based on held-out TEST. No active Red Team network, UNSW benchmark or SOC workflow changes.


## Blue Team — paired Zeek ablation host-group diagnostics (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 and Windows offline Zeek CI and merge only when both pass with no conflict. The optional private port-ablation report schema v2 now contains anonymized per-variant VALIDATION and TEST host-group confusion/rate summaries, with undefined rates and small/single-group warnings. This is descriptive research only.
- [ ] Student preregisters split, both feature variants, metrics and evaluation plan; independently preserves authorized Host-only PCAP/Zeek/annotation hashes, VMware isolation and clock evidence, and runs the pinned private ablation on Windows 11. Review host-group support and disagreement without selecting a model from held-out TEST.
- [ ] Obtain independently adjudicated multi-host/session evidence and measured event-to-alert/SOC latency. Operator-declared host groups are not authenticated, flow-level counts are correlated, and host summaries are not cluster-adjusted confidence intervals. No live capture, active Red Team traffic, operational alert or official UNSW benchmark change is part of this slice.


## Blue Team — verified paired Zeek host diagnostics (#187, 29/10/2026)

- [x] [PR #187](https://github.com/tbao4151/DA_CNTT/pull/187) merged conflict-free after final-head [Ubuntu CI #40830565924](https://github.com/tbao4151/DA_CNTT/actions/runs/40830565924) (**873 passed, 2 skipped**) and [Windows CI #40830565922](https://github.com/tbao4151/DA_CNTT/actions/runs/40830565922) (**132 Zeek + 46 Red Team passed**) succeeded. Supersedes the earlier pending merge gate. No student laptop or real capture was tested.
- [ ] Student obtains independently labeled authorized VMware Host-only PCAP/Zeek sessions, pins original evidence and manifest, preregisters host/session-disjoint splits and both variants, and privately runs the pinned ablation on Windows 11. Review per-host supports and disagreements without tuning on TEST.
- [ ] Confirm scientific Precision/Recall/FPR and host/session variability with independently adjudicated multi-host evidence and measure actual event-to-alert/SOC timing. The anonymized summaries are descriptive, not authenticated hosts or cluster-adjusted confidence intervals. Dataset Mode, SOC and Red Team active-network-disabled state remain unchanged.

## Blue Team — Paired Zeek held-out correctness analysis (29/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 full suite and Windows offline Zeek CI for the aggregate paired TEST correctness report, and merge only if green and conflict-free. No synthetic score is a genuine attack-detection result.
- [ ] On student Windows 11/VMware, preserve original authorized PCAP/Zeek/annotation hashes and physical Host-only isolation evidence, preregister the same fixed variants/splits, and run the private port-ablation report without selecting a winner on TEST.
- [ ] Obtain independently adjudicated host/session-disjoint replicated captures and report class supports, uncertainty and limitations; paired flow counts are descriptive and not an independence-valid significance test. Measure event-to-alert/SOC delay separately; active Red Team remains disabled.

- [ ] PR #188 reconciled with #187/#189 on merged-base tree; verify new final-head Ubuntu and Windows CI before merging. Keep report v2 host summaries and add paired TEST counts without replacing earlier research results.


## Blue Team — paired Zeek correctness merged and verified (#188, 29/10/2026)

- [x] Reconciled PR #188 with merged host diagnostics #187/#189, preserved v2 report and existing tests, and squash-merged as `f9ef8ef511e60a263ef6434dbd2a9fcc7d27e43d` after [Ubuntu CI #40834231739](https://github.com/tbao4151/DA_CNTT/actions/runs/40834231739) (**876 passed, 2 skipped**) and [Windows CI #40834231718](https://github.com/tbao4151/DA_CNTT/actions/runs/40834231718) (**135 Zeek + 46 Red Team passed**) succeeded. These are GitHub-runner software tests, not student laptop or VMware acceptance.
- [ ] Student independently verifies VMware Host-only isolation, records actual Zeek PCAP/conn.log/annotation hashes and clocks, preregisters fixed variants and host/session-disjoint TRAIN/VALIDATION/TEST splits, then runs private `--strict-input-gates --port-ablation-output` on Windows 11. Do not commit sensitive captures or tune on held-out TEST.
- [ ] Collect independently adjudicated multi-session/multi-host test data, report per-class Precision/Recall/FPR and dependence-aware uncertainty, and measure actual event-to-AI-alert-to-SOC-case delay. Paired correctness counts and anonymous host diagnostics remain descriptive; no real-world detection or operational SOC performance is established by this PR.


## Blue Team — anonymous paired host-group correctness (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 full suite and Windows offline Zeek CI for the optional anonymous per-host paired TEST correctness breakdown. Merge only after green CI and no conflict; retain prior paired totals and host variability.
- [ ] On Windows 11, independently preserve authorized Host-only PCAP, Zeek conn.log, annotation hashes, isolation and clock evidence; preregister the same fixed full/portless variants and host/session-disjoint splits before private evaluation. Per-host cells are suppressed if **any** TEST group has fewer than 30 flows; the threshold is not a power or independence guarantee.
- [ ] Collect independently adjudicated multi-host/session test captures and actual event-to-AI-alert-to-SOC-case timing. Do not treat operator-declared group summaries as statistical significance, physical isolation proof, or a basis for TEST-driven model selection. Dataset Mode, SOC and active Red Team execution remain unchanged.


## Blue Team — anonymous paired host correctness verified (#191, 29/10/2026)

- [x] [PR #191](https://github.com/tbao4151/DA_CNTT/pull/191) merged conflict-free as `7eca980b461024a18b4e105d4e53e81684987b61` after [Ubuntu PR CI #40837169345](https://github.com/tbao4151/DA_CNTT/actions/runs/40837169345) (**886 passed, 2 skipped**) and [Windows PR CI #40837169308](https://github.com/tbao4151/DA_CNTT/actions/runs/40837169308) (**145 Zeek + 46 Red Team passed**) succeeded. Supersedes the feature-merge pending item above. These are synthetic software tests, not student laptop/VMware acceptance.
- [ ] Student preserves original authorized Host-only PCAP/Zeek/annotation hashes, isolation and clock evidence privately, preregisters host/session-disjoint splits and fixed variants, then runs the optional private report on Windows 11. If any TEST host group has fewer than 30 flows, all paired per-host cells are intentionally suppressed; do not disable this guard to expose small groups.
- [ ] Validate independent labels, actual multi-host/session held-out performance and event-to-AI-alert-to-SOC-case latency before scientific claims. Paired correctness remains descriptive, not a cluster-adjusted significance test, causal port-effect estimate or deployed-model selection rule.


## Blue Team — cross-section host privacy correction (29/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 and Windows offline Zeek CI for opt-in all-group suppression in both port-ablation variants and both VALIDATION/TEST host summaries; merge only if green and conflict-free.
- [ ] Student validates the private v2 port-ablation JSON on Windows 11 with authorized Host-only evidence. When any group has fewer than 30 flows, `groups` must be empty and `rate_ranges` null for that split; paired TEST cells must also be suppressed. Overall metrics remain visible. This is not differential privacy or a sample-size guarantee.
- [ ] Collect independent multi-host/session labels, capture and clock provenance, and actual event-to-alert-to-SOC-case timing. Keep Dataset Mode/UNSW baseline unchanged and active Red Team disabled until isolation is independently verified.


## Blue Team — cross-section host privacy verified (#193, 29/10/2026)

- [x] [PR #193](https://github.com/tbao4151/DA_CNTT/pull/193) merged as `50538aa373ad9c3b1d029b68da9c274a73edd20c` after final-head [Ubuntu CI #40840318093](https://github.com/tbao4151/DA_CNTT/actions/runs/40840318093) (890 passed, 2 skipped) and [Windows CI #40840318148](https://github.com/tbao4151/DA_CNTT/actions/runs/40840318148) (146 Zeek + 46 Red Team passed). Supersedes the pending merge check above. Post-merge main CI was queued at documentation authoring.
- [ ] Student tests private port-ablation JSON and redaction behavior on Windows 11 with genuine authorized VMware Host-only Zeek/PCAP, independently pinned labels and host/session split plan. Verify the local capture/clock/isolation evidence separately; GitHub CI is not laptop acceptance.
- [ ] Evaluate actual multi-host/session detection with independent adjudication and record event-to-AI-alert-to-SOC-case timestamps. No model deployment, automatic attack alert or causal port effect is established by this privacy correction.


## Blue Team — baseline/ablation small-host privacy consistency (29/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 and Windows offline Zeek CI for the baseline aggregate report v5 all-host suppression; merge only when checks pass and the PR is conflict-free. The previous baseline v4 could reveal tiny-host confusion cells even when the paired ablation report suppressed them.
- [ ] On the student Windows 11/VMware Host-only lab, collect independently authorized PCAP/Zeek logs and adjudicated labels; pin original hashes and session/host splits, keep all reports and private per-flow traces outside public Git, and verify both report types redact groups below 30 flows. Do not treat the 30-flow threshold as statistical sufficiency or the suppression as differential privacy.
- [ ] Independently measure held-out detection accuracy and actual event-to-alert/SOC latency before reporting scientific performance. Dataset Mode UNSW benchmark and active Red Team traffic remain unchanged.

- [ ] Resolve initial Ubuntu CI failure in private trace review by validating the new baseline report v5 alongside legacy v4, then rerun **both** final-head Ubuntu and Windows CI; do not merge using earlier passing Windows/Zeek runs. Preserve private trace v1 integrity checks and backward compatibility.


## Blue Team — baseline Zeek host privacy v5 merge verification (29/10/2026)

- [x] [PR #195](https://github.com/tbao4151/DA_CNTT/pull/195) merged as `f21dcb95ad3610c8cd0fafad7ce1e2a583ae269c` after final-head [Ubuntu CI #40844461501](https://github.com/tbao4151/DA_CNTT/actions/runs/40844461501) (**892 passed, 2 skipped, 2 warnings**), [Windows CI #40844461634](https://github.com/tbao4151/DA_CNTT/actions/runs/40844461634) (**146 Zeek + 46 Red Team passed**) and [real Zeek synthetic smoke #40844461607](https://github.com/tbao4151/DA_CNTT/actions/runs/40844461607) (**success**). This supersedes the pending merge/compatibility items above; the initial v4-only private reviewer regression was fixed before final CI.
- [ ] Verify post-merge `main` CI for PR #195 independently. Run genuine Windows 11/VMware Host-only acceptance with pinned PCAP/Zeek hashes, independent labels, split plan and offline reports. No local capture, independent attack-detection score, causal ablation conclusion or event-to-SOC latency has been demonstrated by these CI checks.

## Blue Team — Zeek v1 numeric feature type parity (29/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 and Windows offline Zeek CI for strict model-input port/count typing; merge only if checks pass and PR is conflict-free. Both baseline training and data-only model scoring must reject forged fractional/absent ports and fractional packet/byte counts while retaining missing optional fields.
- [ ] Run genuine Windows 11/VMware Host-only Zeek capture with independently pinned log/label evidence and test the new model-input gate; CI synthetic tests are not physical isolation, independent labels, live alerts or measured event-to-SOC latency. Keep Dataset Mode official UNSW-NB15 benchmark unchanged.

## Blue Team — Zeek numeric feature type gate verified (#197, 29/10/2026)

- [x] [PR #197](https://github.com/tbao4151/DA_CNTT/pull/197) merged as `9a878faa900b1fe4257a291249fcbfc6ed56676d` after final-head [Ubuntu CI #40847919697](https://github.com/tbao4151/DA_CNTT/actions/runs/40847919697) (906 passed, 2 skipped) and [Windows CI #40847919907](https://github.com/tbao4151/DA_CNTT/actions/runs/40847919907) (146 Zeek + 46 Red Team passed), plus [real Zeek synthetic smoke #40847919837](https://github.com/tbao4151/DA_CNTT/actions/runs/40847919837) (success). Supersedes the pending feature-merge check above; post-merge main CI remains separate.
- [ ] Verify the unchanged model-input v1 contract on genuine student Windows 11/VMware Host-only capture and retain independent original PCAP/Zeek hashes, authorized isolation evidence, labels and split plan. No CI metric is live attack detection or event-to-SOC latency.


## Blue Team — shared Zeek UID identity fail-closed gate (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9, Windows offline Zeek and real-Zeek synthetic CI for shared-parser duplicate UID rejection; merge only if green and conflict-free. Manual offline SOC case creation must reject ambiguous UIDs before creating a database, while distinct UIDs for separate flows remain valid.
- [ ] On student Windows 11/VMware Host-only, validate original authorized Zeek/PCAP evidence and independent SHA-256, actual network isolation, annotations and host/session partitions. Test duplicate UID refusal without editing the original capture; keep private evidence outside Git.
- [ ] Measure genuine labeled held-out Precision/Recall/FPR and event-to-AI-alert-to-SOC-case latency only after approved isolated captures and independent adjudication. A parser integrity check does not establish attack detection, authorization or real capture authenticity.


## Blue Team — shared parser Zeek UID gate verified (#199, 29/10/2026)

- [x] [PR #199](https://github.com/tbao4151/DA_CNTT/pull/199) merged after final-head [Ubuntu CI #40852673104](https://github.com/tbao4151/DA_CNTT/actions/runs/40852673104) (**908 passed, 2 skipped**), [Windows CI #40852673193](https://github.com/tbao4151/DA_CNTT/actions/runs/40852673193) (**147 Zeek + 46 Red Team passed**) and [real Zeek offline synthetic smoke #40852673066](https://github.com/tbao4151/DA_CNTT/actions/runs/40852673066) (**success**). Earlier diagnostic/fixture test failures were fixed and rerun; the pending feature-merge check above is superseded.
- [ ] Student independently tests actual Windows 11/VMware Host-only capture and pinned original Zeek/PCAP evidence; verifies UID uniqueness, labels, host/session split, physical isolation and timestamps without editing original files. GitHub synthetic CI is not a laptop acceptance test.
- [ ] Validate held-out attack-detection Precision/Recall/FPR and real event-to-AI-alert-to-SOC-case latency only with independently adjudicated authorized lab captures. Dataset Mode and active Red Team remain unchanged.


## Blue Team — shared Zeek #types header ordering (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 and Windows offline Zeek CI; merge only when green and conflict-free. The common parser must reject duplicate/late `#types` headers without requiring the optional strict declared-type gate or breaking legacy minimal fixtures.
- [ ] Student validates original authorized Windows 11/VMware Host-only Zeek `conn.log`, pinned hashes, version, actual isolation and independent labels; confirm genuine logs with one well-positioned `#types` parse, and test malformed copies without editing originals.
- [ ] Obtain independently adjudicated held-out detection evidence and actual event-to-AI-alert-to-SOC-case timing. Parser header checks do not establish these outcomes; Dataset Mode and active Red Team remain unchanged.


## Blue Team — shared Zeek #types ordering verified (#201, 29/10/2026)

- [x] [PR #201](https://github.com/tbao4151/DA_CNTT/pull/201) merged conflict-free after final-head [Ubuntu CI #40855635345](https://github.com/tbao4151/DA_CNTT/actions/runs/40855635345) (**909 passed, 2 skipped**), [Windows CI #40855635327](https://github.com/tbao4151/DA_CNTT/actions/runs/40855635327) (**147 Zeek + 46 Red Team passed**) and [real Zeek synthetic CI #40855635368](https://github.com/tbao4151/DA_CNTT/actions/runs/40855635368) (**success**). Earlier test-only source-hash assertion failure was fixed before final verification.
- [ ] Student checks actual Windows 11/VMware Host-only Zeek original PCAP/`conn.log` and separately pinned SHA-256, authorization, physical network isolation and independent labels. CI and parser type-header checks are not genuine attack-detection or event-to-SOC timing evidence.
- [ ] Verify post-merge `main` CI independently, then prioritize independent held-out capture evaluation and measured event-to-AI-alert-to-SOC-case timing; do not claim operational alerts or Red Team active traffic.

## Blue Team — terminal Zeek #close source-boundary integrity (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9, Windows offline Zeek and real-Zeek synthetic smoke CI; merge only when green and conflict-free. The shared parser must reject any content after `#close`, premature/duplicate `#close` and repeated `#separator` without requiring `#close` in legacy minimal logs.
- [ ] Student checks the unchanged original authorized Windows 11/VMware Host-only `conn.log` and independently pinned SHA-256, then tests malformed copies and manual SOC refusal. Record isolation, Zeek version, original PCAP, independent annotations and session/host split evidence outside Git.
- [ ] Validate held-out attack-detection metrics and actual event-to-AI-alert-to-SOC-case latency on independently adjudicated captures. Header/terminal integrity is not evidence of real-world detection, capture authenticity or a network kill switch.

## Blue Team — terminal Zeek #close integrity verified (#203, 29/10/2026)

- [x] [PR #203](https://github.com/tbao4151/DA_CNTT/pull/203) merged as `6d48deaedb579265f747d97ce1f591e3cf9c072a` after final-head [Ubuntu CI #40859227449](https://github.com/tbao4151/DA_CNTT/actions/runs/40859227449) (**911 passed, 2 skipped**), [Windows CI #40859227384](https://github.com/tbao4151/DA_CNTT/actions/runs/40859227384) (**148 Zeek + 46 Red Team passed**) and [real Zeek synthetic smoke #40859227477](https://github.com/tbao4151/DA_CNTT/actions/runs/40859227477) (**success**). Supersedes the pending merge check above; GitHub runners are not student hardware.
- [ ] Student tests the original authorized VMware Host-only Zeek log privately, retains independently pinned PCAP/log SHA-256 and version/network/clock evidence, and checks malformed copies without altering originals. Verify local SOC refusal and preserve separate independent labels/holdout.
- [ ] Collect independently adjudicated multi-host/session captures to measure held-out Precision/Recall/FPR and real event-to-AI-alert-to-SOC-case timing. No operational alert, real attack-detection score, capture authenticity or active Red Team traffic is established by this parser gate.


## Blue Team — Zeek ASCII missing/empty sentinel and conn-path semantics (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9, Windows offline Zeek and real-Zeek synthetic smoke CI, and merge only when conflict-free. Optional `#unset_field`, `#empty_field` and `#path` metadata must be canonical, unique and before flow records; explicitly declared empty service must remain distinct from missing service.
- [ ] Student runs the parser and manual SOC refusal regressions on Windows 11 Python 3.12.9, then checks unchanged original authorized VMware Host-only PCAP/`conn.log` with independent SHA-256, Zeek version, actual network isolation, and labeling evidence. Preserve private data outside Git.
- [ ] Collect independently adjudicated multi-host/session captures and actual event-to-AI-alert-to-SOC-case timing. Parser metadata integrity does not establish real detection, capture authenticity, physical isolation or an active Red Team kill switch.


## Blue Team — Zeek ASCII sentinel gate verified (#205, 29/10/2026)

- [x] [PR #205](https://github.com/tbao4151/DA_CNTT/pull/205) merged as `15dc10bb9c544e6b79b0c10df660591d6df7c6e0` after final-head [Ubuntu CI #40864002492](https://github.com/tbao4151/DA_CNTT/actions/runs/40864002492) (**925 passed, 2 skipped**), [Windows CI #40864002574](https://github.com/tbao4151/DA_CNTT/actions/runs/40864002574) (**149 Zeek + 46 Red Team passed**) and [real Zeek synthetic CI #40864002469](https://github.com/tbao4151/DA_CNTT/actions/runs/40864002469) (**success**). Supersedes the pending feature-merge check above; post-merge main CI is separate.
- [ ] Student verifies unchanged original authorized VMware Host-only PCAP/Zeek, independent SHA-256, Zeek version, actual isolation, labels and held-out splits on Windows 11 Python 3.12.9. Check malformed copies, not original evidence. CI synthetic regression is not student hardware acceptance.
- [ ] Evaluate independent multi-host/session held-out attack detection and actual event-to-AI-alert-to-SOC-case delay. Metadata consistency does not establish capture authenticity, model accuracy, physical isolation or operational Red Team controls.


## Blue Team — optional Zeek #open/#set_separator metadata integrity (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9, Windows offline Zeek and real-Zeek synthetic smoke CI; merge only after green checks and a conflict-free PR. Reject malformed/duplicate/late #open or #set_separator before manual SOC writes; preserve minimal legacy fixtures.
- [ ] Student tests unchanged original authorized Windows 11/VMware Host-only PCAP/Zeek with separately recorded SHA-256, Zeek version, network/clock isolation and independent annotations; use malformed copies for negative tests.
- [ ] Collect genuine multi-host/session labeled holdout and measured event-to-AI-alert-to-SOC-case timing. Parser metadata validation is not proof of source authenticity, operational detection or physical isolation.


## Blue Team — Zeek #open/#set_separator metadata gate verified (#207, 29/10/2026)

- [x] PR #207 (https://github.com/tbao4151/DA_CNTT/pull/207) merged as c3839d0418c96b25e1dbf0242bc8aee1b18fc784 after final-head Ubuntu CI #40866881807 (936 passed, 2 skipped), Windows CI #40866881735 (151 Zeek + 46 Red Team passed) and real-Zeek synthetic CI #40866881683 (success). Supersedes the pending feature-merge item above; post-merge main CI remains a separate check.
- [ ] Student verifies the original authorized Windows 11/VMware Host-only PCAP/Zeek privately with pinned SHA-256, Zeek version, actual isolation/clock evidence and independent labels. Do not modify source captures for tests.
- [ ] Obtain genuine held-out host/session-disjoint detection evidence and measured event-to-AI-alert-to-SOC-case latency. Software metadata consistency does not establish operational detection, authenticated provenance or an active Red Team kill switch.


## Blue Team — NEW-log scoring with pinned declared partition screening (29/10/2026)

- [ ] Confirm final feature-head Ubuntu Python 3.12.9 and Windows offline Zeek
  CI for optional pinned TRAIN/VALIDATION/TEST and flow identity screening
  performed **at the scoring boundary**; merge only after checks pass and
  conflicts are absent. Preserve the existing prediction JSON schema and
  legacy unpinned CLI behavior.
- [ ] On student Windows 11, preserve original authorized VMware Host-only
  PCAP/Zeek and independently pinned model, manifest, annotation and capture
  hashes; run the strict scoring mode with actual private CIDR, inspect
  report and verify that a copy of reserved TEST is refused. Do not alter
  original evidence or commit private inputs.
- [ ] Obtain genuine independently adjudicated held-out attack metrics and
  measured event-to-AI-alert-to-SOC-case latency. Declared non-reuse checks
  cannot establish physical isolation, complete history, ground-truth
  authenticity or operational attack detection.


## Blue Team — pinned NEW-log scoring gate verified (#209, 29/10/2026)

- [x] PR #209 merged at `e8ee5f836c586875ed1a8f6e12e7a7b89ecb4577`
  after final-head Ubuntu #40871455246 (945 passed, 2 skipped),
  Windows #40871455253 (160 Zeek + 46 Red Team passed) and
  real-Zeek synthetic smoke #40871455362 (success). This supersedes
  the pending feature merge gate above. Post-merge main CI is separate.
- [ ] Student verifies pinned strict scoring on independently recorded
  Windows 11/VMware Host-only inputs, tests reserved TEST and normalized
  identity reuse refusal on copies, and records physical isolation and
  labels separately. Synthetic CI is not hardware evidence.
- [ ] Demonstrate independently adjudicated held-out attack detection and
  actual event-to-alert-to-SOC-case timing; the new gate does not provide
  these measurements or operational alerts.

## Blue Team — NEW-log SOC pinned annotation boundary (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9, Windows offline Zeek and applicable synthetic CI; merge only when all required checks are green and no conflict exists. Require `labels_sha256` for every declared annotation in CLI/UI SOC triage, matching the already strict scoring path.
- [ ] Student independently pins annotation, manifest, model, original Zeek and PCAP hashes; tests modified-label and missing-label-pin refusals on Windows 11 with copies, then preserves genuine authorized Host-only evidence outside Git.
- [ ] Collect independently adjudicated held-out labels and measured event-to-AI-alert-to-SOC-case timing. Digest checks do not authenticate ground truth, physical isolation or operational detection.

## Blue Team — NEW-log SOC annotation gate verified (#211, 29/10/2026)

- [x] PR #211 merged as `581fa73d162ab9200cff44a08a441bc34c2af597` after final-head Ubuntu #40875566011 (**949 passed, 2 skipped**), Windows #40875566280 (**160 Zeek + 46 Red Team passed**) and real-Zeek synthetic smoke #40875566154 (**success**). Supersedes the pending feature CI/merge item above.
- [ ] Independently verify post-merge main CI and student Windows 11/VMware Host-only capture with separately pinned annotation/manifest/model/Zeek/PCAP evidence, actual isolation and ground-truth adjudication.
- [ ] Measure held-out attack Precision/Recall/FPR and actual event-to-AI-alert-to-SOC-case timing; annotation hashes only establish consistency with operator-supplied bytes.

## Blue Team — strict per-annotation pins for NEW-log runtime benchmark (29/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 and Windows offline Zeek CI, check conflicts and merge only if green. Runtime timing must refuse a missing `labels_sha256` or changed annotation, even if the manifest/model hashes are otherwise consistent; no timing JSON on failure.
- [ ] Student reruns the pinned read-only runtime benchmark with actual independently preserved Windows 11/VMware Host-only model, manifest, labels and new capture, records original hashes and isolation evidence outside Git.
- [ ] Obtain independently adjudicated held-out attack metrics and actual event-to-AI-alert-to-SOC-case timing. Offline batch timing excludes capture, I/O, model load, partition preflight and SOC work, and must not be reported as detection latency.

## Blue Team — runtime annotation-pin parity verified (#213, 29/10/2026)

- [x] [PR #213](https://github.com/tbao4151/DA_CNTT/pull/213) merged at `8a1c6eeb16ff3e111b83178a90d3cf4e1da57619` after final-head Ubuntu #40879238610 (**951 passed, 2 skipped**), Windows #40879238646 (**175 Zeek + 46 Red Team passed**) and Ubuntu push #40879213816 (**success**). This supersedes the pending feature merge gate above; post-merge main CI is separate.
- [ ] Student independently measures actual Windows 11/VMware Host-only offline batch runtime with original pinned annotations, manifest, model and Zeek/PCAP, records CPU/RAM/Zeek version, isolation and clock evidence outside Git.
- [ ] Obtain independently adjudicated held-out detection metrics and actual event-to-alert-to-SOC-case latency. Software runtime and synthetic CI must not be interpreted as operational detection timing.


## Blue Team — read-only NEW-log SOC evidence-link check (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 CI and Windows offline Zeek regression (where configured); merge only after checks pass and no conflicts exist. Verify original Zeek flow, research prediction and first SOC audit note agree without writing SQLite.
- [ ] Integrate the read-only checker into the existing SOC UI/CLI only after confirming how to pin private manifest and PCAP evidence at that boundary; do not present a matching SQLite note as independent forensic authentication.
- [ ] Student must run on actual authorized Windows 11/VMware Host-only captures with original PCAP/Zeek, separately pinned model/report/manifest/annotation bytes, real isolation evidence and independently adjudicated labels. Measure held-out detection and actual event-to-alert-to-SOC-case timing separately; synthetic CI is not that experiment.


## Blue Team — verified NEW-log SOC evidence-link regression (#215, 29/10/2026)

- [x] PR #215 merged at `75b2861fb52fbdec33ba203ad462b2f636e397a7` after final-head Ubuntu CI #40884444439 (**957 passed, 2 skipped**) and Windows offline Zeek CI #40884444416 (**181 Zeek + 46 Red Team passed**). Supersedes the pending CI/merge item above; post-merge main CI is independent.
- [ ] Expose this read-only case-link check in the SOC workflow only with private pinned manifest/PCAP evidence and explicit "research-only" labeling. Do not convert it into an automatic operational attack verdict.
- [ ] Student validates actual authorized Windows 11/VMware Host-only captures, independent annotations, SHA-256 pins, host isolation and genuine held-out Precision/Recall/FPR; separately instrument real event-to-alert-to-SOC-case timing. CI synthetic checks cannot substitute for those measurements.


## Blue Team — strict pinned CLI for existing SOC case evidence link (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 and Windows offline Zeek CI, no competing PR or conflict; merge only after successful checks. The read-only CLI must refuse altered case snapshot/audit, model/log/report/manifest/annotation pins and missing SQLite without creating or changing cases.
- [ ] Student runs the strict CLI on a real, authorized Windows 11/VMware Host-only capture with independently preserved model, manifest, annotation, Zeek/PCAP hashes, actual network isolation evidence and separately adjudicated labels; test refusal on copies, never edit originals.
- [ ] Measure genuine held-out attack Precision/Recall/FPR and event-to-AI-alert-to-SOC-case timing separately. A consistent SQLite note and declared non-reuse screen are not independent forensic authentication or operational detection.


## Blue Team — strict SOC case-link CLI verified (#217, 29/10/2026)

- [x] [PR #217](https://github.com/tbao4151/DA_CNTT/pull/217) merged as `9372a33e90298490a1fd67c1dd93157fc6e7b112` after final-head [Ubuntu CI #40889546406](https://github.com/tbao4151/DA_CNTT/actions/runs/40889546406) (**968 passed, 2 skipped**) and [Windows CI #40889546209](https://github.com/tbao4151/DA_CNTT/actions/runs/40889546209) (**192 Zeek + 46 Red Team passed**). This supersedes the pending feature merge gate above. Post-merge main CI is separate.
- [ ] Student validates the read-only CLI on independently pinned authorized Windows 11/VMware Host-only PCAP/Zeek, manifest/annotations/model/report, original SOC case and isolation evidence. Record screenshots and original SHA-256 privately; verify no DB changes and refuse tampered copies.
- [ ] Collect independently adjudicated held-out data and measure actual event-to-AI-alert-to-SOC-case delay. A consistent stored Unclassified research case does not constitute a confirmed attack or operational alert.

## Blue Team — canonical SOC creation-audit gate (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 and Windows offline Zeek CI, confirm no competing PR/conflict, then merge only after green checks. The pinned case-link CLI must reject injected attack claims, noncanonical notes and stored manifest/PCAP digests inconsistent with verified inputs.
- [ ] Student runs read-only verification on authorized Windows 11/VMware Host-only original evidence, tests malformed copies without changing original SQLite/PCAP/Zeek, and records independent SHA-256 and isolation evidence outside Git.
- [ ] Obtain independently adjudicated labeled captures and real event-to-AI-alert-to-SOC-case timing. Editable SQLite note consistency is neither forensic authentication nor live detection evidence.

## Blue Team — canonical SOC audit gate verified (#219, 29/10/2026)

- [x] PR #219 merged as ab849977ce390ed0853a0eb809ed603e3314d048 after final-head Ubuntu #40894021102 (974 passed, 2 skipped) and Windows #40894021188 (198 Zeek + 46 Red Team passed); no conflicts. This supersedes the feature CI/merge item above.
- [ ] Student validates original authorized Windows 11/VMware Host-only evidence, separate SHA-256 pins and the read-only CLI; preserve original SQLite/PCAP/Zeek, and test refusal only on copies.
- [ ] Independently adjudicate labels, collect held-out captures and measure event-to-AI-alert-to-SOC-case latency. Synthetic CI and mutable SQLite cannot establish operational detection or forensic authenticity.

## Blue Team — offline existing-case verification stage timing (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 full-suite and Windows offline Zeek CI; merge only if successful, no conflicting open PRs, and base/head remain compatible. The optional `--timing-json` output must be aggregate-only, read-only and absent on failed evidence checks.
- [ ] Student runs pinned read-only SOC case verification on original, authorized Windows 11/VMware Host-only evidence; record per-stage and total processing milliseconds with hardware, Zeek version, source size, independently preserved SHA-256 and network isolation evidence outside Git. Repeat runs under controlled load.
- [ ] Independently instrument and validate actual **network event → log available → AI decision → alert delivered → SOC case created** timestamps. The existing-case verifier's processing time, which recomputes evidence, must not be relabeled as detection latency or SOC case creation time.
- [ ] Obtain independently adjudicated held-out labels and report Precision, Recall, FPR and false negatives; keep UNSW-NB15 historical metrics separate from lab-capture findings.

## Blue Team — offline SOC processing timing CI verified (#221, 29/10/2026)

- [x] PR #221 merged as `dafc089d32e6936670e9fb79553991effe29f049` after final-head [Ubuntu CI #40899359256](https://github.com/tbao4151/DA_CNTT/actions/runs/40899359256) (**976 passed, 2 skipped**) and [Windows CI #40899359119](https://github.com/tbao4151/DA_CNTT/actions/runs/40899359119) (**200 Zeek + 46 Red Team passed**). This supersedes the pending feature merge gate above; post-merge main CI is separate.
- [ ] Student performs private, authorized Windows 11/VMware Host-only capture and independently records SHA-256, hardware/Zeek metadata, network isolation and repeated software verification stage timings. Do not use CI runner timings as student measurements.
- [ ] Add trustworthy instrumented timestamps for genuine event → log availability → AI decision → alert → SOC case creation. This is distinct from read-only existing-case verification overhead and requires independent ground truth/operational evidence.

## Cyber Lab — Windows host-only adapter evidence preflight (29/10/2026)

- [ ] Verify feature-head Ubuntu full-suite and Windows offline workflow (including mocked PowerShell collector), confirm no conflicting PRs and merge only after CI succeeds. This is a host-side configuration preflight, **not** VMware isolation attestation.
- [ ] Student runs the read-only adapter collector and pinned offline checker on their own Windows 11 laptop; stores original snapshot/hash privately. Independently inspects VMware Virtual Network Editor Host-only/NAT/bridging, every guest NIC and guest routes, authorized scope and physical egress before any traffic.
- [ ] Collect original authorized PCAP and Zeek conn.log with independent labels; evaluate held-out Precision/Recall/FPR and genuine event-to-alert-to-SOC-case timing. Neither synthetic CI nor a passing host adapter check proves isolation or attack detection.

## Cyber Lab — Windows host adapter preflight verified (#223, 29/10/2026)

- [x] [PR #223](https://github.com/tbao4151/DA_CNTT/pull/223) merged at `d37075adf856f0e39fafc8b9ad08c2ce714e2383` after final-head Ubuntu #40904586073 (**997 passed, 2 skipped**) and Windows #40904586299 (**200 Zeek + 21 preflight + 46 Red Team tests passed**, mocked PowerShell smoke success). This supersedes the pending CI/merge gate above.
- [ ] Student runs private read-only Windows host adapter collection, independently pins its SHA-256, and validates with the offline checker; physically inspects VMware Host-only mode, disabled NAT/bridging, every guest NIC/route and written test authorization. A passing snapshot check does **not** establish network isolation.
- [ ] Collect authorized real PCAP/Zeek captures and independent labels; report held-out Precision/Recall/FPR and actual event-to-alert-to-SOC-case latency. Synthetic GitHub CI is not student Windows/VMware experimental evidence.


## Cyber Lab — Windows guest NIC/route preflight (29/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 full-suite and Windows offline Zeek CI, including mocked PowerShell guest collector; merge only if green, conflict-free and no competing PR. Local synthetic Python tests: 31 passed, not a VMware test.
- [ ] On the student's owned Windows guest, collect the original private NIC/IPv4/IPv6/default-route/DNS snapshot, independently record SHA-256, run the pinned offline checker and preserve host/guest/VMware screenshots. Confirm no extra guest adapters, NAT/bridging or unintended egress and document authorized scope **manually**; passing software checks do not prove isolation.
- [ ] After independent isolation and permission, capture genuine PCAP/Zeek logs, adjudicate labels and measure held-out detection and event-to-alert-to-SOC latency. Do not relabel CI/synthetic snapshots as real lab evidence.


## Cyber Lab — verified Windows guest preflight merge (#225, 29/10/2026)

- [x] [PR #225](https://github.com/tbao4151/DA_CNTT/pull/225) merged at `0cb865f2b23937d813271fa0e38477bc223be2f9`. Final-head [Ubuntu CI #40909968852](https://github.com/tbao4151/DA_CNTT/actions/runs/40909968852) **1028 passed, 2 skipped**; [Windows CI #40909968472](https://github.com/tbao4151/DA_CNTT/actions/runs/40909968472) **200 Zeek + 21 host + 31 guest + 46 Red Team passed**, mocked host/guest PowerShell smoke passed. Supersedes the pending PR merge gate above. Post-merge main CI #40914048171 was queued when documented.
- [ ] Student runs the pinned offline guest checker on original privately stored Windows 11 guest evidence, preserves independent SHA-256 and manually verifies VMware Virtual Network Editor, host/guest NIC inventory, default routes, absence of unintended egress and approved scope. Synthetic CI does not attest network isolation.
- [ ] Collect independently authorized PCAP and Zeek logs, adjudicate held-out labels and measure genuine event-to-AI-alert-to-SOC-case timing, Precision, Recall and FPR; keep these separate from UNSW-NB15 metrics and CI runtime.


## Cyber Lab — pinned offline host/guest configuration pair (30/10/2026)

- [ ] Confirm final feature-head Ubuntu Python 3.12.9 and Windows offline CI, ensure no competing PR/conflicts, then merge. Synthetic tests are not student VMware acceptance.
- [ ] Student collects original private host and guest snapshots on their own Windows/VMware setup, independently pins both SHA-256 digests, runs `scripts/check_paired_network_preflight.py`, and manually verifies VMware Host-only/NAT/bridging, every NIC/route and written authorization. Software consistency is not physical isolation proof.
- [ ] Obtain independently authorized PCAP/Zeek captures and held-out labels; measure genuine telemetry-to-AI-to-alert-to-SOC-case latency separately from offline verification overhead.


## Cyber Lab — paired Windows host/guest preflight verified (#227, 30/10/2026)

- [x] [PR #227](https://github.com/tbao4151/DA_CNTT/pull/227) merged as `c6170fd05b0f5e8b040aba3118454edf408a217d` after [Ubuntu #40918620002](https://github.com/tbao4151/DA_CNTT/actions/runs/40918620002) (**1045 passed, 2 skipped**) and [Windows #40918620053](https://github.com/tbao4151/DA_CNTT/actions/runs/40918620053) (**17 paired tests and existing Zeek/host/guest/Red Team suites passed**). This supersedes the pending PR gate above. Post-merge main CI is separate.
- [ ] Student collects original private Windows host/guest snapshots with independent SHA-256, runs paired checker, manually verifies VMware Host-only/NAT/bridging, all adapters/routes and authorized scope. Snapshot consistency is not isolation attestation.
- [ ] Obtain authorized PCAP and Zeek conn.log, independently adjudicate held-out labels and measure real AI alert and SOC case creation latency.


## Cyber Lab — host snapshot output privacy (30/10/2026)

- [ ] Verify Windows mocked PowerShell host collector regression and Ubuntu quality gates on the final feature PR head, check conflict-free base and competing PRs, then merge only if CI succeeds. No VMware claim from mocked tests.
- [ ] On Windows 11, store host/guest JSON and independently recorded SHA-256 outside Git; avoid junction/reparse-point paths; manually confirm VMware Host-only mode, NICs/routes and authorization before any permitted traffic.
- [ ] Preserve genuine authorized PCAP/Zeek and independently adjudicated labels to assess held-out Precision/Recall/FPR and event-to-alert-to-SOC timing. Never substitute synthetic CI for student lab evidence.


## Cyber Lab — verified host private output-path guard (#229, 30/10/2026)

- [x] [PR #229](https://github.com/tbao4151/DA_CNTT/pull/229) merged as `f6feebef1278ff1bf587564f8de396ad783cb0f9` after [Ubuntu #40923565551](https://github.com/tbao4151/DA_CNTT/actions/runs/40923565551) (**1045 passed, 2 skipped**) and [Windows #40923565545](https://github.com/tbao4151/DA_CNTT/actions/runs/40923565545) (**mocked host PowerShell privacy regression and other offline suites passed**). This supersedes the pending feature CI/merge gate above; post-merge main CI is separate.
- [ ] Student collects private host/guest snapshots with independent hashes, inspects VMware VMnet/NICs/routes and written authorization; the collector's path guard is not an isolation or junction-security guarantee.
- [ ] Obtain real authorized PCAP/Zeek captures and independently labeled holdout; measure Precision/Recall/FPR and event-to-alert-to-SOC latency without conflating synthetic CI with lab evidence.


## Cyber Lab — atomic private NEW-log research report publication (30/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 and Windows Server 2022 CI, including new atomic filesystem regressions; merge only if all required checks pass and main is conflict-free. Current feature change is **not** student-laptop acceptance.
- [ ] Student tests strict pinned NEW-log scoring in a private local NTFS directory on Windows 11, preserves source/model/manifest/report SHA-256 independently, and confirms existing reports cannot be overwritten. Avoid unsupported network/FAT filesystems; inspect leftover hidden staging files after abrupt interruptions.
- [ ] Collect real authorized VMware Host-only PCAP/Zeek with independent ground truth and host/session-disjoint holdout, then measure true event-to-AI-to-SOC timing. Atomic report publication alone does not establish detection quality, capture authenticity, or network isolation.


## Cyber Lab — verified atomic NEW-log report publication (#231, 30/10/2026)

- [x] [PR #231](https://github.com/tbao4151/DA_CNTT/pull/231) merged as `5160b28cc68af10abf6959fdb0d463f54a9e41ad` after [Ubuntu CI #40929024137](https://github.com/tbao4151/DA_CNTT/actions/runs/40929024137) (**1050 passed, 2 skipped**), [Windows CI #40929023842](https://github.com/tbao4151/DA_CNTT/actions/runs/40929023842) (**205 Zeek, 21 host, 31 guest, 17 paired, 46 Red Team tests passed**) and [real Zeek synthetic smoke #40929023992](https://github.com/tbao4151/DA_CNTT/actions/runs/40929023992) (success). This supersedes the pending CI checkbox above; post-merge main CI is tracked separately.
- [ ] Student validates the pinned new-log CLI on private Windows 11 NTFS and records report SHA-256, with original PCAP/Zeek and model/manifest pins; CI is not a substitute for Windows laptop acceptance.
- [ ] Collect genuine authorized Host-only captures and independent labels, verify held-out Zeek AI Precision/Recall/FPR, and measure event-to-AI-to-SOC timing without confusing offline processing time with live detection latency.


## Cyber Lab — integrated private evidence consistency gate (30/10/2026)

- [ ] Validate final feature-head Ubuntu Python 3.12.9 and Windows offline CI for the integrated five-file SHA-256-pinned host/guest/PCAP/Zeek/import-report consistency gate. Merge only after required checks pass and no conflicting PR remains. Synthetic regression is not real VMware acceptance.
- [ ] Student obtains authorized Host-only configuration and real PCAP, original Zeek `conn.log`, independent SHA-256 pins, host/guest snapshots and offline import report **outside Git**; runs `scripts/verify_lab_evidence_chain.py` on Windows 11 and archives the sanitized result privately.
- [ ] Independently verify VMware VMnet/NIC/routes/egress and approval, adjudicate labels on held-out captures, then measure genuine event-to-AI-alert-to-SOC latency and Precision/Recall/FPR. The new gate verifies only supplied file consistency and does not create alerts or cases.


## Cyber Lab — verified integrated private evidence chain (#233, 30/10/2026)

- [x] [PR #233](https://github.com/tbao4151/DA_CNTT/pull/233) merged as `eca23157d377c738e5473554a3133135d560e88f` after [Ubuntu CI #40933723686](https://github.com/tbao4151/DA_CNTT/actions/runs/40933723686) (**1058 passed, 2 skipped**) and [Windows CI #40933723728](https://github.com/tbao4151/DA_CNTT/actions/runs/40933723728) (**8 integrated synthetic tests and existing offline suites passed**). This supersedes the pending feature gate above; post-merge main CI must be checked independently.
- [ ] Student executes the new pinned read-only gate with genuine authorized Windows 11/VMware Host-only snapshots, PCAP and Zeek import report, retaining original evidence and SHA-256 privately. Synthetic CI cannot verify physical isolation or authenticity.
- [ ] Independently adjudicate labels, establish held-out evaluation and measure real event-to-AI-alert-to-SOC case latency. Do not reinterpret the new gate as AI attack detection.


## Cyber Lab — independently pinned original PCAP/Zeek at integrated evidence gate (30/10/2026)

- [ ] Confirm final-head Ubuntu Python 3.12.9 and Windows offline CI, verify no competing PR/conflicts, and merge only if green. Synthetic tests must not be reported as real VMware acceptance.
- [ ] Student independently records SHA-256 for original private PCAP and Zeek conn.log **before** verification; supply both optional original pins alongside the host/guest/import-report pins and archive the sanitized consistency result outside Git. An absent pair remains explicitly unverified.
- [ ] Manually inspect VMware Host-only isolation and authorized scope; acquire independent ground-truth labels, then evaluate held-out Zeek detection and genuine event-to-alert-to-SOC timing. Independent hash matching is not capture authentication or attack detection.


## Cyber Lab — independent original pins verified (#235, 30/10/2026)

- [x] [PR #235](https://github.com/tbao4151/DA_CNTT/pull/235) merged at `b4dd17b3ca6ff22a66c23a7ee9115042bf8bfb21` after [Ubuntu CI #40937218888](https://github.com/tbao4151/DA_CNTT/actions/runs/40937218888) (**1064 passed, 2 skipped**) and [Windows CI #40937218922](https://github.com/tbao4151/DA_CNTT/actions/runs/40937218922) (**14 integrated synthetic tests and existing offline suites passed**). This supersedes the pending feature merge gate above; post-merge main CI is separate.
- [ ] Student independently pins original authorized PCAP and Zeek conn.log on Windows 11, runs the paired-pin option in the integrated offline checker, and preserves private original evidence; manually validates VMware isolation and approved scope.
- [ ] Establish independently labeled held-out evaluation and instrument genuine event → AI decision → alert → SOC case timing. CI and hash checks alone do not demonstrate real attack detection.


## Cyber Lab — strict original PCAP/Zeek pin requirement (30/10/2026; feature PR pending)

- [ ] Verify and merge the optional strict `--require-independent-original-pins` offline evidence gate after final-head Ubuntu and Windows Python 3.12.9 CI and conflict-free PR review; check post-merge main separately. Existing weaker invocation must remain compatible and clearly flagged.
- [ ] Student records original PCAP and Zeek SHA-256 values separately at acquisition, runs strict preflight with genuine privately archived Host-only evidence, and manually confirms isolation, authorization and independent labels. Software checks do not certify these claims.
- [ ] Preserve untouched UNSW-NB15 benchmark and separately evaluate held-out Zeek AI detection and event-to-alert-to-SOC timing only after real authorized lab data exists.


## Cyber Lab — strict independent original pins verified (#237, 30/10/2026)

- [x] [PR #237](https://github.com/tbao4151/DA_CNTT/pull/237) merged at `a12325107692b027d27262f353dcae654a5fb95b` after final-head [Ubuntu CI #40942952696](https://github.com/tbao4151/DA_CNTT/actions/runs/40942952696) and [Windows CI #40942952660](https://github.com/tbao4151/DA_CNTT/actions/runs/40942952660) succeeded; no conflicts. The older pending entry above is superseded. Post-merge main CI is separately tracked in PROGRESS.
- [ ] Run the strict opt-in CLI on authorized, independently pinned private PCAP/Zeek evidence from the student's Windows 11 VMware Host-only environment. Record physical isolation, consent, scenario, Zeek version and original file hashes separately. A synthetic CI pass does not verify a live capture.
- [ ] Build independently annotated, host/session-disjoint held-out Zeek evaluation and measure genuine telemetry-ready → AI decision → alert → SOC case latency. Preserve Dataset Mode metrics and never infer live detection from checksum validation.


## Cyber Lab — optional pinned guest-flow presence (30/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 quality CI and Windows offline Zeek CI for the optional `--require-guest-endpoint` gate; merge only after both succeed and the PR is conflict-free. The check must be opt-in, require strict original PCAP/Zeek pins and never leak private guest IPs in the JSON report.
- [ ] On the student-owned Windows 11/VMware Host-only environment, retain separate original hashes and NIC/route evidence, and run the optional guest-flow gate only for scenarios where the guest is expected to be a traffic endpoint. A passive sensor observing other VMs must not be failed on this criterion.
- [ ] Independently label authorized host/session-disjoint genuine captures and measure held-out Zeek-specific Precision/Recall/FPR and event-to-alert-to-SOC latency. An IP match cannot prove capture authenticity or isolation; keep Red Team active traffic disabled and UNSW official benchmark unchanged.


## Cyber Lab — guest-flow presence gate merged (#239, 30/10/2026)

- [x] [PR #239](https://github.com/tbao4151/DA_CNTT/pull/239) merged at `b509693db8a1b9b9cc5f127820d9a13546d16206` after final-head [Ubuntu CI #40950725108](https://github.com/tbao4151/DA_CNTT/actions/runs/40950725108) and [Windows CI #40950725439](https://github.com/tbao4151/DA_CNTT/actions/runs/40950725439) succeeded; this supersedes the pending CI/merge item above.
- [ ] Student validates opt-in guest-flow presence only for scenarios in which the declared guest is expected to send/receive traffic, using independently pinned private Host-only evidence and manually checked VMnet/NIC isolation and authorization. A matching IP is not proof of capture authenticity or isolation.
- [ ] Prioritize offline end-to-end Zeek telemetry → Zeek-schema AI inference → research alert → SQLite SOC case, with reproducible stage timings and independent held-out labels. Keep official UNSW-NB15 metrics separate and do not claim live detection from synthetic CI.

## Cyber Lab — verified offline research candidate queue (30/10/2026)

- [ ] Verify feature-head Ubuntu Python 3.12.9 and Windows Server 2022 CI for the new pinned offline research-alert bundle and synthetic tamper/no-overwrite regressions. Merge only if checks pass, no conflicts or competing PR.
- [ ] Student exports a private candidate queue on Windows 11 from genuine authorized Host-only Zeek data with independent model/log/report/manifest/annotation SHA-256 pins; manually triages one original row into exactly one Unclassified SOC case and archives evidence outside Git.
- [ ] Establish independent capture/ground-truth provenance, untouched held-out Zeek evaluation, actual alert-to-SOC timing and operator-approved isolation before claiming attack detection or moving from research candidates to operational alerts.

## Cyber Lab — verified research alert bundle merged (#241, 30/10/2026)

- [x] [PR #241](https://github.com/tbao4151/DA_CNTT/pull/241) merged at `e119441a7d28487b8d1ee87df8594e3332fab722` after [Ubuntu #40963986710](https://github.com/tbao4151/DA_CNTT/actions/runs/40963986710) (**1076 passed, 2 skipped**) and [Windows #40963986611](https://github.com/tbao4151/DA_CNTT/actions/runs/40963986611) (**212 Zeek + existing offline suites passed**). This supersedes the pending CI/merge checkbox above; post-merge main is a separate check.
- [ ] On student Windows 11, export a pinned private research candidate bundle from authorized genuine Host-only Zeek capture; manually triage one original candidate row to one Unclassified SOC case, retain original PCAP/log/model/manifest/annotation hashes and screenshot the actual workflow.
- [ ] Evaluate held-out real-lab detection, operator scope/VMware isolation, false positives and actual event-to-candidate-to-SOC timing. The research queue is not operational alerting and cannot validate labels or physical isolation.


## Cyber Lab — opt-in strict classic-PCAP framing (30/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 quality CI and Windows Server 2022 offline tests, including new synthetic parser/CLI regressions; merge only if green, no conflict and no competing PR. The isolated parser unit test passed 16 cases locally, but this is not full CI or a real capture.
- [ ] Student runs the strict `--require-pcap-framing` read-only verifier on an independently SHA-256-pinned, authorized classic PCAP from their private Windows 11/VMware Host-only lab. Archive original PCAP, Zeek `conn.log`, report, version, isolation/authorization evidence and actual command outputs outside Git.
- [ ] Investigate packet-to-Zeek flow semantic linkage separately; record framing does not establish packet/flow correspondence or genuine AI detection. Independently adjudicate held-out labels and measure event-to-candidate-to-manual-SOC latency without substituting synthetic CI.

## Cyber Lab — classic-PCAP framing gate verified (#243, 30/10/2026)

- [x] [PR #243](https://github.com/tbao4151/DA_CNTT/pull/243) merged at `6c2169cba1a4566394162b04feb7c8306716ca7a` after final-head [Ubuntu CI #40968094559](https://github.com/tbao4151/DA_CNTT/actions/runs/40968094559) and [Windows CI #40968094551](https://github.com/tbao4151/DA_CNTT/actions/runs/40968094551) passed. This supersedes the earlier pending-merge item; post-merge main CI is tracked separately.
- [ ] Student validates an independently pinned private classic PCAP in authorized Windows 11/VMware Host-only, archiving capture/Zeek versions, original checksums, network-isolation proof and command outputs outside Git. Framing does not prove PCAP-to-Zeek flow semantics or capture origin.
- [ ] Next prioritize verified offline research candidate → explicit manual SOC case handoff and stage timing, then genuine independently labeled held-out Zeek evaluation. Do not represent synthetic CI as live detection.


## Cyber Lab — integrated strict classic-PCAP framing (30/10/2026)

- [ ] Validate final feature-head Ubuntu Python 3.12.9 quality CI and Windows Server 2022 offline tests, confirm mergeability and no competing PR before merging. The opt-in integrated gate must refuse missing independent original pins, header-only classic PCAP and truncated packet records while accepting a well-formed synthetic PCAP.
- [ ] Student runs `--require-pcap-framing --require-independent-original-pins` on an authorized, independently SHA-256-pinned private VMware Host-only PCAP/Zeek capture, preserving original evidence and manual isolation proof outside Git.
- [ ] Study real PCAP packet-to-Zeek flow semantic linkage and independent held-out labels; structural record validity is not evidence of genuine AI detection, authorization, live alerts or event-to-SOC latency.


## Cyber Lab — integrated strict PCAP framing merged (#245, 30/10/2026)

- [x] [PR #245](https://github.com/tbao4151/DA_CNTT/pull/245) merged at `84b38fc67c8b90562fe6069a8f4c0dc75024cc45` after final-head [Ubuntu CI #40974345980](https://github.com/tbao4151/DA_CNTT/actions/runs/40974345980) and [Windows CI #40974345837](https://github.com/tbao4151/DA_CNTT/actions/runs/40974345837) succeeded with no conflicts. This supersedes the earlier pending-CI checkbox; post-merge main CI remains a separate verification.
- [ ] On Windows 11, use independently SHA-256-pinned, authorized private Host-only classic PCAP and Zeek conn.log with `--require-pcap-framing --require-independent-original-pins`; retain original files, NIC/VMnet screenshots, permission, version and command outputs outside Git. Synthetic CI cannot prove VMware isolation or capture origin.
- [ ] Next prioritize a verified offline research alert bundle → explicitly analyst-approved Unclassified SOC case handoff with tamper/duplicate checks and reproducible stage timings, followed by independently adjudicated host/session-disjoint real-lab evaluation. Do not substitute packet framing for packet-to-flow linkage or live AI detection.


## Cyber Lab — strict pinned research queue manual SOC handoff (30/10/2026)

- [ ] Validate feature-head Ubuntu Python 3.12.9 quality CI and Windows Server 2022 offline CI, including synthetic selected-index/ref, independent SHA-256, stale/re-pinned queue, duplicate-key and idempotency regressions. Merge only with green checks and no conflicts.
- [ ] Student performs genuine authorized VMware Host-only experiment on Windows 11, independently pins original PCAP/Zeek/model/prediction report/manifest/annotations and private exported research queue, then selects one original queue row through the explicit analyst-confirmed Unclassified SOC workflow. Preserve screenshots, private JSON, independent bundle pin/reference in lab notebook, canonical case audit, checksums, Zeek version and manual isolation/authorization evidence outside Git.
- [ ] Design independent event/candidate/manual-SOC stage timestamps and independently adjudicated host/session-disjoint labels before claiming latency, Recall, Precision or FPR. A pinned research candidate and Unclassified case are **not** operational attack detection.


## Cyber Lab — verified pinned research queue → manual SOC (#247, 30/10/2026)

- [x] [PR #247](https://github.com/tbao4151/DA_CNTT/pull/247) merged as `16dc39d10e3255ca96cb8cd858fdda894d87cf0b` after successful final-head [Ubuntu CI #40981760189](https://github.com/tbao4151/DA_CNTT/actions/runs/40981760189), [Windows offline CI #40981760150](https://github.com/tbao4151/DA_CNTT/actions/runs/40981760150), and [real-Zeek synthetic smoke #40981760203](https://github.com/tbao4151/DA_CNTT/actions/runs/40981760203). Post-merge main CI is separate.
- [ ] On Windows 11, manually validate the strict pinned queue selection, original index/reference, Unclassified SOC case and source+UID idempotency using authorized, independently recorded private VMware Host-only evidence; archive original PCAP/Zeek, independent SHA-256, capture/label provenance, network isolation screenshots and SOC audit outside Git.
- [ ] Next measure separately instrumented offline inference/research queue/manual SOC processing times, and design genuine capture-to-case timing only when synchronized real lab clocks exist. Obtain independently adjudicated host/session-disjoint labels before reporting attack detection Recall/Precision/FPR. Keep Red Team traffic disabled until safety controls and authorization are verified.


## Cyber Lab — measured offline manual SOC handoff software time (30/10/2026)

- [ ] Confirm feature-head Ubuntu Python 3.12.9 and Windows Server 2022 CI passes for the opt-in `--measure-manual-soc-runtime` CLI and synthetic tamper/idempotency tests; merge only after no conflicts and no competing PR. Keep default CLI output, existing SQLite and canonical audit unchanged.
- [ ] Student repeats one first-create and one idempotent-reuse manual SOC handoff on private, authorized Windows 11/VMware Host-only evidence, independently pinning the source/model/manifest/report/research bundle; record hardware, source size, original capture provenance and exact output outside Git. Do not interpret a software processing duration as detection latency.
- [ ] Separately instrument verified queue export and capture/Zeek stages; only report real event-to-candidate-to-manual-SOC timing after synchronized clocks, genuine captures and independent labels. Never substitute synthetic CI, UNSW historical metrics or operator-attested attack truth.


## Cyber Lab — manual SOC software timing merged (#249, 30/10/2026)

- [x] [PR #249](https://github.com/tbao4151/DA_CNTT/pull/249) merged as `3091e376c4cf46076128b25589122dbfa73e956a` after final-head [Ubuntu CI #40987342769](https://github.com/tbao4151/DA_CNTT/actions/runs/40987342769), [Windows CI #40987342697](https://github.com/tbao4151/DA_CNTT/actions/runs/40987342697), and [Real Zeek synthetic smoke #40987342931](https://github.com/tbao4151/DA_CNTT/actions/runs/40987342931) succeeded. This supersedes the earlier pending CI/merge item; post-merge main CI is a separate verification.
- [ ] Student executes first-create and idempotent-reuse handoffs with independently pinned, authorized Windows 11/VMware Host-only evidence and records environment, duration, output, evidence checksums and SOC audit privately. Timing excludes collection, Zeek processing and analyst wait; never report it as detection latency.
- [ ] Separately instrument offline Zeek model inference and research queue export with clearly bounded clocks; design real capture-to-case timing only after independent labels, capture provenance and synchronized lab clocks are available.


## Cyber Lab — opt-in verified research queue export software timing (30/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 and Windows Server 2022 CI for `--measure-research-export-runtime`, including synthetic no-timing-on-failure and deterministic JSON regressions; merge only when green and conflict-free with no competing PR.
- [ ] On student Windows 11, run timed and untimed exports of independently pinned, authorized private Host-only Zeek evidence; archive exact commands, source sizes, output hashes, machine configuration and stage durations outside Git. Do not report software duration as detection latency.
- [ ] Separately time capture/Zeek processing, inference, queue export and manual SOC handoff using comparable, explicitly bounded clocks; obtain independently labeled host/session-disjoint held-out captures before reporting real Precision/Recall/FPR or end-to-end event-to-case latency. Preserve official UNSW-NB15 benchmark and keep active Red Team disabled pending approved isolation.


## Cyber Lab — verified research queue export software timing (#251, 30/10/2026)

- [x] [PR #251](https://github.com/tbao4151/DA_CNTT/pull/251) merged as `507ad9038db73b9ea5dd67c290a9f5cd907f077f` after final-head [Ubuntu CI #40993420683](https://github.com/tbao4151/DA_CNTT/actions/runs/40993420683) and [Windows CI #40993420643](https://github.com/tbao4151/DA_CNTT/actions/runs/40993420643) succeeded. This supersedes the earlier pending verification/merge item; post-merge main CI remains a separate check.
- [ ] Student validates timed versus untimed private research queue export on authorized Windows 11/VMware Host-only evidence, archives original SHA-256, output hashes, hardware, versions, commands and stdout outside Git. Do not claim event-to-alert latency from this software-only clock.
- [ ] Instrument offline inference separately; only after genuine captures, independent host/session-disjoint labels, synchronized clocks and preregistered held-out evaluation should the team measure end-to-end detection/case latency and report Precision/Recall/FPR. Preserve UNSW benchmark and leave active Red Team disabled until lab isolation and approval are verified.


## Cyber Lab — opt-in NEW-log score-to-publication software timing (30/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 and Windows Server 2022 CI for `--measure-inference-publication-runtime`, including byte-identical report JSON, wrong-pin refusal and no timing on failed/no-overwrite publication. Merge only when green, conflict-free and without competing PRs.
- [ ] On student Windows 11, run timed and untimed pinned offline NEW-log scoring against authorized, independently recorded private VMware Host-only evidence, using separate new output filenames. Archive original hashes, report hashes, source size, hardware, exact commands and stdout outside Git; compare repeated runs only with explicit measurement boundaries.
- [ ] Treat score-to-publication, research-queue export and manual SOC handoff as **separate software durations**; they omit capture, Zeek processing, analyst wait and clock synchronization. Do not sum them into event-to-case latency. Obtain independently adjudicated host/session-disjoint held-out labels and genuine capture provenance before reporting real Precision/Recall/FPR. Keep active Red Team disabled and preserve official UNSW-NB15 benchmark.


## Cyber Lab — verified NEW-log score-to-publication timing (#253, 30/10/2026)

- [x] [PR #253](https://github.com/tbao4151/DA_CNTT/pull/253) merged as `33c5d843b25074de644c34a7ce98f4ce47ce6712` after final-head [Ubuntu CI #40998311764](https://github.com/tbao4151/DA_CNTT/actions/runs/40998311764), [Windows offline CI #40998311775](https://github.com/tbao4151/DA_CNTT/actions/runs/40998311775) and [Real Zeek synthetic smoke #40998311783](https://github.com/tbao4151/DA_CNTT/actions/runs/40998311783) all succeeded. This supersedes the earlier pending feature-head CI/merge checklist; post-merge main CI must be checked separately.
- [ ] Student executes pinned timed/untimed NEW-log scoring with different output filenames on Windows 11 using independently preserved, authorized VMware Host-only evidence. Preserve command, input/output SHA-256, source size, hardware, Python/Zeek versions and stdout privately; verify byte-identical JSON without committing sensitive captures.
- [ ] Design a separately evidenced experiment for capture → Zeek → scoring → research queue → analyst-approved SOC handoff, recording clock domains and human wait separately. Obtain genuine captures, independent host/session-disjoint labels and documented isolation before reporting Precision/Recall/FPR or detection/event-to-case latency. Do not sum disjoint software timers as end-to-end latency. Keep Red Team disabled until authorized isolation is established and preserve UNSW-NB15 benchmark.


## Cyber Lab — offline PCAP/Zeek tuple-presence gate (30/10/2026)

- [ ] Confirm final-head Ubuntu quality and Windows Server 2022 Python 3.12.9 CI for `tests/test_pcap_zeek_tuple.py` and existing regression suites; inspect failures and mergeability and avoid competing PRs before merging.
- [ ] Student executes the read-only, independently SHA-256-pinned `scripts/verify_pcap_zeek_tuple.py` against a genuine authorized private classic Ethernet IPv4 TCP/UDP Host-only capture and corresponding Zeek `conn.log` on Windows 11; archive source bytes/hashes, Zeek version, Host-only isolation screenshots, operator authorization, exact commands, exit code and output outside Git.
- [ ] Evaluate unsupported formats separately (VLAN, IPv6, fragmentation, other protocols) and plan a stronger reproducible offline Zeek reprocessing comparison. Tuple existence alone is not a packet-to-flow proof or source authenticity; repeated 5-tuples can match one packet. Do not infer independent attack labels, live AI alerts, Precision/Recall/FPR or event-to-case latency. Preserve official UNSW-NB15 benchmark and keep active Red Team disabled.


## Cyber Lab — verified offline PCAP/Zeek tuple-presence gate (#255, 30/10/2026)

- [x] [PR #255](https://github.com/tbao4151/DA_CNTT/pull/255) merged as `83d7bcd22856f851dfa304ddca2f2b6893d7aaa9` after successful final-head [Ubuntu CI #41004591023](https://github.com/tbao4151/DA_CNTT/actions/runs/41004591023) and [Windows offline Zeek CI #41004591010](https://github.com/tbao4151/DA_CNTT/actions/runs/41004591010). This supersedes the earlier pending feature CI/merge item; post-merge main CI must be verified separately.
- [ ] On student Windows 11, run the pinned read-only checker on an independently recorded, authorized original VMware Host-only classic Ethernet IPv4 TCP/UDP PCAP and Zeek conn.log; archive hashes, Zeek version, isolation evidence, commands, exit codes and output privately. CI synthetic tests do not replace this acceptance.
- [ ] Evaluate stronger offline Zeek reprocessing/provenance comparison and clearly account for VLAN, IPv6, fragments, repeated tuples and time/connection-state ambiguity. Do not claim one-to-one flow identity, source authenticity, attack detection, independent labels, Precision/Recall/FPR or event-to-case latency from tuple existence. Preserve official UNSW-NB15 and leave active Red Team disabled pending approved isolation.


## Cyber Lab — opt-in Zeek reprocessing parsed-flow comparison (30/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 and Windows Server 2022 CI for `tests/test_zeek_reprocessing_compare.py` and existing regressions; inspect mergeability and competing PRs, merge only if all required checks pass on the exact head.
- [ ] On authorized student Windows 11/VMware Host-only, preserve original PCAP and independently recorded SHA-256; run `zeek -r` twice offline in a documented Linux environment with version/config/script information, independently pin both private `conn.log` files, then compare with `scripts/compare_zeek_reprocessing.py`. Archive commands, exit codes, hashes, isolation evidence and results privately.
- [ ] This comparison covers only the supported parsed fields and record multiplicity; Zeek UIDs and unparsed columns are not checked, and it cannot prove both logs originate from the pinned PCAP. Plan a separate reproducible PCAP-to-Zeek provenance protocol, independent ground-truth labels, and host/session-disjoint evaluation before claiming detection quality or event-to-case latency. Preserve Dataset Mode and keep Red Team execution disabled until isolation is approved.


## Cyber Lab — verified offline Zeek reprocessing comparison (#257, 30/10/2026)

- [x] [PR #257](https://github.com/tbao4151/DA_CNTT/pull/257) merged as `368b8a9e29a51ef615062bfb182568d643cea45b` after final-head [Ubuntu CI #41009544956](https://github.com/tbao4151/DA_CNTT/actions/runs/41009544956) and [Windows offline Zeek CI #41009544904](https://github.com/tbao4151/DA_CNTT/actions/runs/41009544904) both passed. This supersedes the earlier pending feature-CI/merge item; post-merge `main` CI is tracked separately.
- [ ] Student runs two independently documented, offline `zeek -r` passes over the **same** authorized, SHA-256-pinned VMware Host-only PCAP, records Zeek binary/version/scripts/config and each private `conn.log` SHA-256, then runs the read-only comparator on Windows Python 3.12.9. Retain isolation screenshots, commands, exit codes, output and original files outside Git.
- [ ] Design a stronger reproducible PCAP-to-Zeek provenance check and explicitly evaluate unparsed columns, Zeek UID variation, protocol/version differences and timestamp precision. Collect independently adjudicated ground truth with host/session-disjoint holdout before reporting Blue Team precision/recall/FPR or real event-to-case latency. No active Red Team outside an approved isolated lab.


## Cyber Lab — opt-in strict full Zeek ASCII field comparison (30/10/2026)

- [ ] Verify final-head Ubuntu Python 3.12.9 and Windows Server 2022 CI for `tests/test_zeek_reprocessing_compare.py` and existing suites; merge only after all required checks pass and the PR is conflict-free.
- [ ] Student records two independent offline Zeek `conn.log` outputs from the same privately SHA-256-pinned authorized Host-only PCAP; compare with and without `--strict-all-fields`, preserve Zeek version, scripts/config, command lines, original hashes, exact outputs and failure cases outside Git.
- [ ] Document raw formatting sensitivity, additional run-specific columns, absent `#types` and UID-containing fields. A successful full raw comparison still cannot prove PCAP provenance, VMware isolation or ground-truth labels. Preserve UNSW-NB15 benchmark and leave active Red Team disabled pending verified authorization.


## Cyber Lab — strict Zeek ASCII comparison merged (#259, 30/10/2026)

- [x] [PR #259](https://github.com/tbao4151/DA_CNTT/pull/259) merged as `133ced93d3c0a56d3af71c4ba2f1cf6775661131` after final-head [Ubuntu CI #41016012203](https://github.com/tbao4151/DA_CNTT/actions/runs/41016012203) and [Windows offline CI #41016012252](https://github.com/tbao4151/DA_CNTT/actions/runs/41016012252) succeeded. This supersedes the pending feature-CI/merge item above; post-merge `main` CI remains a separate check.
- [ ] Student runs default and `--strict-all-fields` comparisons on two privately SHA-256-pinned offline Zeek `conn.log` outputs from the same authorized VMware Host-only PCAP. Archive original PCAP, version/config/scripts, SHA-256, exact commands, output, exit codes and isolation screenshots outside Git; distinguish synthetic CI from actual Windows 11 acceptance.
- [ ] Prioritize an auditable PCAP-to-Zeek offline reprocessing protocol and independently adjudicated, host/session-disjoint labeled captures for Blue Team AI → alert → SOC evaluation. Raw-field equality is not PCAP origin proof or attack detection; active Red Team remains disabled until explicit lab authorization and isolation checks.


## Cyber Lab — optional triple-pinned PCAP and two Zeek reprocessing logs (30/10/2026)

- [ ] Verify exact feature-head Ubuntu Python 3.12.9 and Windows Server 2022 CI for the updated `tests/test_zeek_reprocessing_compare.py` and all existing regressions; inspect open PRs, mergeability and conflicts before merging.
- [ ] On student-owned authorized Windows 11/VMware Host-only lab, independently preserve the original classic Ethernet IPv4 TCP/UDP PCAP SHA-256 and two distinct `zeek -r` run logs/hashes, Zeek version/scripts/config, isolation screenshots and exact commands outside Git. Run `scripts/compare_zeek_reprocessing.py` with both optional PCAP flags, then with `--strict-all-fields`; archive exit codes and stdout/stderr.
- [ ] Treat success only as matching two Zeek flow multisets and five-tuple **presence** in one pinned PCAP; do not claim packet-to-flow derivation, authenticated capture, Zeek binary provenance, independent labels, Precision/Recall/FPR or end-to-end detection latency. Repeated tuples and unsupported protocols require a separate experimental protocol. Preserve Dataset Mode and keep active Red Team disabled until authorized isolation controls are validated.


## Cyber Lab — triple-pinned PCAP and two Zeek replays: verified merge (30/10/2026)

- [x] [PR #261](https://github.com/tbao4151/DA_CNTT/pull/261) merged as `965e4c9dde51eb5e13b436ddae02a953d6087da5` after exact-head [Ubuntu CI #41021431454](https://github.com/tbao4151/DA_CNTT/actions/runs/41021431454) and [Windows offline CI #41021431259](https://github.com/tbao4151/DA_CNTT/actions/runs/41021431259) succeeded. This supersedes the pending feature-CI/merge item above; post-merge `main` CI must be verified separately.
- [ ] Student independently captures and pins authorized private VMware Host-only PCAP and two separately produced Zeek `-r` logs, recording Zeek version, scripts/config, adapters/routes, commands, exit codes, SHA-256 and operator authorization outside Git. Run both default and `--strict-all-fields` comparison with optional pinned PCAP flags on Windows Python 3.12.9; preserve failures and successes without changing original files.
- [ ] Establish independently adjudicated host/session-disjoint ground truth and measure held-out Blue Team Precision/Recall/FPR plus event-to-alert/SOC latency. Triple-pinned tuple presence does not prove PCAP-to-log derivation, capture authenticity, host isolation or attack detection. Keep active Red Team traffic disabled pending approved isolated lab controls; preserve official UNSW-NB15 benchmark.


## Cyber Lab — two-pass offline Zeek reproduction (30/10/2026)

- [ ] Verify exact feature-head Ubuntu Python 3.12.9 and Windows Server 2022 CI for `scripts/replay_zeek_twice_offline.py` and `tests/test_two_pass_offline_zeek.py`; resolve any regression, then merge only with clean PR mergeability. This item is **not** completed merely by adding tests.
- [ ] Student-owned isolated Linux/VMware lab: independently record classic PCAP SHA-256 and Zeek version, verify Host-only adapters/routes, then run two `zeek -r` passes through the opt-in script with two fresh private output directories. Preserve original PCAP, both `conn.log` files, import reports, hashes, exact commands, exit codes and failures outside Git.
- [ ] Validate PCAP/Zeek provenance and independent labels, then measure host/session-disjoint Blue Team Precision/Recall/FPR and separately bounded Research Alert/SOC timing. Two-pass agreement and tuple presence alone do not prove capture authenticity, isolation, packet-to-flow identity or AI attack detection. Red Team active traffic remains disabled pending authorized safety controls.


## Cyber Lab — verified two-pass offline Zeek reproduction merge (#263, 30/10/2026)

- [x] [PR #263](https://github.com/tbao4151/DA_CNTT/pull/263) merged as `547ae256f4ce57ff24ce652ef50c4362b7342b16` after exact-head [Ubuntu CI #41027915959](https://github.com/tbao4151/DA_CNTT/actions/runs/41027915959) and [Windows offline CI #41027915998](https://github.com/tbao4151/DA_CNTT/actions/runs/41027915998) succeeded. This supersedes the earlier pending feature CI/merge checklist. Post-merge `main` CI must be assessed separately.
- [ ] Student performs the two actual Zeek `-r` passes on a privately SHA-256-pinned authorized VMware Host-only capture in Linux/WSL with independently documented Zeek version/config, operator approval, isolation, commands, logs and exit codes. Archive all private evidence outside Git. Synthetic/mock CI cannot substitute for this experiment.
- [ ] Obtain independent ground-truth labels and host/session-disjoint holdout; evaluate Blue Team Precision/Recall/FPR and separately measured capture-to-alert/SOC latency. Two-pass reproducibility plus tuple presence is not source authentication, packet-to-flow identity or attack detection. Preserve official UNSW-NB15 Dataset Mode and keep active Red Team disabled until isolation is verified.


## Cyber Lab — optional pinned Zeek executable for two-pass reproduction (30/10/2026)

- [ ] Verify exact feature-head Ubuntu Python 3.12.9 and Windows offline Zeek CI for the optional binary SHA-256 gate and its mocked regressions. Merge only if all relevant checks succeed and the PR remains conflict-free; the feature is not complete merely because source files were pushed.
- [ ] On an authorized isolated student-owned Linux/VMware lab, independently record the resolved Zeek executable SHA-256 and version, scripts/configuration and original PCAP SHA-256. Use `--expected-zeek-binary-sha256` with the two-pass offline tool, preserve both Zeek logs, checksums, commands and evidence outside Git; compare a deliberately modified **copy** of the binary only in a disposable test environment if needed, never modify the installed production binary.
- [ ] Continue independently adjudicated host/session-disjoint lab capture labeling and held-out Precision/Recall/FPR evaluation. Executable-byte integrity alone does not authenticate Zeek dependencies, scripts, PCAP origin, VMware isolation or event-to-alert/SOC latency. Preserve official UNSW-NB15 Dataset Mode and keep active Red Team disabled.


## Cyber Lab — Zeek binary pin CI and merge verified (30/10/2026)

- [x] [PR #265](https://github.com/tbao4151/DA_CNTT/pull/265) merged as `9c0b96c53ea40ba96b3bbfe1c89f3ef746f376b4` after successful exact-head [Ubuntu CI #41035470042](https://github.com/tbao4151/DA_CNTT/actions/runs/41035470042) and [Windows offline Zeek CI #41035469965](https://github.com/tbao4151/DA_CNTT/actions/runs/41035469965), with no conflict. This supersedes the earlier pending feature CI/merge item; main post-merge CI remains a separate verification.
- [ ] Independently hash and record Zeek executable, version, scripts/configuration and original PCAP in an authorized VMware Host-only environment; run real offline two-pass Zeek and preserve private output and checksums. Mocked CI cannot substitute for this experiment.
- [ ] Prioritize independent host/session-disjoint ground truth and held-out Blue Team Precision/Recall/FPR, then verified AI alert-to-SOC evidence and stage-specific latency. Keep UNSW-NB15 Dataset Mode unchanged and active Red Team disabled until lab isolation is independently verified.

## Cyber Lab — pinned Zeek invocation path hardening (30/10/2026)

- [ ] Verify exact feature-head Ubuntu Python 3.12.9 quality CI and Windows Server 2022 offline Zeek CI, including `tests/test_offline_pcap_import.py` and `tests/test_two_pass_offline_zeek.py`; merge only when conflict-free and all required checks pass.
- [ ] On an authorized isolated Linux VMware lab, independently record Zeek binary SHA-256, `zeek --version`, dependencies/scripts, original PCAP digest, commands and exit codes; verify the pinned two-pass runner uses the intended executable and produces private evidence. Never equate synthetic CI with laptop/real Zeek acceptance.
- [ ] Investigate stronger runtime provenance (in-place binary replacement race, script/dependency hashes) without falsely claiming binary authenticity or capture provenance. Collect independent labels and host/session-disjoint holdout before reporting Blue Team Precision/Recall/FPR or real end-to-end latency. Dataset Mode and active Red Team remain unchanged.

## Cyber Lab — pinned Zeek executable invocation CI verified (30/10/2026)

- [x] [PR #267](https://github.com/tbao4151/DA_CNTT/pull/267) merged as `752672cbe0ee3f577d9b0748553aa1c75daaefca`; final-head [Ubuntu CI #41042484936](https://github.com/tbao4151/DA_CNTT/actions/runs/41042484936), [Windows offline CI #41042484752](https://github.com/tbao4151/DA_CNTT/actions/runs/41042484752), and [Real Zeek synthetic smoke #41042484748](https://github.com/tbao4151/DA_CNTT/actions/runs/41042484748) all completed successfully. This supersedes the preceding pending CI/merge item; post-merge main CI is separate.
- [ ] Student: confirm VMware Host-only isolation and authorization, record real Linux Zeek binary/version/scripts, PCAP and log SHA-256, then execute pinned two-pass offline reproduction and archive private artifacts with command lines and exit codes. Do not claim laptop acceptance based on GitHub CI.
- [ ] Research priority: independently labeled lab sessions, host/session-disjoint holdout and schema-compatible Blue Team model with measured Precision/Recall/FPR; only then evaluate AI alert-to-SOC evidence and stage-specific latency. Do not tune against official UNSW-NB15 test or activate Red Team outside approved isolated lab.

## Cyber Lab — real Zeek two-pass CI integration (30/10/2026)

- [ ] Verify final feature-head Ubuntu Python 3.12.9 quality gates and `Real Zeek offline synthetic smoke` CI, especially both actual `zeek -r` passes, bad-pin refusal, strict non-UID comparison and PCAP tuple checks. Resolve any CI failures before merging.
- [ ] Clearly distinguish CI's pinned host-side Docker proxy from the Zeek executable inside the container; the workflow does not attest container Zeek ELF, image provenance, scripts or libraries. Preserve short-lived synthetic CI artifacts and report flags; never present these as student VMware evidence.
- [ ] On the student's Windows 11 laptop with authorized, verified VMware Host-only isolation, capture original PCAP, record Zeek binary/version/configuration and independently labeled host/session-disjoint experiments, then validate AI scoring, Research Alert and manual SOC Case with private evidence. No active Red Team or public deployment.

## Cyber Lab — verified production two-pass real Zeek synthetic CI (30/10/2026)

- [x] [PR #269](https://github.com/tbao4151/DA_CNTT/pull/269) merged as `361469995d20f327b503345dbeb430e5ecd3f7d5`; exact-head [Ubuntu CI #41050093235](https://github.com/tbao4151/DA_CNTT/actions/runs/41050093235) and [Real Zeek synthetic CI #41050093215](https://github.com/tbao4151/DA_CNTT/actions/runs/41050093215) passed. The production two-pass CLI was exercised with two real network-disabled Zeek `-r` executions against a deterministic benign synthetic PCAP, including negative proxy-pin gate and strict comparison. Supersedes the preceding pending feature-CI item; post-merge main CI is not yet verified.
- [ ] Student acceptance: independently verify VMware Host-only isolation and authorized lab scope; record original PCAP SHA-256, Linux Zeek executable (not Docker proxy) SHA-256/version/scripts and two actual offline passes; preserve private logs, commands, exit codes, and signed-off capture provenance. GitHub synthetic CI is not laptop evidence.
- [ ] Research: collect independently adjudicated benign/attack ground truth across host/session-disjoint partitions; evaluate schema-compatible Blue Team model on held-out captures with Precision, Recall and FPR, then measure alert-to-SOC stages. Keep active Red Team disabled until isolation/approval, and do not treat UNSW Dataset Mode metrics as Cyber Lab results.

## 2026-10-30: Next evidence gate — CI container Zeek binary fingerprint

- **In review / not verified:** CI must record the real in-container Zeek executable hash and image ID, check the executable hash before each offline proxy pass, and demonstrate fail-closed behavior on an incorrect digest. Keep the host-side proxy pin separate and explicitly mark the container digest as runtime-observed, not independently attested.
- **Acceptance:** exact-head Real Zeek synthetic smoke and Ubuntu quality CI success, clean PR mergeability, artifact with the in-container hash/image ID and both offline outputs. Do not interpret CI synthetic evidence as a VMware capture or independently labeled attack detection.
- **Student next:** collect owned VMware Host-only PCAP, archive network isolation evidence and Zeek executable/version/configuration in a private notebook; perform offline two-pass reproduction before drawing scientific conclusions.

## 2026-10-30 — Verified in-container Zeek binary CI fingerprint; next research acceptance

- [x] [PR #271](https://github.com/tbao4151/DA_CNTT/pull/271) merged as `f444671948111765816339822bd8efd7f6100e2f` after successful exact-head [Ubuntu quality CI #41057572837](https://github.com/tbao4151/DA_CNTT/actions/runs/41057572837) and [Real Zeek synthetic CI #41057572832](https://github.com/tbao4151/DA_CNTT/actions/runs/41057572832), with clean mergeability. Synthetic artifact records observed in-container Zeek executable SHA-256, image ID and a negative wrong-hash refusal; no independent authenticity or execution attestation claimed.
- [ ] Student Windows 11 + Linux VMware Host-only: verify adapters/routes and authorization independently; capture owned PCAP, hash original, record actual Zeek binary/version/config/scripts, run two offline passes, archive outputs/commands/exit codes in private evidence folder. CI cannot substitute for laptop acceptance.
- [ ] Scientific priority: independently adjudicate benign and approved test sessions; split by host/session with capture provenance; evaluate schema-compatible Blue Team on held-out logs with Precision/Recall/FPR, then measure capture-to-alert-to-SOC stages. Preserve official UNSW benchmark and keep active Red Team disabled pending lab isolation/approval.

## 2026-10-30 — Opt-in PCAP/Zeek timestamp presence (feature acceptance pending)

- [ ] Verify exact-head Ubuntu Python 3.12.9 and Windows offline Zeek CI for `tests/test_pcap_zeek_tuple.py`; resolve failures and merge only if conflict-free. The new gate must remain opt-in and fail closed on a five-tuple reused at a distant timestamp.
- [ ] Student: obtain an authorized VMware Host-only PCAP and Zeek `conn.log`, independently record SHA-256, inspect clock synchronization and original packet timestamps, then run both tuple-only and `--require-timestamp-corroboration` verification. Preserve private inputs and results; investigate mismatches without widening the fixed tolerance to manufacture success.
- [ ] Research: independently label benign/approved test sessions and split by host/session before evaluating schema-compatible Blue Team Precision/Recall/FPR and separate capture-to-alert/SOC timing. Timestamp presence is not packet-to-flow derivation, capture authenticity, isolation attestation or live attack detection. Keep Dataset Mode and active Red Team unchanged.


## 2026-10-30 — Timestamp-presence PCAP/Zeek verification merged; student acceptance remains

- [x] [PR #273](https://github.com/tbao4151/DA_CNTT/pull/273) merged as `13286bfeee3f533d0e6194f72ac31c2c09c0f5be` after clean mergeability and successful final-head [Ubuntu CI #41065721391](https://github.com/tbao4151/DA_CNTT/actions/runs/41065721391), [Windows offline CI #41065722369](https://github.com/tbao4151/DA_CNTT/actions/runs/41065722369) and [Real Zeek synthetic CI #41065721439](https://github.com/tbao4151/DA_CNTT/actions/runs/41065721439). Supersedes the preceding pending feature-CI item. The opt-in timestamp gate was tested with synthetic fixtures; no real VMware capture acceptance is claimed.
- [ ] Student Windows 11 + Linux VMware Host-only: document authorization, isolation and synchronized capture/log clocks; independently hash the private PCAP and Zeek `conn.log`; execute tuple-only and `--require-timestamp-corroboration` checks, archive raw inputs, commands, exit codes and failure explanations outside Git. Do not adjust the fixed one-second window to force success.
- [ ] Next research priority is **independently adjudicated** benign/approved-test labels and host/session-disjoint held-out evaluation of the Zeek-schema-compatible Blue Team model, followed by evidence-linked AI alert and manual SOC case timing. A timestamp-presence match does not establish attack detection, packet-to-flow derivation or VMware isolation. Preserve official UNSW-NB15 Dataset Mode and keep active Red Team disabled until explicit approval and isolation validation.


## 2026-10-30: Real-Zeek pre-scoring timestamp integration (pending PR CI)

- [ ] Confirm final-head Ubuntu quality and network-disabled Real Zeek synthetic CI for the pre-scoring timestamp-presence gate; inspect `ci_real_zeek_scoring_report.json` and only merge after checks pass and no conflicts.
- [ ] On Windows/Linux VMware Host-only, independently record authorization, isolated adapters/routes, original PCAP and Zeek hashes, capture clocks and operator notes; test tuple-only versus timestamp opt-in without changing the fixed one-second window. Do not treat CI synthetic acceptance as student laptop acceptance.
- [ ] Prioritize independently adjudicated, host/session-disjoint labeled captures and Zeek-schema Blue Team research evaluation before any automated alert or Red Team activity; retain explicit human confirmation for Unclassified SOC cases and preserve official UNSW-NB15 benchmark.


## 2026-10-30 — Real-Zeek synthetic timestamp-gated research acceptance verified

- [x] [PR #275](https://github.com/tbao4151/DA_CNTT/pull/275) merged as `68dbb594b052b077a3254f3e2136e4ef4c899c11` after clean mergeability and exact-head [Ubuntu CI #41074206007](https://github.com/tbao4151/DA_CNTT/actions/runs/41074206007), [Windows offline CI #41074206010](https://github.com/tbao4151/DA_CNTT/actions/runs/41074206010) and [real Zeek 9.0.1 synthetic CI #41074205917](https://github.com/tbao4151/DA_CNTT/actions/runs/41074205917) succeeded. The previous pending-CI entry remains a historical authoring snapshot, not current PR status.
- [ ] Verify post-merge main quality workflow [#41078703078](https://github.com/tbao4151/DA_CNTT/actions/runs/41078703078) when complete; separately test the same CLI on student Windows 11 with authorized private VMware Host-only PCAP, Zeek log, independently recorded hashes and clock/scope evidence.
- [ ] Prioritize independently adjudicated benign/approved-test labels, host/session-disjoint holdout and a Zeek-schema Blue Team model evaluation with honest Precision/Recall/FPR and timing before claiming AI attack detection. Keep active Red Team disabled pending isolation/authorization; do not confuse synthetic CI manual SOC cases with production alerts.


## 2026-10-30 — Production offline new-log timestamp gate (feature acceptance pending)

- [ ] Verify final-head Ubuntu Python 3.12.9 and Windows offline Zeek CI for `tests/test_new_log_timestamp_scoring_gate.py`, including fail-closed refusal before prediction publication; only merge if all relevant checks succeed and GitHub reports no conflicts.
- [ ] On the student's Windows 11 / authorized Linux VMware Host-only setup, independently record original PCAP/Zeek SHA-256, Zeek version/configuration, operator authorization, isolation screenshots and capture clock notes. Use the opt-in scoring gate with the three pinned import inputs and retain private output/exit codes. CI synthetic tests do not substitute for this acceptance.
- [ ] Obtain independently adjudicated benign/approved-test labels, pre-register host/session-disjoint holdout, measure Zeek-schema Blue Team Precision/Recall/FPR and stage-specific timing, then link research candidates to explicitly analyst-confirmed SOC cases. No active Red Team traffic or public deployment before isolation approval; preserve UNSW Dataset Mode benchmark.

## 2026-10-30 — Production Zeek timestamp-gated offline scoring verified

- [x] [PR #277](https://github.com/tbao4151/DA_CNTT/pull/277) merged as `7c36478fea5ade4c743c00b7d21d2000a9a5e2f5`; exact-head [Ubuntu CI #41083612923](https://github.com/tbao4151/DA_CNTT/actions/runs/41083612923), [Windows offline CI #41083612690](https://github.com/tbao4151/DA_CNTT/actions/runs/41083612690) and [real-Zeek synthetic CI #41083612727](https://github.com/tbao4151/DA_CNTT/actions/runs/41083612727) passed. Earlier pending-check items are historical authoring snapshots. No student-operated capture was tested.
- [ ] Record authorized Windows 11 + VMware Host-only topology, route/isolation proof, original private PCAP/Zeek SHA-256 and Zeek version; exercise the **opt-in** scorer against genuinely corresponding lab captures. Keep all private evidence outside the public repository.
- [ ] Prioritize independently adjudicated benign/approved-test labels, host/session-disjoint holdout, Zeek-schema model Precision/Recall/FPR and stage-specific latency with provenance. Link research candidates to manually confirmed SOC cases only; keep active Red Team disabled until lab approval. Preserve official UNSW-NB15 Dataset Mode.


## 2026-10-30 — Real Zeek production timestamp scoring acceptance (CI pending)

- [ ] Verify **exact feature-head** Ubuntu Python 3.12.9 quality CI and network-disabled Real Zeek synthetic smoke, including the new production CLI opt-in positive path, identical legacy prediction semantics, and the coherently re-pinned +120-second negative fixture refused **before** publishing a prediction. Check PR mergeability; merge only with all required checks green. CI-only fabricated metadata must never be presented as authentic Zeek import provenance.
- [ ] On the student's authorized Windows 11/Linux VMware Host-only environment, independently verify isolation and capture provenance, pin original PCAP/Zeek/import/model hashes, run both scoring paths with the same trusted Zeek-schema research model, and privately archive commands, outputs and exit codes. Do not use CI-only synthetic models for the student experiment.
- [ ] Scientific priority remains independently adjudicated benign/approved-test sessions with host/session-disjoint holdout and Zeek-schema Precision/Recall/FPR, then measured offline capture-to-alert-to-manual-SOC stages. Keep UNSW Dataset Mode unchanged and active Red Team disabled until isolation and operator authorization are independently established.

## 2026-10-31 — Real-Zeek production timestamp gate CI verified; independent evaluation next

- [x] [PR #279](https://github.com/tbao4151/DA_CNTT/pull/279) merged as `61887005658800536b58f04174a10b6f4f33c27e` after clean mergeability and successful exact-head [Ubuntu quality #41092083099](https://github.com/tbao4151/DA_CNTT/actions/runs/41092083099), [Windows offline #41092083189](https://github.com/tbao4151/DA_CNTT/actions/runs/41092083189), and [real Zeek synthetic #41092082854](https://github.com/tbao4151/DA_CNTT/actions/runs/41092082854). This supersedes the preceding pending feature-CI item; synthetic re-pinned negative metadata is not authentic provenance. Post-merge main CI must be verified separately.
- [ ] Student Windows 11 + authorized VMware Host-only Linux VM: independently document network isolation/route checks, original PCAP and Zeek `conn.log` SHA-256, import report/model pins, Zeek version, clocks, exact commands and exit codes; run both production scoring paths with a research model trained only on approved, independently labeled lab data. Keep all capture/evidence files private and outside GitHub.
- [ ] Scientific priority: collect independently adjudicated benign/approved-test sessions; pre-register host/session-disjoint train/validation/held-out test with no source reuse, report Zeek-schema model Precision/Recall/FPR and per-stage offline latency, then connect research candidates to explicitly analyst-confirmed SOC cases. Do not claim attack-detection accuracy or live operation from CI synthetic fixtures. Keep official UNSW Dataset Mode unchanged and active Red Team disabled until verified isolation and authorization.

## 2026-10-31 — Research provenance consistency before Zeek model fitting

- [ ] Verify exact-head Ubuntu quality CI and regression tests for duplicate
  `(source_sha256, uid)` rows, conflicting source/session/host/annotation
  metadata, and valid multiple sessions on one host within the same split.
  Merge the feature PR only after clean CI and conflict checks.
- [ ] On the student's authorized, independently isolated VMware Host-only
  lab, preserve original private Zeek logs and annotation SHA-256; pre-register
  disjoint train/validation/test hosts and sessions and verify original bytes
  before the one-time held-out evaluation. Software provenance consistency
  does not authenticate labels, captures or isolation.


## 2026-10-31 — PR #281 CI repair gate

- [ ] Recheck Ubuntu quality and Windows offline Zeek workflows for the repaired PR #281 head (`44488baf0cbe03e366efd6eef23c9ecdc294c2e9`); the previous head `6c153af1ef699210746b773bda18ae383b9cfedb` failed because port-ablation tests forged a second host on the same source log. Merge only with successful exact-head checks and clean mergeability.
- [ ] Student Windows 11: after merge, run `py -3.12 -m pytest -q tests/test_zeek_offline_baseline.py tests/test_zeek_port_ablation.py` and preserve private, independently labeled Host-only lab captures before reporting any detection metrics.


## 2026-10-31 — PR #281 latest Ubuntu regression repair

- [ ] Verify new exact-head Ubuntu full quality suite and Windows offline Zeek checks after commit `5766a95a909cca583dc05bb3a6b2a39e19c26b4e` on PR #281. Prior [Ubuntu #41104325669](https://github.com/tbao4151/DA_CNTT/actions/runs/41104325669) failed only the pre-existing cross-split SHA-256 diagnostic expectation (1 failed, 1213 passed, 2 skipped), while [Windows #41104325609](https://github.com/tbao4151/DA_CNTT/actions/runs/41104325609) passed. Preserve both leakage detection and its established error semantics. Merge only after fresh exact-head green CI and no conflicts.
- [ ] Continue independent host/session-disjoint labeled VMware Host-only evidence collection on the student's Windows machine; no synthetic fixture metrics count as research attack detection.


## 2026-10-31 — Verified PR #281 integration; research evidence remains outstanding

- [x] Merge Zeek research dataset provenance consistency guard as [PR #281](https://github.com/tbao4151/DA_CNTT/pull/281), squash commit `2e8c0b95f6cd18e7bbb706af2e1aaad2254c4b10`, with successful exact-head [Ubuntu #41109221783](https://github.com/tbao4151/DA_CNTT/actions/runs/41109221783) and [Windows #41109221887](https://github.com/tbao4151/DA_CNTT/actions/runs/41109221887). Earlier unchecked CI tasks are superseded; post-merge `main` CI remains unverified.
- [ ] Student Windows 11: run `py -3.12 -m pytest -q tests/test_zeek_offline_baseline.py tests/test_zeek_port_ablation.py`; preserve original authorized VMware Host-only PCAP/Zeek logs, SHA-256 and independently adjudicated labels, and preregister host/session-disjoint holdout. Synthetic CI is not real lab attack-detection evidence.

## 2026-10-31 — Predeclared NEW-log always-Normal research comparator

- [ ] Verify exact-head Ubuntu Python 3.12.9 quality CI and Windows offline
  tests for the additive always-Normal aggregate comparator; merge only after
  green checks and clean PR mergeability. This policy is fixed before labels,
  does not fit or tune on NEW data, and is not a useful detector.
- [ ] On the student's authorized VMware Host-only lab, preserve private
  PCAP/Zeek SHA-256, independent annotations, pre-registered disjoint
  train/validation/test hosts and evidence of physical isolation; report
  genuine held-out metrics and model-vs-reference tradeoffs without claiming
  synthetic CI performance as real attack detection.


## 2026-10-31 — Fixed trivial-policy comparison for private NEW Zeek evaluation

- [x] Verify [PR #283](https://github.com/tbao4151/DA_CNTT/pull/283) merged and its exact-head [Ubuntu #41117434320](https://github.com/tbao4151/DA_CNTT/actions/runs/41117434320) and [Windows #41117434375](https://github.com/tbao4151/DA_CNTT/actions/runs/41117434375) CI passed; post-merge [main quality #41121257764](https://github.com/tbao4151/DA_CNTT/actions/runs/41121257764) passed. Historical pending PR #283 entry above is superseded.
- [ ] Validate the complementary always-Attack reference with mixed/single-class synthetic regression tests on Ubuntu and Windows CI; merge its PR only if exact-head checks succeed and no conflicts. Both fixed references are non-learning controls, not detectors, and cannot be selected using NEW labels.
- [ ] On student Windows 11 with authorized isolated VMware Host-only lab, independently preserve PCAP/Zeek SHA-256, labels and scenario evidence, pre-register host/session-disjoint holdout, run `py -3.12 -m pytest -q tests/test_zeek_new_log_evaluation.py`, then compare model against both fixed policies on genuine independently adjudicated data. Never interpret synthetic CI as measured attack detection.


## 2026-10-31 — Verified both fixed NEW Zeek evaluation controls

- [x] Merge [PR #284](https://github.com/tbao4151/DA_CNTT/pull/284) (always-Attack reference), squash commit `2832b14ed62d30522a97df6645679fda6c8b2353`, after successful exact-head [Ubuntu #41125321058](https://github.com/tbao4151/DA_CNTT/actions/runs/41125321058) and [Windows #41125320981](https://github.com/tbao4151/DA_CNTT/actions/runs/41125320981) CI and clean mergeability. Earlier pending always-Attack checkbox is superseded; post-merge main CI must be verified separately.
- [ ] Stop adding trivial references without a research need. Prioritize genuine authorized VMware Host-only PCAP and Zeek `conn.log`, independently adjudicated labels, pre-registered host/session-disjoint holdout, and provenance evidence. Compare fixed research model against both predeclared references on a NEW private holdout without tuning from it; report Precision/Recall/FPR and uncertainty with honest limitations.
- [ ] Student Windows 11: run `py -3.12 -m pytest -q tests/test_zeek_new_log_evaluation.py`, validate Host-only isolation before capture, and archive original PCAP/log SHA-256, Zeek version, annotations and consent/approval privately. GitHub synthetic CI is not proof of local lab attack detection.
