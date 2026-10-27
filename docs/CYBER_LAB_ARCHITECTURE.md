# Cyber Lab Mode — telemetry boundary (offline-first)

## Architecture and current implementation

Dataset Mode is the existing `app.py` + `src/siem_ai/` UNSW-NB15 prototype. It has an offline trained Random Forest, held-out benchmark reports, alert views and SQLite SOC cases. The official UNSW train/test CSVs do not contain original IPs or event timestamps.

Cyber Lab Mode is **not yet a working end-to-end application**. This increment has an **offline** Zeek reader (`src/blue_team_ai/zeek.py`) and a separate Streamlit Blue Team preview (`pages/1_Cyber_Lab.py` with `src/blue_team_ai/preview.py`). The preview accepts a user-selected `conn.log` and displays validated telemetry summaries and provenance. It does not capture packets, replay traffic, execute Red Team scenarios, classify Zeek flows, create alerts or cases. The existing Dataset Mode entry point and model are unchanged. Preview PR CI is tracked separately in `PROGRESS.md`.

Planned boundary: `Host-only VMware lab (student-owned, isolated) -> Zeek conn.log / offline PCAP -> validated telemetry -> separately trained lab-compatible AI -> alert -> SOC evidence/case -> Blue Team UI`. A separate Red Team UI may later select only pre-approved, non-destructive offline replays under explicit operator control, with an allowlist, rate limits and kill switch. None of those active controls is implemented in this increment; lab operation must remain off.

## Offline Zeek contract

The `load_zeek_conn_log(path)` and `parse_zeek_conn_log(data)` functions accept Zeek's ASCII tab-separated `conn.log` with `#separator \\x09`, a `#fields` header, and the required source/destination address, port, UID, timestamp and protocol columns. They reject invalid IPs/ports, malformed numeric fields, bad UTF-8, duplicate/missing headers, mismatched field counts and empty logs. The local file reader is bounded to 15 MiB and 10,000 records. It never opens a socket.

Each event includes `origin=offline_zeek_log`, `source_sha256` of the exact bytes, `event_time_utc` derived from the supplied Zeek `ts`, `uid`, source/destination IP and port, protocol, and optional duration/bytes/packets. Missing optional numeric values are `None`, not zero. These are **claims about the log file contents**, not a claim that a live network was observed or that a label is correct.

**Critical scientific boundary:** Zeek `conn.log` is not feature-equivalent to the 42 UNSW-NB15 model inputs. Never call the existing Random Forest with this event dictionary, and never infer missing UNSW features as zero. A separate validated feature schema, labeled lab dataset, split protocol and trained model are required before Cyber Lab AI alerts can be claimed.

## Repeatable developer checks

From the repository root on Windows with Python 3.12 installed:

```powershell
py -3.12 -m pytest -q tests/test_zeek_telemetry.py
py -3.12 -c "import sys; sys.path.insert(0, 'src'); from blue_team_ai.zeek import load_zeek_conn_log; print(load_zeek_conn_log('PATH_TO_YOUR_OFFLINE_CONN.LOG')[:2])"
```

Use only a `conn.log` collected within a network the group owns or has permission to test. Record the Zeek version, capture time, network isolation settings, source file checksum and original evidence separately. The synthetic test fixture is not a student-operated capture. Do not upload real private IP logs or sensitive payloads to a public repository.

## Next verified milestones

1. Validate the separate offline Cyber Lab preview with GitHub CI and a real student-owned Zeek log on Windows, without changing the Dataset Mode benchmark.
2. Build a typed event/evidence store and parser fixtures for real student-owned Zeek logs; confirm schema and timestamps.
3. Train and evaluate a lab-schema model on independently labeled data; report precision/recall/FPR and detection latency with provenance.
4. Only after operator validation of Host-only isolation, add controlled replay orchestration, safety policy and distinct Red/Blue UIs.

## Offline Blue Team preview interface

Start with `streamlit run app.py`, then open the Cyber Lab page in Streamlit's page navigation. Upload only an authorized Zeek ASCII `conn.log` of up to 15 MiB. The page displays the first 500 validated events, flow counts, unique IPs, protocol distribution, Zeek event timestamp bounds and the exact input SHA-256. The upload is read only by the locally running Streamlit server; do not expose that server publicly or upload sensitive logs to GitHub. A missing file shows an empty-state explanation rather than fabricated results.

The preview uses no attack labels or model scores. The optional manual review action below creates an Unclassified SOC case only after explicit user confirmation. The displayed timestamps and addresses are claims from the uploaded file, not independently authenticated network observations. For real lab evaluation, preserve capture context, Zeek version, Host-only configuration, source integrity and independent labels.

## Explicit offline analyst case (manual review, not AI)

After a validated offline upload, select one of the first 500 displayed flows, tick the permission/consent checkbox for that source SHA-256, and click **Tạo hồ sơ Unclassified**. The server re-parses the exact original bounded bytes before persisting the selected record. This avoids trusting a mutable UI event dictionary. The dedicated local SQLite path is `runtime/cyber_lab_cases.sqlite3`, separate from Dataset Mode's `runtime/soc_cases.sqlite3`. Nothing is persisted on upload or an ordinary page rerun. Every deliberate click creates a new case; there is no deduplication yet.

The case has verdict `Unclassified` and null confidence, not `Attack` or an AI-generated alert. Its evidence snapshot includes the Zeek-supplied timestamp/IP/UID, source SHA-256 and `origin=offline_zeek_log`; a JSON export includes case metadata and audit events. The existing shared SOC store serializes feature values to bounded strings, so this is a human-readable, **not lossless**, event snapshot (e.g. absent values may appear as the string `None`). Preserve the original `conn.log` separately and verify its SHA-256. SQLite records and JSON are editable, unsigned and not forensic chain-of-custody evidence. No active capture, traffic replay or AI model inference is introduced.

Run `py -3.12 -m pytest -q tests/test_zeek_manual_triage.py tests/test_cyber_lab_preview.py tests/test_zeek_telemetry.py` and test the manual selection/export locally on Windows. The synthetic tests do not establish real-lab correctness. Next, design a typed event/evidence schema that preserves missing-value types, followed by independently labeled lab data and a separate model.

## Source-verified typed export (PR pending, 28/10/2026)

The manual case still stores a bounded **string** snapshot in the existing SQLite SOC table; no schema migration or changes to Dataset Mode. After an explicit case creation, the Cyber Lab UI remembers the selected zero-based record index for the current Streamlit session. On export, `src/blue_team_ai/verified_report.py` re-parses the uploaded original Zeek bytes, verifies SHA-256, compares every selected parsed field with the stored string snapshot and checks the stored flow digest. If the file, index or snapshot differs, it refuses to export. The exported version-2 JSON retains the original case metadata/audit and adds `typed_zeek_event` (nulls remain null; counts/ports remain integers; duration remains numeric) and `typed_event_source` with the original record index and checksum.

This is **source-consistency verification**, not proof that the source file was genuinely captured from a VMware lab or that the SQLite database is immutable. The original log must still be available in the active upload session for typed export. Historical exports from `siem_ai.case_report` remain schema v1 and unchanged. No AI classification or automated alert is introduced. Run `py -3.12 -m pytest -q tests/test_zeek_verified_report.py tests/test_zeek_manual_triage.py` and test the new button manually on Windows. CI status and merge are tracked in PROGRESS.

## Zeek-only lab feature contract v1 (PR #48 merged, 28/10/2026)

`src/blue_team_ai/features.py` defines `LAB_FEATURE_SCHEMA_VERSION = 1` and a **strict projection**, not an AI model. `extract_zeek_feature_rows` accepts a nonempty ordered batch of already parsed offline Zeek events from exactly one SHA-256 source; the output preserves row order and excludes UID, IP addresses, event timestamps, provenance, labels and AI/UI columns. Unexpected fields (including `label` and `attack_cat`) fail closed instead of being silently used as model inputs. The nine permitted features are `proto`, `service`, `src_port`, `dst_port`, `duration_s`, `orig_bytes`, `resp_bytes`, `orig_pkts`, and `resp_pkts`.

Missing duration/counts/service remain Python `None`; measured zeros remain numeric zero. No imputation, one-hot encoding, normalization, model fitting, attack labeling, score or SOC alert is performed. A future trainer must use **only** projected rows, explicitly version the schema, choose missingness/imputation using training data only, and validate on independently labeled holdout flows. Source ports, destination ports and protocol/service can create environment-specific shortcuts; evaluate generalization across capture sessions/hosts, not only random rows from one log. Do not use UNSW-NB15 model/metrics for these Zeek features.

The extractor validates the event shape and source digest format but **does not authenticate the original capture or independently recompute its SHA-256**. The upstream parser/verified export handles bytes; the researcher must preserve the original log and authorized VMware Host-only collection context. Synthetic unit tests do not establish real-world performance.

Run `py -3.12 -m pytest -q tests/test_zeek_features.py` for this feature contract. PR #48 quality gates passed (`223 passed, 2 skipped`); see PROGRESS for post-merge CI and local acceptance limitations.


## Independently labeled Zeek dataset contract (feature PR pending, 28/10/2026)

`src/blue_team_ai/labeled_dataset.py` adds an **offline research input contract**, not a trained classifier. The caller supplies an ordered sequence of 3–30 capture descriptors, each with the **original Zeek ASCII log bytes**, a unique `session_id`, a `host_group` identifying the originating machine/environment, an explicitly assigned `split` (`train`, `validation`, `test`), `label_method` (`controlled_scenario_record` or `manual_analyst_review`), a nonempty `label_reference` to independently retained operator evidence, and a `labels_by_uid` map containing a separately determined binary 0/1 label for every Zeek UID. This contract has **no mechanism to verify the truthfulness** of the labels, operator claims or physical host isolation; the lab notebook and signed-off scenario records remain necessary.

`build_labeled_lab_dataset(captures)` parses the **original bytes** with the existing bounded Zeek parser, computes the source SHA-256, rejects duplicate source files, duplicate sessions, duplicate UIDs within a capture, missing/extra labels, booleans, nonbinary labels, unknown metadata, unsupported label methods, cross-split host reuse and any split lacking either class. It caps aggregate flows at 30,000. It uses the existing nine-column v1 feature projection, returning `features`, `labels` and `provenance` in **separate dictionaries by split**. No IP, UID, timestamp, ground-truth label, source hash or host identity is included in the feature matrix; these are retained only in provenance. No imputation or model fitting occurs, and **nothing is automatically inferred from attack category, timestamps, port numbers or an existing model prediction**.

Host-disjoint splitting is stricter than random flow splitting. Each `host_group` must belong to exactly one split, although multiple sessions from the same host may be grouped in that split. Operators must assign these partitions **before inspecting test performance**, reserve the test set for a single final evaluation, and ensure scenario/host diversity rather than only label balance. For small labs with one physical/virtual host, the function deliberately refuses to pretend host-disjoint generalization has been established. `label_reference` is only an identifier; keep the actual human/scenario annotation evidence outside the public repo and validate timestamps and experiment notes manually.

Example integration (on Windows, in an authorized isolated lab after capturing three distinct host groups):

```python
from pathlib import Path
from blue_team_ai.labeled_dataset import build_labeled_lab_dataset

captures = [
    {
        "log_bytes": Path("private/train-host/conn.log").read_bytes(),
        "session_id": "train-run-001", "host_group": "vm-host-train",
        "split": "train", "label_method": "controlled_scenario_record",
        "label_reference": "private-notes/train-run-001",
        "labels_by_uid": {"ZeekUID_A": 0, "ZeekUID_B": 1},
    },
    # Supply independently annotated validation and test captures as well.
]
# The example is intentionally incomplete and will be rejected until
# all three partitions, full UID maps and both labels per split exist.
dataset = build_labeled_lab_dataset(captures)
```

Use `py -3.12 -m pytest -q tests/test_zeek_labeled_dataset.py` to validate the synthetic contract tests. There is no UI/CLI for labeling yet, no lab-trained model, no AI alert, no real attack-detection metric, and no Windows/VMware acceptance evidence. The next research slice is an **offline** training/evaluation pipeline that fits preprocessing only on train, tunes thresholds on validation and reports untouched test Precision/Recall/FPR and provenance. Do not publish raw private logs, annotation notes or sensitive IP addresses.
