# DA005 — Blue Team NEW-log verified review (local Streamlit)

This is a separate **offline** Cyber Lab page for NEW Zeek `conn.log`
predictions, distinct from the held-out research trace viewer. It can optionally
create one analyst-confirmed **Unclassified research SOC case** in a private
SQLite database. It does not capture traffic, run Red Team, verify attacks or
emit operational alerts.

## Windows acceptance procedure

1. Use Python 3.12.9 and run `streamlit run app.py` from the repository root.
2. Open **New Log Review** in the Streamlit page navigation. Keep the exported
   Zeek model JSON, original NEW `conn.log`, saved NEW prediction report and
   independently recorded SHA-256 values outside Git, ideally under
   `C:/DA005-private/`.
3. Retain an independently recorded SHA-256 for the **original**
   TRAIN/VALIDATION/TEST manifest. Keep all original captures and per-UID
   annotations at their manifest-declared private paths. The UI now **requires**
   this manifest path and independent digest before it displays candidates;
   missing or altered source evidence fails closed. Do not put the manifest,
   raw captures, annotations or private model into Git.
4. Enter the private absolute model and manifest paths, independently
   recorded model/manifest/NEW-log SHA-256, actual authorized VMware Host-only
   CIDR, and upload the original `conn.log` and `new-predictions.json`.
   Click **Xác minh**. The page checks manifest hash and declared capture
   integrity, split labels and host/session separation, then rejects exact-byte
   reuse and normalized UID/time/five-tuple overlap with any declared
   TRAIN/VALIDATION/TEST capture **before** displaying any predictions.
5. Verify the candidate table contains only first-500-row candidates,
   sorted by recomputed attack probability, with original Zeek timestamps
   and endpoints. Capture screenshots and retain original evidence privately.
   Try an incorrect manifest digest, a reserved TEST log (including re-encoded
   bytes), a wrong model/log digest and a modified report. All must be
   refused before any SOC write.

The page uses the strict JSON-only SHA-pinned model loader, checks the
original log and CIDR, recomputes and compares **every** saved prediction,
and recomputes the display rows rather than trusting the uploaded report.
The model file must remain in a trusted private directory. The page never
shows ground-truth labels. Up to 500 original flow positions are considered
for the table; the overall candidate count includes the whole verified log.
This is a **declared-partition consistency check**, not proof that the
operator's manifest captures the full research history. A changed UID,
timestamp or endpoint may evade the conservative identity screen.

## Optional manual SOC triage on this page

After successful pinned verification, the **Manual SOC** form appears if there
are research candidates in the first 500 original Zeek rows. Select a candidate
by its **original one-based Zeek row** (not the sorted table position). Enter
an absolute private SQLite `.sqlite3` destination **outside Git** in an
existing private directory, and explicitly check all three attestations:
reviewed original evidence, authorization, and independent NEW-capture status.
The selected row is converted to the existing zero-based manual-triage API.
An empty selection, missing confirmation, invalid destination or changed
evidence is refused. The page never silently opens a case.

The **write boundary** uses the same strict private-path rules as the CLI:
reload model bytes using its independent SHA-256, reload the manifest and all
original TRAIN/VALIDATION/TEST captures/labels, recheck the independent
manifest digest, source SHA-256, CIDR, exact-byte and normalized flow non-reuse,
and recompute every prediction from the original uploaded log and report.
Only then can an `Unclassified` case be created/reused in private SQLite.
A repeat click for the same source SHA-256 + Zeek UID reuses the original case
and its audit history. The earlier on-screen preview is **not** accepted as
evidence at write time. There is no automatic alert, attack verdict or network
operation. The UI does not export the private database.

Alternatively, use `scripts/triage_zeek_new_log.py` with the independently
pinned manifest gate in `docs/ZEEK_NEW_LOG_MANUAL_SOC_TRIAGE.md`.
Both paths rely on operator attestations: SHA-256 and the declared manifest
cannot independently prove complete historical partition independence, model
authorship, physical isolation, ground-truth authenticity or real detection.

For Windows acceptance, test a valid case, repeated creation (same ID), each
missing checkbox, altered model/manifest/report and a reserved TEST capture;
save local screenshots and private audit JSON. Never commit the private
model, log, manifest, annotations or SQLite database.

## Software-only verification

```powershell
py -3.12 -m pytest -q tests/test_zeek_new_log_workspace.py tests/test_zeek_new_log_ui_partition.py tests/test_zeek_new_log_ui_soc.py
```

Synthetic tests and GitHub CI do not prove a student-owned Host-only
capture, independent labels, model authorship, physical isolation, real
attack detection, operational latency, or generalization. Preserve original
UNSW-NB15 Dataset Mode and historical benchmark unchanged.


## Read-only SOC case history in the Blue Team page

The **New Log Review** page also has a separate section **Hồ sơ SOC nghiên cứu
đã lưu (chỉ đọc)**. This section can be used without uploading a model or
NEW Zeek log again. Enter the **absolute path** of an existing private
`.sqlite3` file outside the repository, click **Đọc danh sách**, select an
`Unclassified` Zeek case, and inspect its stored flow snapshot, source digest,
UID and chronological audit entries. Export the displayed snapshot as JSON
for a private review notebook. This is a read-only SQLite connection
(`mode=ro`, `query_only=ON`), not an update or a second case-creation path.

For resource safety the viewer rejects missing, symlinked, non-SQLite, Git-local,
empty or >128 MiB databases, scans at most 500 recent Unclassified cases,
displays at most 100 matching Zeek cases, and reads at most the latest 200
audit events per case. If the history is truncated, the UI and exported JSON
explicitly say so. Do not treat the bounded JSON as a complete forensic export.
The database and its contents remain private; never expose Streamlit publicly
or commit a case database, export or source capture. Database owners can edit
SQLite; this viewer does not authenticate the original capture, model, labels,
operator, or isolation.

Synthetic-only regression:
`py -3.12 -m pytest -q tests/test_zeek_case_workspace.py`.
Student Windows acceptance: create a private Unclassified case via the
existing verified manual UI, open the viewer using that same private database,
check source SHA-256/UID and audit history, download the JSON to a private
directory, then repeat after a manual case state change via the existing SOC
workflow. Verify a missing database is refused **without creating it**.
GitHub CI is not proof that this procedure was performed on the student's laptop.
