# DA005 — Blue Team NEW-log verified review (local Streamlit)

This is a separate **read-only** Cyber Lab page for NEW Zeek `conn.log`
predictions, distinct from the held-out research trace viewer. It does not
capture traffic, run Red Team, create SQLite cases or emit operational alerts.

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
   refused without creating a SOC case.

The page uses the strict JSON-only SHA-pinned model loader, checks the
original log and CIDR, recomputes and compares **every** saved prediction,
and recomputes the display rows rather than trusting the uploaded report.
The model file must remain in a trusted private directory. The page never
shows ground-truth labels. Up to 500 original flow positions are considered
for the table; the overall candidate count includes the whole verified log.
This is a **declared-partition consistency check**, not proof that the
operator's manifest captures the full research history. A changed UID,
timestamp or endpoint may evade the conservative identity screen.

For explicitly consented `Unclassified` SOC case creation, continue using
`scripts/triage_zeek_new_log.py` with the separately pinned manifest gate
described in `docs/ZEEK_NEW_LOG_MANUAL_SOC_TRIAGE.md`. This UI deliberately
does not write SQLite or create operational alerts. Its successful preflight
must not be substituted for the CLI's recheck at the case-write boundary.

## Software-only verification

```powershell
py -3.12 -m pytest -q tests/test_zeek_new_log_workspace.py tests/test_zeek_new_log_ui_partition.py
```

Synthetic tests and GitHub CI do not prove a student-owned Host-only
capture, independent labels, model authorship, physical isolation, real
attack detection, operational latency, or generalization. Preserve original
UNSW-NB15 Dataset Mode and historical benchmark unchanged.
