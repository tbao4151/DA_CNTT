# DA005 — Verified offline Zeek research alert-candidate bundle

This is a **research candidate queue**, not operational SIEM alerting or
confirmed attack detection. It bridges the existing pinned Zeek new-log
inference/report review to the **existing explicit manual** SOC triage path.
The CLI writes one private JSON, never a SQLite case or network packet.

From the repository root on Windows 11 with Python 3.12.9, first generate
`new-predictions.json` using `scripts/score_zeek_new_log.py` and its
pinned TRAIN/VALIDATION/TEST manifest gate. Record SHA-256 of all four inputs
**independently** in the private experiment notebook. Then run:

```powershell
py -3.12 scripts/export_zeek_research_alerts.py `
  --model "C:/DA005-private/zeek-experiment/model.json" `
  --expected-model-sha256 "<64 lowercase hex>" `
  --log "C:/DA005-private/new-capture/conn.log" `
  --expected-log-sha256 "<64 lowercase hex>" `
  --report "C:/DA005-private/new-capture/new-predictions.json" `
  --expected-report-sha256 "<64 lowercase hex>" `
  --manifest "C:/DA005-private/zeek-experiment/manifest.json" `
  --expected-manifest-sha256 "<64 lowercase hex>" `
  --cidr "192.168.56.0/24" `
  --output "C:/DA005-private/new-capture/research-alerts.json"
```

Replace the CIDR with the approved RFC1918 VMware Host-only subnet. The
manifest must include `labels_sha256` for every declared TRAIN, VALIDATION
and TEST capture. The exporter re-reads those original captures and labels,
checks model/manifest provenance and screens source and normalized flow
identity non-reuse. It independently verifies the saved prediction JSON by
recomputing **every** score from the pinned model and original log bytes.

The queue preserves the **original zero-based Zeek record index**, UID,
original timestamp/endpoints, research probability and selected validation
threshold, plus source/model/report/manifest hashes. It sorts visible
candidates by probability, with the original index as a deterministic
tie-breaker. `research_alert_ref` uses the existing source+UID research
deduplication namespace, but is **not a SOC case ID**.

Only candidate flows among the **first 500 original rows** are exported:
the current `triage_zeek_new_log.py` manual SOC API intentionally permits
only original indices 0–499. The bundle reports both total candidates and
how many fall outside this window; it never silently renumbers rows. An
analyst may inspect the bundle, then separately run the existing pinned
manual triage command with a chosen original `record_index`, private
SQLite destination and explicit authorization/review/new-capture confirmations.
That operation creates/reuses an **Unclassified** research case, not a
confirmed attack. The exporter itself creates no cases or operational alerts.

Publication uses the existing atomic, no-overwrite same-directory hard-link
writer. The output must be a new JSON file beside the original private log,
outside the public repository. The bundle contains private IPs/UIDs and
must not be uploaded to GitHub. It is not signed evidence. Original PCAP
provenance should be checked separately using the existing offline evidence
chain; this exporter does not claim PCAP provenance.

**Scientific limitations:** operator-declared partition screening cannot
prove the completeness of capture history or authenticity of ground-truth
labels. No physical VMware isolation, genuine attack detection, model
generalization, Precision/Recall/FPR, or event-to-alert-to-SOC latency is
established by synthetic CI. No active Red Team traffic is generated.

Synthetic-only regression:

```powershell
py -3.12 -m pytest -q tests/test_zeek_research_alert_bundle.py
```

On the student Windows laptop, preserve genuine authorized PCAP/Zeek,
model, report, manifest, independent SHA-256 pins, approval and Host-only
configuration privately. Confirm that a selected queue record opens exactly
one Unclassified case through the existing manual SOC workflow and that
a modified input or existing output is refused. Record local results
separately from GitHub CI.
