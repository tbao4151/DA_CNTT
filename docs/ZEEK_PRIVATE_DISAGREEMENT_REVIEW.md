# DA005 — Private Zeek disagreement review (offline)

This optional step follows the aggregate two-reviewer agreement check in
[ZEEK_ANNOTATOR_AGREEMENT.md](ZEEK_ANNOTATOR_AGREEMENT.md). The existing
aggregate report remains UID-free. The new command produces a **separate,
explicitly requested private worksheet containing Zeek UIDs** for flows where
two complete reviewer annotations disagree.

No labels are adjudicated automatically. Every exported disagreement has
null adjudicated_label and evidence_reference fields, even when one reviewer
labels a flow Attack. The worksheet is NOT a valid annotation-v1 input for
training, and no model, SOC case, traffic, or network operation is performed.

## Windows 3.12.9 — authorized, offline input only

First pin the original conn.log and both completed reviewer files independently
in a private notebook. Use two reviewers who worked without seeing each
other's labels or AI predictions. Then, from the repository root:

```powershell
Get-FileHash "C:/DA005-private/capture-001/conn.log" -Algorithm SHA256
Get-FileHash "C:/DA005-private/capture-001/reviewer-a.json" -Algorithm SHA256
Get-FileHash "C:/DA005-private/capture-001/reviewer-b.json" -Algorithm SHA256

py -3.12 scripts/prepare_zeek_disagreements.py `
  --log "C:/DA005-private/capture-001/conn.log" `
  --annotation-a "C:/DA005-private/capture-001/reviewer-a.json" `
  --annotation-b "C:/DA005-private/capture-001/reviewer-b.json" `
  --expected-log-sha256 "<pinned lowercase log SHA256>" `
  --expected-a-sha256 "<pinned lowercase reviewer A SHA256>" `
  --expected-b-sha256 "<pinned lowercase reviewer B SHA256>" `
  --output "C:/DA005-private/capture-001/disagreements.json" `
  --acknowledge-private-uids
```

The output must be a **new JSON file beside the original private log,
outside Git**. The command rejects symlink inputs, changed SHA-256, invalid
or incomplete UID annotations, reused input paths, oversized data, and an
existing output. It never prints UID values to the terminal. The original
reviewer annotations and raw log are never modified.

The worksheet includes original log/reviewer hashes, a count, and a mapping
from **disagreement UID** to the two original labels and two null review
fields. It does not include IP/timestamp fields, but UIDs themselves may be
sensitive or identify hosts. Keep the worksheet and the separate adjudication
notebook private; do not commit, upload, or share it publicly.

## Manual adjudication protocol

For each disagreement, review separately preserved scenario execution records,
capture timing, and other authorized evidence. Document the adjudicator, date,
evidence reference, reason, and unresolved uncertainty privately. Never choose
a label just because the AI predicted Attack or a majority voted Attack. If
ground truth cannot be independently established, keep the case unresolved;
do not silently map it to Normal.

After adjudication, prepare a **new versioned annotation-v1 JSON** with
complete UID coverage, separately recorded evidence and fresh SHA-256. The
existing model-training manifest must be explicitly updated by the operator;
the worksheet cannot be passed directly as training labels. Do not tune
thresholds on the reserved TEST partition.

The new CLI and regression tests run offline on synthetic Zeek rows in CI.
They do not prove independent reviewers, true attacks, physical Host-only
isolation, real model detection accuracy, or Windows laptop acceptance.
