# DA005 — Independent Zeek annotation agreement (offline)

This optional Blue Team research quality check compares **two independently
completed** private annotation-v1 files against the **same unchanged** Zeek
ASCII `conn.log`. It never generates ground-truth labels, adjudicates
disagreements, trains a model, scores attacks, creates SOC cases or sends traffic.

Use two reviewers who annotate without seeing each other's labels or AI scores.
Record each reviewer's identity, method, independent scenario evidence and
review time in a **private lab notebook**. The program cannot verify that the
reviewers are independent or that either label is correct.

For an authorized student-owned VMware Host-only capture, first create two
separate templates with `scripts/prepare_zeek_annotations.py`. Have reviewers
complete them separately (all UIDs must be independently labeled 0 or 1).
Uncertain flows require investigation or a new capture; do not silently
turn unknown into Normal. Keep both completed files and the original log
outside Git, and pin each SHA-256 separately before running this command:

```powershell
Get-FileHash "C:/DA005-private/capture-001/conn.log" -Algorithm SHA256
Get-FileHash "C:/DA005-private/capture-001/reviewer-a.json" -Algorithm SHA256
Get-FileHash "C:/DA005-private/capture-001/reviewer-b.json" -Algorithm SHA256

py -3.12 scripts/review_zeek_annotation_agreement.py `
  --log "C:/DA005-private/capture-001/conn.log" `
  --annotation-a "C:/DA005-private/capture-001/reviewer-a.json" `
  --annotation-b "C:/DA005-private/capture-001/reviewer-b.json" `
  --expected-log-sha256 "<independently pinned lowercase log SHA256>" `
  --expected-a-sha256 "<independently pinned lowercase reviewer A SHA256>" `
  --expected-b-sha256 "<independently pinned lowercase reviewer B SHA256>" `
  --output "C:/DA005-private/capture-001/agreement.json"
```

Output is a new, exclusively created private JSON **beside the original log**.
It contains only source/annotation hashes, aggregate 2×2 reviewer counts,
agreement rate, Cohen's kappa, and explicit unverifiable-claim flags. It
contains no UIDs, IPs, individual labels, names or disagreement list.
The original inputs remain unchanged. A failed validation does not create
the report. Files inside the repository, direct symlinks, oversized inputs,
duplicate JSON keys, missing/extra UIDs, invalid binary labels, mismatched
SHA-256 and existing output paths are rejected.

Interpretation: observed agreement is the fraction of UIDs with matching
labels. Cohen's kappa adjusts for expected chance agreement based on the
two reviewers' marginal label distributions. Kappa is `null` if expected
chance agreement is exactly one (e.g., both label every flow Normal).
Kappa can be negative and can be unstable for small, imbalanced or highly
correlated flow samples. Report the 2×2 counts and class prevalence, not
just kappa. Agreement is **not** a measure of detection accuracy, independent
ground truth, authorization or physical network isolation.

Resolve disagreements only using separately preserved, independently
verified scenario evidence and a documented adjudication protocol. Never
automatically replace a reviewer file with consensus or use a reserved TEST
partition to tune model thresholds. Any adjudicated labels require a new
versioned private annotation file, new pinned SHA-256 and explicit provenance
in the experiment manifest. The existing `evaluate_zeek_lab.py` pipeline
continues to consume one separately selected, fully annotated file per
capture; this agreement tool does not change it.

Synthetic pytest/CI runs validate software behavior only. Genuine Windows
3.12.9, VMware Host-only capture, independent labeling and lab detection
performance remain separate student acceptance tasks.
