# DA005 — Verify a finalized private Zeek label chain (offline)

This **read-only** tool independently reopens the five original files: the
Zeek ASCII `conn.log`, reviewer A annotation-v1, reviewer B annotation-v1,
completed private disagreement worksheet, and the finalized annotation-v1.
It recomputes every final label from the manual decisions and checks the
final annotation against that reconstruction. All five exact SHA-256 values
must have been recorded independently **before** verification.

This is a research-integrity check, **not** independent attack ground truth,
proof of two blind annotators, proof of VMware Host-only isolation, a live
detector, or a new model evaluation. The output is an aggregate JSON summary
only; no UIDs, IPs, labels by UID, file paths or notebook references are
printed or written.

## Run on Windows Python 3.12.9

Keep all five original files in the same private capture directory **outside
Git**, and independently record their hashes in a lab notebook:

~~~powershell
Get-FileHash "C:/DA005-private/capture-001/adjudicated-v2.json" -Algorithm SHA256

py -3.12 scripts/verify_zeek_final_labels.py `
  --log "C:/DA005-private/capture-001/conn.log" `
  --annotation-a "C:/DA005-private/capture-001/reviewer-a.json" `
  --annotation-b "C:/DA005-private/capture-001/reviewer-b.json" `
  --worksheet "C:/DA005-private/capture-001/disagreements.json" `
  --final-annotation "C:/DA005-private/capture-001/adjudicated-v2.json" `
  --expected-log-sha256 "<pinned lowercase log SHA-256>" `
  --expected-a-sha256 "<pinned lowercase reviewer A SHA-256>" `
  --expected-b-sha256 "<pinned lowercase reviewer B SHA-256>" `
  --expected-worksheet-sha256 "<pinned lowercase completed worksheet SHA-256>" `
  --expected-final-sha256 "<pinned lowercase finalized annotation SHA-256>"
~~~

Replace every placeholder with the real 64-character lowercase SHA-256. Do not
place private logs, UIDs, annotations or notebook evidence in GitHub issues or
PRs. The tool refuses missing, oversized, aliased, symlinked, non-private or
changed inputs. It never edits source files, creates a report file, trains AI,
writes SQLite or contacts a network.

A successful run returns `chain_consistency_verified: true`, aggregate
flow/Normal/Attack counts, source hashes and explicit
`ground_truth_verified: false`,
`annotator_independence_verified: false`, and
`host_only_isolation_verified: false`. Re-pinning a modified final file
does not bypass recomputation: the finalized UID labels must still exactly
match the original reviewers and every manual worksheet decision.

## Research protocol

1. Obtain an authorized Host-only Zeek capture and independently document the
   scenario evidence, network isolation, session and host group.
2. Produce two complete annotations without sharing predictions or reviewer
   answers; review disagreements manually with external evidence.
3. Finalize using `scripts/finalize_zeek_adjudication.py`, preserve the five
   immutable versions, and pin their hashes separately.
4. Run this verifier and retain its stdout privately with the notebook.
5. Only then reference the finalized annotation from a **pre-registered**
   host/session-disjoint experiment manifest. Keep held-out TEST untouched
   until final evaluation and never use AI predictions to decide labels.

Limitations: both reviewers can agree on an incorrect label; a worksheet
reference can point to nonexistent evidence; an operator can falsify all
source files and independently pinned hashes. SHA-256 and consistency checks
cannot authenticate physical events or prove attack occurrence. The tool
does not inspect private evidence content. Synthetic CI tests do not count
as Windows/VMware acceptance or measured detection accuracy.
