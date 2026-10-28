# DA005 — Finalize private Zeek manual adjudication (offline)

This step converts a **manually completed** private disagreement worksheet into a
new, complete annotation-v1 file accepted by the existing Zeek research input
contract. It does not invent Attack labels, use AI predictions, authenticate
scenario evidence, prove annotator independence, or modify original annotations.
It is not an operational alert, a lab capture, or a claim of verified ground truth.

## Preconditions

Use an authorized VMware Host-only capture kept **outside Git**, with the
original \`conn.log\`, two independent complete annotation-v1 files and the
worksheet created by \`scripts/prepare_zeek_disagreements.py\`. Keep a separate
private notebook recording each source SHA-256 and evidence of lab authorization,
isolation, scenario execution, annotator identity and time.

For every UID in \`disagreements_by_uid\`, the adjudicator must manually fill
\`adjudicated_label\` with integer \`0\` or \`1\` and \`evidence_reference\` with a
nonempty private notebook reference (1–512 printable characters). Do not change
UID keys, reviewer labels, provenance fields or safety flags. If evidence is
inconclusive, leave the UID unresolved and **do not run finalization**; do not
silently map unknown events to Normal. Agreed reviewer labels are copied as-is
under explicit operator responsibility; agreement alone is not ground truth.

Pin the **completed worksheet SHA-256 after editing**, independently from the
worksheet itself. Original hashes of log and reviewer files must also be pinned.

## Windows Python 3.12.9

From the repository root, after reviewing and saving all four original files:

~~~powershell
Get-FileHash "C:/DA005-private/capture-001/disagreements.json" -Algorithm SHA256

py -3.12 scripts/finalize_zeek_adjudication.py \`
  --log "C:/DA005-private/capture-001/conn.log" \`
  --annotation-a "C:/DA005-private/capture-001/reviewer-a.json" \`
  --annotation-b "C:/DA005-private/capture-001/reviewer-b.json" \`
  --worksheet "C:/DA005-private/capture-001/disagreements.json" \`
  --expected-log-sha256 "<pinned lowercase log sha256>" \`
  --expected-a-sha256 "<pinned lowercase A sha256>" \`
  --expected-b-sha256 "<pinned lowercase B sha256>" \`
  --expected-worksheet-sha256 "<pinned lowercase completed worksheet sha256>" \`
  --output "C:/DA005-private/capture-001/adjudicated-v2.json" \`
  --confirm-manual-evidence-review

py -3.12 scripts/prepare_zeek_annotations.py \`
  --log "C:/DA005-private/capture-001/conn.log" \`
  --verify-labels "C:/DA005-private/capture-001/adjudicated-v2.json"
~~~

The output must be a **new file beside the original log**, outside the
repository. Existing outputs and symlink inputs are rejected. The command
checks all four independent SHA-256 values, reconstructs the original
disagreement template from the log and reviewer files, rejects altered reviewer
labels/UIDs/metadata, and requires an explicit decision plus evidence reference
for every disagreement. It writes only the exact annotation-v1 contract:
\`source_sha256\` and \`labels_by_uid\`. It does not print UIDs.

Pin the newly generated annotation SHA-256 independently. Preserve the original
log, both original reviews, the completed worksheet, its evidence notebook and
the new annotation as **distinct immutable versions**. An operator must
explicitly update any experiment manifest and preregister TRAIN/VALIDATION/TEST
host/session splits; the tool never modifies a manifest, a model or SQLite.

## Research limitations

A completed binary annotation is **not proof of attack ground truth**. The
program checks only schema, provenance consistency and the presence of a
manual evidence reference; it cannot inspect the underlying evidence, confirm
the adjudicator reviewed it, or establish VMware isolation. Reviewer agreement
may still be wrong on UIDs that were never disputed. Do not use the reserved
TEST partition for threshold selection or report synthetic CI metrics as
real-world detection. Before a defense claim, run the lab experiment on the
student's Windows/VMware machine, retain private artifacts, and evaluate
held-out labels independently.
