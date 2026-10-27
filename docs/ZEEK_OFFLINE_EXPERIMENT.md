# DA005 Cyber Lab — offline Zeek experiment CLI (research only)

This command runs a **local, offline** Logistic Regression experiment on
independently annotated Zeek ASCII conn.log files. It does **not** capture
traffic, create attacks, save a deployable model, generate alerts, or touch
Dataset Mode's UNSW-NB15 benchmark/SOC database. Synthetic CI fixtures are
software tests, **not** evidence of real attack-detection performance.

## Prepare evidence before running

On student-owned, authorized VMware **Host-only** environments, preserve the
original Zeek conn.log bytes, record Zeek version, VM/host identity,
isolation settings, time window, scenario/normal activity and independent
labeling evidence. Use **at least three distinct host groups**, pre-assign
train/validation/test by host **before** viewing test results and keep test
untouched for one final evaluation. Each split needs both Normal (0) and
Attack (1) labels. Assign labels from independent scenario/analyst evidence,
**not** model predictions or inferred from a port or protocol. Never upload
private logs, IP addresses, annotation files or lab notebooks to GitHub.

Create a **private folder outside the Git repository**, e.g.
C:/DA005-private/zeek-experiment/, containing the following files. Use
relative POSIX-style forward slashes in JSON paths, including on Windows.

Manifest v1 (illustrative placeholders, not a runnable lab result):

~~~json
{
  "manifest_version": 1,
  "captures": [
    {
      "log_path": "train/conn.log",
      "labels_path": "train/labels.json",
      "source_sha256": "<actual lowercase 64-character SHA-256>",
      "session_id": "train-001",
      "host_group": "vm-group-train",
      "split": "train",
      "label_method": "controlled_scenario_record",
      "label_reference": "private-notebook-train-001"
    },
    {
      "log_path": "validation/conn.log",
      "labels_path": "validation/labels.json",
      "source_sha256": "<actual validation SHA-256>",
      "session_id": "validation-001",
      "host_group": "vm-group-validation",
      "split": "validation",
      "label_method": "manual_analyst_review",
      "label_reference": "private-notebook-validation-001"
    },
    {
      "log_path": "test/conn.log",
      "labels_path": "test/labels.json",
      "source_sha256": "<actual test SHA-256>",
      "session_id": "test-001",
      "host_group": "vm-group-test",
      "split": "test",
      "label_method": "controlled_scenario_record",
      "label_reference": "private-notebook-test-001"
    }
  ]
}
~~~

Each labels.json must include **every UID in its corresponding conn.log**
exactly once, with independently assigned binary integer labels (not booleans):

~~~json
{
  "source_sha256": "<same SHA-256 as corresponding conn.log>",
  "labels_by_uid": {
    "<actual Zeek UID for a normal flow>": 0,
    "<actual Zeek UID for an independently confirmed test scenario>": 1
  }
}
~~~

The placeholders are format illustrations only. Do not fabricate UIDs,
ground truth or digests. On Windows, calculate exact source hashes with
Get-FileHash -Algorithm SHA256 PATH_TO_CONN_LOG and use lowercase hex in JSON.

## Execute on Windows (Python 3.12.9)

From the repository root after installing requirements.txt:

~~~powershell
py -3.12 scripts/evaluate_zeek_lab.py --manifest "C:/DA005-private/zeek-experiment/manifest.json" --output "C:/DA005-private/zeek-experiment/first-report.json"
~~~

Output must be a **new** JSON file inside the private manifest directory;
existing reports are never overwritten. The CLI reads only local files,
refuses absolute/traversal/symlink escapes in input paths, caps each Zeek log
at 15 MiB, each annotation at 2 MiB, manifest at 256 KiB, 3–30 captures
and 30,000 total flows. It rejects duplicate JSON keys, mismatched hashes,
missing/extra UID labels and cross-split host reuse. Invalid inputs do not
create reports. It does not infer labels or auto-select train/test splits.

## Descriptive probability quality (report v2)

The offline report also includes `validation_probability_diagnostics` and
`test_probability_diagnostics`, calculated from the corresponding split's
predicted Attack probabilities and independently supplied labels. Each contains
the **Brier score** (mean squared probabilistic error, lower is better), a
five-bin **Expected Calibration Error** (ECE, lower is better), prevalence,
sample size and fixed-width reliability bins (counts, mean predicted Attack
probability, observed Attack frequency). Empty bins have `null` averages;
the rightmost bin includes probability 1.0. A `small_sample_warning` is raised
for fewer than 100 flows or any occupied bin containing fewer than 20 flows.

These are **descriptive diagnostics, not probability calibration**. ECE depends
on binning and sample size; good Brier/ECE on a tiny or shifted dataset does not
establish reliable deployment probabilities. The validation threshold is still
chosen exclusively by validation F1 and false-positive tie-breaking, without
using these diagnostics. The held-out test diagnostics are computed **once,
after model/threshold selection** and must not be used to retune or recalibrate
the model. Report v2 preserves the previous `validation_metrics`,
`test_metrics` and provenance fields. It contains no raw IP/UID or
label-reference strings, but **aggregated bins can still reveal information
about very small groups**; keep experiment reports private.

The report includes SHA-256 source hashes, train/validation/test support,
confusion counts, Precision/Recall/F1/FPR and validation-selected threshold.
It intentionally excludes raw IPs, UIDs and label-reference strings. The
report is unsigned; hashes do not prove the truth of labels; the Logistic
Regression probabilities are not calibrated. Do not treat tiny sample
scores as deployable detection performance. Preserve experiment protocol,
original files and final test result separately; do not repeatedly tune on test.

Synthetic-only developer regression:

~~~powershell
py -3.12 -m pytest -q tests/test_zeek_lab_cli.py
~~~

Next: collect genuine independently labeled captures, assess calibration,
false positives and host/scenario shift before AI-to-SOC alert integration.
