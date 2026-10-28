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

## Prepare private UID annotation templates (offline helper)

Instead of manually transcribing Zeek UIDs, use the non-network helper on **each**
original, authorized `conn.log`. From the repository root on Windows:

~~~powershell
py -3.12 scripts/prepare_zeek_annotations.py --log "C:/DA005-private/zeek-experiment/train/conn.log" --output "C:/DA005-private/zeek-experiment/train/labels.json"
~~~

The output is a **new** annotation-v1 JSON containing the exact source SHA-256
and every UID mapped to `null` (not 0 or 1). No labels are guessed from
protocol, port, timestamp, IP or AI predictions. Use independent, documented
lab scenario records or analyst review to replace **every** `null` with an
integer `0` (Normal) or `1` (Attack). Do not convert uncertain flows to
Normal merely to fill the template; investigate or exclude/recollect the
capture before research. The tool refuses duplicate UIDs, invalid Zeek logs,
oversized annotation templates, pre-existing outputs and output paths inside
the Git repository. It never overwrites the source log.

Before creating a manifest entry, validate the completed annotation against
the **same unchanged** raw log:

~~~powershell
py -3.12 scripts/prepare_zeek_annotations.py --log "C:/DA005-private/zeek-experiment/train/conn.log" --verify-labels "C:/DA005-private/zeek-experiment/train/labels.json"
~~~

Verification rejects missing/extra UIDs, `null`, booleans, strings,
non-binary labels, duplicate JSON keys, malformed JSON, oversized inputs
and mismatched raw-source SHA-256. It does **not** authenticate the labeler's
independence, scenario authorization or whether an Attack actually occurred.
The labels JSON contains UIDs and belongs in a private folder **outside**
the repository. The manifest still requires separate, truthful session IDs,
host-disjoint split assignments, label methods and private evidence references;
this helper neither creates those nor changes train/validation/test.

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

## Validate a private manifest without training (preflight)

After completing UID annotations and assigning host-disjoint splits in the
private manifest, run this **read-only** preflight first:

~~~powershell
py -3.12 scripts/evaluate_zeek_lab.py --manifest "C:/DA005-private/zeek-experiment/manifest.json" --preflight
~~~

This command reuses the experiment's bounded manifest, SHA-256, annotation,
UID and host/session split checks, then prints JSON with aggregate per-split
Normal/Attack flow counts, host-group counts, session counts and small-sample
warnings. It **does not fit a model, score held-out test predictions, save
reports, generate alerts or contact a network**. Its output deliberately omits
private paths, UIDs, IPs, host names and label-reference strings. It refuses
incomplete labels and invalid splits rather than silently substituting values.

`structural_validation_passed=true` only means the provided files and
declared split structure passed software checks. It does **not** prove that
the VM network was Host-only, that an Attack occurred, that labels are true,
or that a model will converge. With fewer than two host groups in a split,
host-variability diagnostics cannot compare machines within that split.
Keep the untouched test partition sealed until the final planned experiment.
Use exactly one of `--preflight` and `--output`; the existing `--output`
research workflow remains unchanged.

## Optional all-capture declared-CIDR gate (offline, fail-closed)

The standalone scope checker can now also be applied to **every capture** in
the same private experiment manifest. Add one or more explicit `--cidr`
arguments (up to four canonical RFC1918 IPv4 networks, each /16 or narrower)
to **either** `--preflight` or `--output`. The check uses the original,
SHA-256-verified log bytes already loaded for the experiment; an out-of-scope
source or destination in **any** train, validation or test capture refuses
the entire operation before model fitting or report creation.

~~~powershell
py -3.12 scripts/evaluate_zeek_lab.py --manifest "C:/DA005-private/zeek-experiment/manifest.json" --cidr "192.168.56.0/24" --preflight
py -3.12 scripts/evaluate_zeek_lab.py --manifest "C:/DA005-private/zeek-experiment/manifest.json" --cidr "192.168.56.0/24" --output "C:/DA005-private/zeek-experiment/scoped-report.json"
~~~

The CIDR above is illustrative; use the **actual independently verified**
VMware Host-only network(s). Do not expand scope to conceal unexpected
endpoints. The CLI remains backward-compatible when `--cidr` is omitted:
`declared_scope_screened=false` and
`all_endpoints_within_declared_scope=null` explicitly mean **not checked**.
When requested and successful, both fields become `true`; they assert
address membership only, **not** physical network isolation, authorization,
log authenticity, label correctness or AI detection. No CIDR/IP/UID is added
to the aggregate preflight or experiment JSON. This is an opt-in research
safety gate, not a network connection or live traffic control.

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

## Flow-level rate uncertainty (report v3)

Report v3 retains all v2 fields and adds `validation_detection_uncertainty`
and `test_detection_uncertainty`. Each contains **95% Wilson score
intervals** for Attack Precision (TP / (TP + FP)), Attack Recall
(TP / (TP + FN)) and False Positive Rate (FP / (FP + TN)), with explicit
numerator/denominator counts. If the denominator is zero, the estimate
and bounds are JSON `null` (not a fabricated zero). A small-denominator
warning is raised if any of the three denominators is below 30.

**Scientific limitation:** These are *descriptive flow-level* binomial
intervals that assume independent flows. Multiple flows from the same
machine, session or scenario are often correlated, so these intervals can
be **too narrow** and are not host-cluster-adjusted confidence intervals.
Host-disjoint train/validation/test prevents some leakage but does not
make flows within a split independent. Do not claim statistically reliable
real-world detection from these bounds alone. With genuine multi-host
captures, report host/scenario-level variability separately. Held-out
test intervals are computed only after model and threshold selection,
never used for tuning. Synthetic CI results remain non-scientific.

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

## Host-group variability (report v4)

Report v4 retains the v3 Wilson flow-level diagnostics and adds
`validation_host_variability` and `test_host_variability` at the
**fixed, validation-selected threshold**. Each section contains per-group
TP/FP/TN/FN, support, Attack Precision/Recall/FPR and unweighted
across-group min/max/mean of each defined rate. Undefined denominators are
JSON `null`, not zero. A single host group or a group with fewer than
30 flows triggers an explicit warning. The anonymous group numbers are
local to each report and do not identify machines across reports; raw
host-group names, UIDs, IP addresses and label references are omitted.

The `host_group` field is **declared by the operator**, not authenticated.
The report does not verify that host groups are genuinely independent or
that scenario labels are correct. Group means and ranges are descriptive,
not cluster-adjusted confidence intervals; they may be unstable when
groups have different attack prevalence, tiny supports or missing classes.
With only one host group in a split, there is no within-split host
variation to estimate. Do not interpret synthetic CI fixtures as lab
measurements. The test section is computed once after fitting and
validation-only threshold selection; never use test group variability to
choose thresholds, model parameters or collection scenarios.

Keep reports in the private experiment directory. Even aggregated
small-group counts may reveal sensitive details when combined with
external lab notebooks. Record genuine host/scenario provenance and
isolation evidence separately on the student Windows/VMware environment.


## Optional private held-out prediction trace (research, not automated SOC)

After **pre-registering** host-disjoint train/validation/test splits and verifying
independent labels, the experiment can produce a **separate, opt-in private
test-flow trace** instead of the aggregate report. It fits the same train-only
Logistic Regression and validation-selected threshold; test labels do **not**
influence fitting, threshold choice or predicted probabilities.

~~~powershell
py -3.12 scripts/evaluate_zeek_lab.py --manifest "C:/DA005-private/zeek-experiment/manifest.json" --cidr "192.168.56.0/24" --trace-output "C:/DA005-private/zeek-experiment/private-heldout-trace.json"
~~~

The output is a **new, exclusive JSON file** within the private manifest
directory, outside the Git repository. It contains the existing aggregate
research report plus `private_test_trace` v1: for each held-out test flow,
the original source SHA-256, Zeek UID, model Attack probability, fixed-threshold
binary prediction, operator-supplied label and TP/FP/TN/FN outcome. It does not
include raw IP addresses or private label-reference strings. UIDs and per-flow
labels remain sensitive; **never upload this trace to public GitHub**.
Join UID and source SHA to the original privately held conn.log for manual
analyst review. The trace does not create SOC cases, deploy a model, verify
ground truth, run network traffic or produce live alerts.

`--trace-output`, `--output` and `--preflight` are mutually exclusive.
Existing aggregate reports remain unchanged and contain no test-flow UIDs.
The trace is a **one-time held-out analysis**: do not iterate model choices
based on its false positives/false negatives and then report the same test
set as untouched. For further tuning, collect a fresh independently labeled
holdout. Synthetic CI fixtures demonstrate only the software contract.

## Blue Team UI: read-only private held-out prediction review

After running the **existing** offline experiment with `--trace-output`, start the local
Streamlit app (`py -3.12 -m streamlit run app.py`) and navigate to **Cyber Lab · Blue Team**.
Upload one of the original **held-out test** Zeek `conn.log` files, then optionally upload
the private trace JSON in the research review section. Keep both files outside GitHub.

The UI checks the original log SHA-256, exact UID coverage for that log, the
private trace's declared schema, validation-selected threshold, probability/
verdict consistency, unique SHA/UID keys and confusion totals against the
operator-supplied labels. It shows a **read-only**, label-free list of up to 500
research Attack candidates and their actual Zeek IP/timestamps, sorted by
research probability. The trace may include other test captures; this view
does **not** verify their original bytes. Uploading a trace neither fits/loads
a model nor writes alerts, SOC cases, database rows or network traffic.

A passing check only establishes **internal consistency of supplied files**.
It cannot authenticate who trained the model, whether labels are correct, or
whether VMware Host-only was truly isolated. It is NOT live detection and
must not be presented as a deployed AI alert queue. The separate manual
`Unclassified` case action still requires explicit operator confirmation and
does not import a research AI verdict or score. Do not select thresholds or
retrain using the untouched held-out test trace.


## Analyst-confirmed research candidate to local SOC case (offline only)

On the **Cyber Lab · Blue Team** page, load the original held-out test
`conn.log` and the private `--trace-output` JSON together. The read-only
trace review must pass SHA-256, UID coverage, threshold and confusion-count
checks before any candidate is selectable. The analyst can then explicitly
select a predicted-Attack candidate among the **first 500 Zeek rows**, tick
a consent checkbox and press **Mở hồ sơ nghiên cứu Unclassified**.

Only this deliberate click calls `create_research_candidate_case`. The server
revalidates the entire trace and source bytes, verifies that the chosen row is
a predicted-Attack candidate and atomically creates a **New / Unclassified**
case in `runtime/cyber_lab_cases.sqlite3`. Confidence remains null.
The initial audit note records source SHA-256, private trace SHA-256, Zeek UID,
research-only probability and locked validation threshold; operator-supplied
ground-truth labels are **not** copied into the case. The typed Zeek export
continues to require the original source bytes and snapshot consistency.
Dataset Mode and its SQLite store remain untouched.

This is **manual analyst triage of a research hypothesis**, not an AI-to-SOC
automatic alert, authenticated attack, deployed model or real-time detection.
The source file, trace, SQLite and research note are all mutable and not
forensic-grade. Repeated explicit clicks for the same original source SHA-256 and Zeek
UID reuse the first research case (including its original audit note), even if
a later valid research trace changes its threshold. The lookup and insert are
atomic in SQLite, and this is **not** an authentication mechanism. Distinct
source files with the same UID can create distinct research cases; ordinary
manual cases still allow duplicates. Keep private traces/logs/cases outside public GitHub and
do not tune the held-out test based on this review. The student must verify
the workflow on Windows with independently annotated, authorized VMware
Host-only evidence; synthetic CI does not replace that acceptance test.

Developer regression: `py -3.12 -m pytest -q tests/test_zeek_research_triage.py`.


## Private trace source-set consistency (28/10/2026)

The read-only Blue Team private trace reviewer now rejects a report unless its
held-out `provenance.test.source_sha256` list matches **exactly** the source
SHA-256 set in the private per-flow trace and its declared test flow count
matches the number of trace rows. The report and trace feature schema versions
must also agree with the supported Zeek feature contract. This prevents a
self-consistent trace for a different test source from silently appearing under
an unrelated experiment's aggregate provenance. Existing private trace files
created by the official v4 experiment CLI already contain these fields.

This is **internal consistency only**: the JSON, labels, model-training claims,
source collection context and physical Host-only isolation are not
cryptographically authenticated. The reviewer still checks original bytes and
UIDs for only the supplied log, not other test captures. Do not infer real
attack detection or operational alerts from this check.


## Cross-capture normalized flow overlap guard (28/10/2026)

The offline experiment's dataset builder now rejects reuse of the exact
normalized Zeek identity `(uid, event_time_utc, src_ip, src_port, dst_ip,
dst_port, proto)` **between any two declared captures**, even when their
raw log bytes have different SHA-256 values (for example, due to an extra
header comment). The same identity contract is shared with the existing
NEW-log TRAIN/VALIDATION/TEST partition-exclusion screen. The check happens
before model fitting and applies to preflight, evaluation, and private model
export. Failed validation must not create an experiment report.

This is a conservative exact-identity screen only. Rewritten UIDs, times or
endpoints can evade it, and a legitimate repeated UID at a different event
time is not automatically rejected. It cannot authenticate host/session
provenance, ground-truth annotations, physical VMware isolation or the
completeness of the declared capture history. Keep independently pinned
original captures and labels, and never tune using held-out TEST results.
