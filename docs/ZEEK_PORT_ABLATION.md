# DA005 — Offline Zeek port-feature ablation (research only)

This is a **paired software experiment** on one independently pinned, privately
labeled Zeek TRAIN/VALIDATION/TEST manifest. It compares two prespecified
Logistic Regression pipelines on the **same split**:

- **full**: the existing nine Zeek v1 features, including `src_port` and `dst_port`;
- **without_ports**: both port columns are actually excluded by the
  `ColumnTransformer` (not replaced by zeros or imputed), leaving seven
  features. Protocol and service remain, and may still encode lab shortcuts.

Both variants fit imputation, standardization, category encoding and classifier
**on TRAIN only**, choose thresholds independently **on VALIDATION only**, and
score untouched TEST once per variant. This is a descriptive sensitivity
comparison, **not** a causal port-importance estimate. Do not select the
better-looking variant using TEST or claim that port exclusion necessarily
improves generalization. For a confirmatory comparison, preregister variants,
repeat across separately acquired host/session-disjoint datasets, and report
confidence intervals and class supports. A two-flow fixture cannot establish
real attack detection.

## Windows 11 private run

Use Python 3.12.9 and the existing requirements. First retain outside public
Git: genuine authorized Host-only PCAPs, original Zeek logs, independent UID
labels, label-file SHA-256 values, manifest SHA-256, lab scope, Zeek version,
capture/host/session assignments and evidence of physical isolation. The
manifest v1 must contain `labels_sha256` for **every** capture.

Choose the split and variants before viewing TEST. Record the original
manifest hash independently (for example, in a separate lab notebook):

```powershell
$manifest = "C:/DA005-private/zeek-experiment/manifest.json"
$pin = (Get-FileHash -Algorithm SHA256 $manifest).Hash.ToLowerInvariant()
$pin
```

Preflight first:

```powershell
py -3.12 scripts/evaluate_zeek_lab.py `
  --manifest "C:/DA005-private/zeek-experiment/manifest.json" `
  --expected-manifest-sha256 "<INDEPENDENT_MANIFEST_SHA256>" `
  --cidr "<ACTUAL_HOST_ONLY_CIDR>" `
  --strict-input-gates `
  --preflight
```

Then use the **same** independently recorded pin, declared CIDR and gate
settings, writing a NEW private file alongside the manifest:

```powershell
py -3.12 scripts/evaluate_zeek_lab.py `
  --manifest "C:/DA005-private/zeek-experiment/manifest.json" `
  --expected-manifest-sha256 "<INDEPENDENT_MANIFEST_SHA256>" `
  --cidr "<ACTUAL_HOST_ONLY_CIDR>" `
  --strict-input-gates `
  --port-ablation-output "C:/DA005-private/zeek-experiment/port-ablation.json"
```

The command refuses missing manifest pin, strict gates or CIDR, refuses an
existing output, and never modifies the official UNSW-NB15 benchmark, models,
SQLite SOC or Red Team. Optional `--require-originator-ip-disjoint` can be
added **only if** the address-based host-split assumption is scientifically
appropriate (NAT/DHCP can cause false refusals). Keep the exact same flags for
both variants; the command uses the same input split automatically.

The private aggregate JSON contains validation and held-out TEST confusion
counts, Precision, Recall, F1, FPR, validation-selected thresholds, a signed
delta (`without_ports - full`), and source hashes/counts. It intentionally
omits raw IPs, Zeek UIDs, host identifiers and label references. Report
schema version 2 also includes `validation_host_variability` and
`test_host_variability` for **each** variant, reusing the existing
anonymized host-group summarizer. Each group has confusion counts, class-rate
denominators through counts, undefined rates as `null`, and warnings for
fewer than 30 flows or only one declared host group. The anonymous group
numbers are sorted consistently within each variant for a given split, but
are **not authenticated host identities** and must not be joined to other
experiments. Aggregate confusion counts must equal the sum across groups.
Do not use TEST host-level diagnostics to choose features or thresholds.

These descriptive summaries are not cluster-adjusted confidence intervals
and cannot verify the authenticity of operator labels, actual Host-only
isolation or capture provenance. No live collection, automatic alert, operational attack
detection, SOC case creation or event-to-SOC latency is measured.

Synthetic software regression:

```powershell
py -3.12 -m pytest -q tests/test_zeek_port_ablation.py
```

Passing GitHub Ubuntu/Windows CI is **not** acceptance on the student's
Windows 11/VMware lab. Keep the local output and lab notebook privately for
GVHD review; do not publish sensitive evidence in this public repository.

## Paired TEST correctness contingency (29/10/2026)

The optional JSON now includes `paired_test_correctness`: aggregate counts of
`both_correct`, `full_only_correct`, `without_ports_only_correct`, and
`neither_correct` for **the same held-out TEST rows**, plus breakdowns by
operator-supplied normal/attack labels. Both prediction vectors are computed
after their own TRAIN-only fit and VALIDATION-only threshold selection; the
report never stores row-level predictions, IPs, UIDs or timestamps.

This is useful because two variants can have similar aggregate F1 yet make
different errors. Counts are descriptive only: neither paired rows nor their
labels are independently authenticated, flows may be correlated within
sessions, and no p-value, confidence interval, statistical significance,
causal port importance, or deployment winner is asserted. Do not use TEST to
retune either variant. Validate on separately captured host/session-disjoint
data before any scientific performance claim.


## Anonymous paired host-group disagreement (29/10/2026)

The same optional v2 JSON report now includes
`paired_test_correctness.by_anonymous_host_group`. This compares **which**
of the two predeclared models was correct within each operator-declared TEST
host group, not just each model's separate confusion matrix. Only aggregate
four-cell correctness counts and discordant counts are emitted. Groups are
numbered anonymously; raw group names, IPs, UIDs, timestamps and row-level
predictions are not exported.

To avoid exposing correctness for a tiny group by subtracting visible group
counts from overall totals, **all** per-group cells are suppressed whenever
**any** TEST group contains fewer than 30 flows. In that case `groups` is
empty and `all_group_counts_suppressed` is true; overall and class-level
aggregate counts remain as in the earlier report. The 30-flow threshold is a
privacy guard, **not** a sample-size sufficiency guarantee. One group, even
when large, cannot establish generalization. This is descriptive analysis:
flows may be dependent within host/session, group assignments and labels
remain operator-supplied, and no p-value, confidence interval or deployment
winner is asserted. Do not tune using held-out TEST.


## Cross-section small-host privacy correction (29/10/2026)

The paired TEST section already suppresses all per-host correctness cells when
any TEST group contains fewer than 30 flows. However, the same v2 JSON also
contained per-variant VALIDATION/TEST host confusion rows and per-host rate
ranges, which could still expose a small group's labels or predictions.
Suppressing only the paired section was insufficient.

The port-ablation exporter now enables **the same opt-in all-group suppression
for both variants and both splits**. When any group in a split contains fewer
than 30 flows, that split's `validation_host_variability` or
`test_host_variability` returns `groups: []`,
`rate_ranges: null`, `all_group_counts_suppressed: true`, and
`minimum_support_per_group: 30`. The group count, warning flags, and
**overall** validation/TEST metrics remain available. When every group has
at least 30 flows, per-group summaries and rate ranges remain visible.
The generic host-variability function keeps its previous behavior unless
explicitly called with `suppress_small_groups=True`; other callers are not
silently changed. Report schema remains v2, but downstream consumers must
handle `rate_ranges: null` for redacted splits.

This is a best-effort small-group disclosure guard, not differential privacy:
aggregate metrics, known external information, repeated overlapping reports,
or data access outside this JSON can still reveal sensitive facts. Keep all
lab evidence and individual labels private. No model, threshold, UNSW baseline,
SQLite case, network activity, or live detection claim changes.
