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
omits raw IPs, Zeek UIDs, host identifiers and label references. It does not
verify the authenticity of operator labels, actual Host-only isolation or
capture provenance. No live collection, automatic alert, operational attack
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
