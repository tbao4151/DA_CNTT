# DA005 — Threshold-free ranking diagnostics for NEW Zeek logs

This read-only, **offline** addition to the existing private
`scripts/evaluate_zeek_new_log_labels.py` evaluation reports
`threshold_free_ranking_metrics` alongside fixed-threshold
Precision/Recall/FPR/F1. It does not train a model, select a threshold,
change UNSW-NB15, generate traffic, create alerts or write SOC cases.

## Interpretation

- **ROC AUC** is the fraction of positive/negative flow pairs ranked correctly,
  with half credit for tied probabilities. It is `null` when either class is
  absent; 0.5 is chance-level *pair ranking*, not a detection guarantee.
- **Average precision (AP)** is a stepwise precision–recall summary: each
  *entire tied-score group* contributes its increase in recall times the
  precision after that group. It is not trapezoidal PR AUC. AP is `null`
  when there are no positive labels. All-equal scores yield AP equal to
  observed positive prevalence.
- **Positive prevalence** and the two class supports accompany the metrics
  because AP is sensitive to prevalence. No test/NEW labels are used to
  choose a model, features, threshold or operating point.
- **Unit of analysis:** one Zeek network flow. Flows from the same host,
  session or scenario are correlated; no host-cluster confidence interval
  is claimed. For small or single-class captures, retain the `null` values
  and report limitations rather than substituting zero.
- The annotation file and its SHA-256 are **operator-supplied**, not
  independently authenticated ground truth. Verify original capture
  provenance, Host-only isolation, session/host-disjoint holdout and
  annotation procedure separately. CI synthetic numbers are not scientific
  performance measurements or operational attack-detection evidence.

## Running on the student Windows computer

Use the existing pinned private inputs and CLI documented in
`docs/ZEEK_OFFLINE_EXPERIMENT.md`. The CLI invocation is unchanged.
Its JSON stdout now contains `threshold_free_ranking_metrics` with
`roc_auc`, `average_precision`, `positive_prevalence`,
`positive_support`, `negative_support` and `tied_score_groups`.
Preserve the JSON and original SHA-256 pins privately outside GitHub.

Synthetic regression only:

```powershell
py -3.12 -m pytest -q tests/test_zeek_ranking_metrics.py tests/test_zeek_new_log_evaluation.py
```

These scores assess **ranking of a fixed offline research model against
supplied labels**; they are not packet-to-alert latency, live SOC
performance, attack confirmation or proof of generalization.
