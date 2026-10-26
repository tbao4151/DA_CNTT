# DA005 — Roadmap (living plan)

## Goal
Build a defensible, reproducible Mini-SIEM research prototype for network-flow
intrusion detection. A working dashboard alone is not evidence of model quality.

## Prioritized milestones
1. **Foundation**: validated dataset reader, offline tests, CI, read-only dataset dashboard.
2. **Model reproducibility**: persist versioned training pipeline, reproducible metrics
   on untouched official test split; confusion matrix, precision/recall/F1, PR-AUC.
3. **Prediction pipeline**: validated batch inference; never use label/attack_cat/id
   as features; record model version and confidence with every prediction.
4. **SOC triage**: durable alert store, analyst state transitions, evidence and notes;
   clearly distinguish predicted alerts from known dataset ground truth.
5. **Demo & defense**: threat model, architecture diagram, reproducible demo, tests,
   limitations, ablation/comparison and explanation of false positives.

## Non-goals
- No claim of real-time packet capture, production SOC capability or proven detection
  on unseen enterprise traffic.
- Do not tune on the official test split.
- No fabricated results or synthetic alerts presented as model output.
- No exposed public dashboard or destructive automated response.

## Working rules
Every milestone requires code, tests, documented limitations and a verified CI run.
Keep changes in reviewed PRs where practical. Record status in PROGRESS.md.
