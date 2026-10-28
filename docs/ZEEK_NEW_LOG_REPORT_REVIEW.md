# DA005 — Private new-log prediction report verification (offline only)

This independent, read-only check recomputes every research score from the
**original** Zeek ASCII `conn.log` and the **independently SHA-256-pinned**
Zeek JSON model. It compares the full saved prediction JSON against the
recomputed output, including UID, source/destination IP/port, Zeek timestamps,
probabilities, candidate flags, source/model hashes, schema, threshold and
research-only safety flags. It rejects changed, missing, additional or
reordered records, duplicate JSON keys, non-finite numbers, invalid UTF-8
and reports larger than 16 MiB. It does not use ground-truth labels.

Prerequisites: Python 3.12.9, installed dependencies, an authorized private
Host-only capture, the original source and model retained outside Git, a
`new-predictions.json` previously created with
`scripts/score_zeek_new_log.py`, and independently recorded model/capture
SHA-256 digests. Run from the repository root on Windows:

```powershell
py -3.12 scripts/verify_zeek_new_log_report.py `
  --model "C:/DA005-private/zeek-experiment/zeek-research-model.json" `
  --expected-model-sha256 "<64 lowercase hex characters>" `
  --log "C:/DA005-private/new-capture/conn.log" `
  --expected-log-sha256 "<64 lowercase hex characters>" `
  --report "C:/DA005-private/new-capture/new-predictions.json" `
  --cidr "192.168.56.0/24"
```

Use the **actual** authorized RFC1918 Host-only CIDR, not the example. The
report must be in the same private directory as the capture. All three inputs
must be regular files outside the repository, with no direct symlinks. The
command reads bounded inputs, writes **nothing**, prints only counts and the
SHA-256 of the verified report, and returns nonzero on any inconsistency.
Keep all original files and the reported digest in the private lab notebook.
The report includes private IPs and Zeek UIDs; never upload it publicly.

Passing this check establishes only **internal consistency** of the report
with the pinned bytes and declared CIDR. It does not authenticate the model
author, labels, physical VMware isolation, capture origin, model generalization,
or exclusion of the preregistered held-out TEST capture. It does not measure
Precision, Recall, FPR or latency; it creates **no** SOC alert or case, and
does not execute Red Team activity. Do not claim verified attack detection.

Run the synthetic regression tests with:

```powershell
py -3.12 -m pytest -q tests/test_zeek_new_log_review.py
```

These tests are software checks only. Student-run Windows and VMware
acceptance remain separate, unverified milestones.
