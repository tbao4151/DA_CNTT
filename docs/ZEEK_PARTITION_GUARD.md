# DA005 — Private declared-partition non-reuse gate (offline)

This read-only preflight checks that a **new** Zeek `conn.log` is not byte-for-byte identical to any capture declared in the **original private TRAIN, VALIDATION or held-out TEST** manifest. It additionally binds the experiment manifest to the pinned Zeek research model, checks that the model's TRAIN and VALIDATION source lists match the actual, hash-checked experiment captures, and validates all annotations and host-disjoint splits through the existing experiment loader. This is a research integrity check, not attack detection.

Before running, independently record three SHA-256 values in a separate private notebook: the exported JSON model, the **unchanged experiment manifest v1**, and the new capture. Keep the original annotated TRAIN/VALIDATION/TEST logs and annotation files accessible at the relative paths declared by that manifest. Use the **actual** authorized VMware Host-only CIDR; do not broaden it to hide unexpected endpoints. Keep all inputs outside the public Git repository.

```powershell
py -3.12 scripts/check_zeek_partition_exclusion.py `
  --model "C:/DA005-private/zeek-experiment/zeek-research-model.json" `
  --expected-model-sha256 "<PINNED_MODEL_SHA256>" `
  --manifest "C:/DA005-private/zeek-experiment/manifest.json" `
  --expected-manifest-sha256 "<PINNED_MANIFEST_SHA256>" `
  --log "C:/DA005-private/new-capture/conn.log" `
  --expected-log-sha256 "<PINNED_NEW_LOG_SHA256>" `
  --cidr "192.168.56.0/24"
```

The command refuses modified model/manifest/new-log bytes, malformed or incomplete annotations, host-disjoint split violations, unexpected network scope, mismatched model/manifest source provenance and exact-byte reuse of **any** declared split (including TEST). It writes no files, does not score TEST, train a model, send packets, open sockets, create SOC cases or generate operational alerts. On success it prints an aggregate JSON summary with counts and digests, but no raw IPs, UIDs, label references or paths. Preserve the output in the private lab notebook if needed.

**Scientific limitations:** A successful check is conditional on the operator-declared and independently pinned manifest being complete and historically accurate. SHA-256 only detects identical bytes; the same network flows can be re-encoded, merged, split or recaptured and pass. The software cannot authenticate experiment registration dates, host identity, independent label truth, capture authenticity, physical VMware isolation, model authorship or predictive accuracy. The summary explicitly reports these limitations as `false`. The existing `score_zeek_new_log.py` report deliberately retains `test_partition_exclusion_verified=false`; this separate preflight does **not** silently upgrade or rewrite that report. For a defensible study, preserve the preregistered split plan, timestamped scenario records and independent VM screenshots outside GitHub.

Synthetic regression checks (not Windows/VMware evidence):

```powershell
py -3.12 -m pytest -q tests/test_zeek_partition_guard.py
```
