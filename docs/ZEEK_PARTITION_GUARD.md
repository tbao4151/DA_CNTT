# DA005 — Private declared-partition non-reuse gate (offline)

This read-only preflight checks that a **new** Zeek `conn.log` is not byte-for-byte identical to any capture declared in the **original private TRAIN, VALIDATION or held-out TEST** manifest. It also compares a conservative normalized identity (Zeek UID, UTC timestamp, source/destination IP and port, protocol) against every flow in those original captures, refusing matching identities even when a log was re-encoded with different headers or comments. It additionally binds the experiment manifest to the pinned Zeek research model, checks that the model's TRAIN and VALIDATION source lists match the actual, hash-checked experiment captures, and validates all annotations and host-disjoint splits through the existing experiment loader. This is a research integrity check, not attack detection.

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

The command refuses modified model/manifest/new-log bytes, malformed or incomplete annotations, host-disjoint split violations, unexpected network scope, mismatched model/manifest source provenance and exact-byte or normalized UID/time/five-tuple reuse of **any** declared split (including TEST). It writes no files, does not score TEST, train a model, send packets, open sockets, create SOC cases or generate operational alerts. On success it prints an aggregate JSON summary with counts and digests, but no raw IPs, UIDs, label references or paths. Preserve the output in the private lab notebook if needed.

**Scientific limitations:** A successful check is conditional on the operator-declared and independently pinned manifest being complete and historically accurate. SHA-256 only detects identical bytes. The additional normalized identity check detects re-encoding that preserves UID, UTC timestamp and five-tuple, but a changed UID/timestamp/endpoint, merged or split flow, or a recapture can still pass. This is **not** semantic flow non-reuse proof. Conservative identity matches may also reject unrelated flows with coincident identifiers. The software cannot authenticate experiment registration dates, host identity, independent label truth, capture authenticity, physical VMware isolation, model authorship or predictive accuracy. The summary explicitly reports these limitations as `false`. The existing `score_zeek_new_log.py` report deliberately retains `test_partition_exclusion_verified=false`; this separate preflight does **not** silently upgrade or rewrite that report. For a defensible study, preserve the preregistered split plan, timestamped scenario records and independent VM screenshots outside GitHub.

Synthetic regression checks (not Windows/VMware evidence):

```powershell
py -3.12 -m pytest -q tests/test_zeek_partition_guard.py
```

The read-only result includes `declared_flow_identity_nonreuse_checked=true` when the original capture bytes were supplied. `semantic_flow_nonreuse_verified` remains `false`. The optional library API arguments preserve existing exact-byte-only callers; the private preflight CLI supplies both originals and new bytes and therefore performs the stronger screen. The same screen runs in the pinned-manifest manual SOC triage path before a SQLite write. All checks remain offline and based on operator-provided provenance.
