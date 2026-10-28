# DA005 — Private NEW-log operator-labeled evaluation (offline only)

This optional Blue Team research step evaluates fixed, recomputed predictions
on a NEW operator-owned Zeek conn.log against a separate per-UID binary
annotation file. It is not a live detector, verified attack label, automated
SOC alert or independent scientific benchmark. No model is fitted and the
validation-selected threshold is never changed.

## Required private evidence on Windows

Keep outside Git (for example C:/DA005-private): the original Zeek model JSON,
pre-registered experiment manifest and ALL original TRAIN/VALIDATION/TEST
captures/annotations, an authorized NEW conn.log, its saved research prediction
report, and a completed annotation JSON for the NEW log. Preserve separately
recorded SHA-256 values for model, manifest, NEW log and NEW annotations.
The report is verified by complete re-scoring, not trusted as supplied.

First generate a template with null labels, then independently annotate
every UID using documented, authorized scenario/analyst evidence:

~~~powershell
py -3.12 scripts/prepare_zeek_annotations.py --log "C:/DA005-private/new-capture/conn.log" --output "C:/DA005-private/new-capture/new-labels.json"
~~~

Do not invent labels. Record the annotator, capture session, scenario timing,
VMware Host-only network settings and Zeek version separately. Verify all
annotations are 0/1 and that the source digest matches the original bytes:

~~~powershell
py -3.12 scripts/prepare_zeek_annotations.py --log "C:/DA005-private/new-capture/conn.log" --verify-labels "C:/DA005-private/new-capture/new-labels.json"
Get-FileHash "C:/DA005-private/new-capture/new-labels.json" -Algorithm SHA256
~~~

Then run the read-only evaluation with independently recorded hashes and the
actual owned Host-only CIDR (the subnet below is illustrative):

~~~powershell
py -3.12 scripts/evaluate_zeek_new_log_labels.py --model "C:/DA005-private/zeek-experiment/model.json" --expected-model-sha256 "<MODEL_SHA256>" --manifest "C:/DA005-private/zeek-experiment/manifest.json" --expected-manifest-sha256 "<MANIFEST_SHA256>" --log "C:/DA005-private/new-capture/conn.log" --expected-log-sha256 "<NEW_LOG_SHA256>" --report "C:/DA005-private/new-capture/new-predictions.json" --annotations "C:/DA005-private/new-capture/new-labels.json" --expected-annotations-sha256 "<NEW_ANNOTATIONS_SHA256>" --cidr "192.168.56.0/24"
~~~

The command prints only aggregate counts and metrics to stdout: TP/FP/TN/FN,
attack precision, recall, F1, false-positive rate, and descriptive flow-level
Wilson intervals. Undefined denominators yield JSON null, not fabricated zero.
No source IP, UID, individual label, private path or case is printed. Redirect
stdout to a private evidence file only if required.

It refuses altered or malformed report/annotations, duplicate keys, missing
or extra UIDs, bool/nonbinary labels, mismatched independent hashes, invalid
scope, exact-byte TRAIN/VALIDATION/TEST reuse, and conservative normalized
UID/time/five-tuple overlap with the original declared captures. The original
manifest and all its captures/annotations must be available.

## Scientific limits

The labels are operator supplied, not authenticated by the software. The
manifest is operator supplied and may not reflect the actual experiment history.
A successful normalized identity screen does not establish semantic independence
when UIDs/times/endpoints have changed. Flow-level Wilson intervals assume
independence and are not adjusted for correlated flows within hosts/sessions.
A tiny or single-class NEW capture may yield undefined metrics; this is
reported explicitly. Never use these NEW-log evaluation results to select
a model, features or threshold and then call the same data held-out.

The command does not measure detection latency; event timestamps are not
inference wall-clock measurements. It does not prove physical Host-only
isolation, attack truth, model authorship, generalization or deployment
readiness. Preserve the existing UNSW-NB15 Dataset Mode benchmark unchanged.

Software regression tests:

~~~powershell
py -3.12 -m pytest -q tests/test_zeek_new_log_evaluation.py
~~~

GitHub CI synthetic fixtures are not Windows laptop/VMware experimental results.
