# DA005 — Private Zeek research model JSON (non-deployable)

This opt-in, **offline-only** export preserves a fitted Zeek Logistic Regression
baseline as **data-only JSON**. It is not joblib/pickle, does not deserialize
Python objects, and does not touch the official UNSW-NB15 model or Dataset Mode.
The export fits preprocessing/classifier on **TRAIN only**, locks the threshold
using **VALIDATION only**, and does **not score TEST**. The input contract still
validates the presence and structure of the pre-registered test split, without
using its features or labels for training, threshold selection or output.

From the repository root on Windows with Python 3.12.9 and dependencies installed:

```powershell
py -3.12 scripts/export_zeek_model.py `
  --manifest "C:/DA005-private/zeek-experiment/manifest.json" `
  --cidr "192.168.56.0/24" `
  --output "C:/DA005-private/zeek-experiment/zeek-research-model.json"
```

Replace the example CIDR with the **independently verified actual VMware
Host-only subnet**. Every train/validation/test capture must pass the strict
declared-CIDR membership gate. The new output must remain inside the private
manifest directory **outside the Git repository**; the CLI refuses overwrite,
malformed inputs and out-of-scope endpoints. It prints the SHA-256 of the
exact output bytes. Record that digest independently with the capture/label
evidence; a checksum is **not a digital signature or proof of authorship**.

The JSON includes versioned Zeek feature columns, training and validation
source digests, the manifest digest, locked validation threshold, fitted
categorical contributions and numeric imputation/scaling coefficients. It
contains no UIDs, IP addresses, labels, per-flow predictions or test metrics.
It does not include the test source list. There is no model file execution,
network traffic, automatic alert, SOC case creation, or Red Team activity.

`src/blue_team_ai/model_artifact.py` also provides an internal deterministic
scorer for already validated **feature rows**. Synthetic regression tests
compare its probabilities with the actual fitted scikit-learn pipeline,
including missing numeric measurements and unseen categories. This scorer is
**not a deployed inference service**: no untrusted file loader, artifact
signature verification, fresh-capture CLI, operational SOC alert or runtime
model trust gate is implemented. Do not manually use a JSON model obtained
from another party without independent provenance verification.

The JSON export has a finite versioned contract but is not authenticated;
a person who can replace both the file and its recorded checksum can forge
them. The source/manifest hashes do not prove the VMware isolation, lab
authorization, independent label truth, or attack-detection performance.
Synthetic CI success is software evidence only. The next steps are an
explicit expected-digest loader, inference on **new** authorized Zeek logs
(without test labels), controlled analyst review and measured latency.
Never tune the locked threshold on held-out TEST.

If writing is interrupted, the newly created output may be incomplete.
The CLI never silently overwrites it: inspect the file, preserve any evidence
needed, and select a **different new output path** for another run.


## Independently pinned private model verifier (28/10/2026)

After exporting a private JSON model, preserve the printed SHA-256 in a
**separate trusted experiment notebook or record**, not in the model's folder
as a self-asserted source of truth. Verify on Windows before any future scoring:

```powershell
py -3.12 scripts/verify_zeek_model.py `
  --model "C:/DA005-private/zeek-experiment/zeek-research-model.json" `
  --expected-sha256 "<64 lowercase hex digits recorded independently>"
```

The read-only verifier refuses missing/incorrect digests, direct symlinks,
non-regular files, files larger than 2 MiB, duplicate JSON keys (including
nested duplicates), non-standard NaN/Infinity, invalid UTF-8 and incompatible
artifact schemas. It checks SHA-256 **before JSON parsing**. The model must
remain outside the Git repository. No pickle/joblib is loaded, no traffic
is scored and no alert/SOC record is created. This is a prerequisite for
future *offline new-log inference*, **not** that inference itself.

A checksum comparison only binds the bytes to the independently supplied
digest; it does not authenticate the original exporter or prevent someone
who can replace both the file and the independent record from forging it.
The directory containing the model must be trusted, particularly on Windows
where a filesystem race or parent-directory junction is not fully prevented
by the direct-symlink check. The independent label provenance, actual Host-only
isolation, authorization, held-out evaluation and Windows acceptance are still
required. Synthetic CI tests are not genuine attack-detection evidence.

## New-log scoring follow-up (28/10/2026)

The previously planned private, bounded new-log inference CLI is now implemented
in [score_zeek_new_log.py](../scripts/score_zeek_new_log.py) and documented in
[ZEEK_NEW_LOG_OFFLINE_INFERENCE.md](ZEEK_NEW_LOG_OFFLINE_INFERENCE.md).
[PR #87](https://github.com/tbao4151/DA_CNTT/pull/87) passed its final-head
and post-merge main CI. This does **not** validate actual student Host-only
capture, independent labels, exclusion of the reserved TEST set, or
operational detection; no automated SOC alert is produced.

## Zeek v1 numeric type gate (29/10/2026)

The offline TRAIN/VALIDATION/TEST research baseline and direct data-only JSON model scorer now share a strict numeric feature validator. `src_port` and `dst_port` must be exact Python integers in 0..65535; Zeek byte/packet counts must be exact nonnegative integers (or `None` when absent); duration may be a finite nonnegative integer/float (or `None`). The model-input safety ceiling remains 10^12 for counts and duration. Booleans, fractional ports/counts, out-of-range values and non-finite durations fail closed. Optional missing measurements are **not** coerced to zero. No feature order, model weights, validation-selected threshold or UNSW-NB15 benchmark is changed.

This gate protects direct Python API callers from bypassing the original Zeek parser's type contract with manually constructed rows. It does **not** authenticate the source log, independently validate labels, measure real detection accuracy or activate any network/SOC action. Synthetic regression: `py -3.12 -m pytest -q tests/test_zeek_model_feature_types.py tests/test_zeek_model_artifact.py tests/test_zeek_offline_baseline.py`. GitHub CI and student Windows 11/VMware acceptance are tracked separately in PROGRESS.md.
