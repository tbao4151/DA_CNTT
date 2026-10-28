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
