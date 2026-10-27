#!/usr/bin/env python3
"""Recheck a trusted locally trained UNSW-NB15 model and save reproducible evidence.

This script never trains or downloads data. The held-out test split is used
only for evaluation. Only load a joblib model you generated or trust.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from math import isclose
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import average_precision_score, classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.download_unsw_nb15 import FILES  # official expected rows and SHA-256
from siem_ai.model import predict_batch

FORBIDDEN_FEATURES = {"id", "label", "attack_cat", "AI_verdict", "AI_attack_probability", "flow_ref"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_commit(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
            text=True, check=True, timeout=5,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    sha = result.stdout.strip()
    return sha if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha) else None


def verify_local_run(root: Path, *, expected_files: dict[str, tuple[int, str]] = FILES) -> dict:
    """Raise on failed verification; return a report only after every check passes.

    expected_files is injectable solely to allow tiny synthetic unit tests.
    The CLI always uses the pinned official UNSW-NB15 checksums.
    """
    root = Path(root)
    data_dir = root / "data" / "raw" / "unsw_nb15"
    artifact_dir = root / "artifacts"
    model_path = artifact_dir / "unsw_binary_rf.joblib"
    metrics_path = artifact_dir / "metrics.json"
    dataset_hashes = {}
    for filename, (expected_rows, expected_hash) in expected_files.items():
        actual_hash = sha256_file(data_dir / filename)
        if actual_hash != expected_hash:
            raise ValueError(f"{filename}: SHA-256 mismatch; refusing unverified dataset")
        dataset_hashes[filename] = actual_hash

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    if (metrics.get("train_size"), metrics.get("test_size")) != (
        expected_files["UNSW_NB15_training-set.csv"][0],
        expected_files["UNSW_NB15_testing-set.csv"][0],
    ):
        raise ValueError("Local metrics train/test sizes do not match verified data")
    features = metrics.get("features")
    if not isinstance(features, list) or not features or any(not isinstance(f, str) for f in features):
        raise ValueError("Local metrics have no valid feature list")
    if len(features) != len(set(features)) or FORBIDDEN_FEATURES.intersection(features):
        raise ValueError("Local metrics contain duplicate or ground-truth features")

    test = pd.read_csv(data_dir / "UNSW_NB15_testing-set.csv")
    if len(test) != metrics["test_size"]:
        raise ValueError("Held-out test row count mismatch")
    if "label" not in test or test["label"].isna().any() or not test["label"].isin([0, 1]).all():
        raise ValueError("Held-out test labels must be complete binary 0/1")
    if not set(features).issubset(test.columns):
        raise ValueError("Held-out test lacks trained features")

    # joblib uses pickle; this is deliberately limited to a trusted local artifact.
    model = joblib.load(model_path)
    if hasattr(model, "named_steps") and "preprocess" in model.named_steps:
        trained_features = list(model.named_steps["preprocess"].feature_names_in_)
    else:
        trained_features = list(model.feature_names_in_)
    if trained_features != features:
        raise ValueError("Saved model feature order differs from local metrics")
    predicted = np.asarray(model.predict(test[features]))
    if predicted.shape != (len(test),) or not np.isin(predicted, [0, 1]).all():
        raise ValueError("Saved model returned invalid class predictions")
    scored = predict_batch(model, test)
    labels = test["label"].to_numpy()
    matrix = confusion_matrix(labels, predicted, labels=[0, 1]).tolist()
    if matrix != metrics.get("confusion_matrix_0_1"):
        raise ValueError("Recomputed confusion matrix differs from local metrics")
    computed = classification_report(labels, predicted, labels=[0, 1], output_dict=True, zero_division=0)
    saved = metrics.get("classification_report", {})
    for class_key in ("0", "1", "macro avg", "weighted avg"):
        for measure in ("precision", "recall", "f1-score", "support"):
            if not isclose(computed[class_key][measure], saved.get(class_key, {}).get(measure, float("nan")), rel_tol=1e-8, abs_tol=1e-10):
                raise ValueError(f"Recomputed {class_key} {measure} differs from local metrics")
    if not isclose(computed["accuracy"], saved.get("accuracy", float("nan")), rel_tol=1e-8, abs_tol=1e-10):
        raise ValueError("Recomputed accuracy differs from local metrics")
    ap = float(average_precision_score(labels, scored["attack_probability"].to_numpy()))
    if not isclose(ap, metrics.get("average_precision_attack", float("nan")), rel_tol=1e-8, abs_tol=1e-10):
        raise ValueError("Recomputed average precision differs from local metrics")

    ui_verdicts = np.where(scored["attack_probability"].to_numpy() >= 0.5, 1, 0)
    return {
        "schema_version": 1,
        "verification_status": "passed",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "execution_environment": {
            "os": platform.system(),
            "python": platform.python_version(),
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "git_commit": git_commit(root),
        "dataset": "UNSW-NB15 official train/test partition",
        "dataset_sha256": dataset_hashes,
        "model_sha256": sha256_file(model_path),
        "metrics_sha256": sha256_file(metrics_path),
        "train_rows": int(metrics["train_size"]),
        "test_rows": int(metrics["test_size"]),
        "feature_count": len(features),
        "confusion_matrix_0_1": matrix,
        "attack_precision": computed["1"]["precision"],
        "attack_recall": computed["1"]["recall"],
        "attack_f1": computed["1"]["f1-score"],
        "average_precision_attack": ap,
        "dashboard_vs_model_predict_disagreements_at_0_5": int(np.count_nonzero(ui_verdicts != predicted)),
        "scope_note": (
            "Local artifact and held-out dataset consistency check only; "
            "not a new benchmark, independent replication, live capture, or proof "
            "that a human completed the demonstration. The report is not signed."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "local_verification.json")
    args = parser.parse_args()
    try:
        report = verify_local_run(ROOT)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        print(f"LOCAL VERIFICATION FAILED: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"LOCAL VERIFICATION PASSED: {args.output}")
    print(f"Attack F1: {report['attack_f1']:.4f}; dashboard/model disagreements: {report['dashboard_vs_model_predict_disagreements_at_0_5']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
