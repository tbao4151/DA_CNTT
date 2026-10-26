#!/usr/bin/env python3
"""Export measured global RandomForest MDI feature importances with provenance.

Only load joblib artifacts you created yourself or otherwise fully trust:
joblib/pickle may execute code during deserialization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from siem_ai.importance_report import build_importance_report
from siem_ai.model import load_local_model


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, default=ROOT / "artifacts/unsw_binary_rf.joblib")
    parser.add_argument("--metrics", type=Path, default=ROOT / "artifacts/metrics.json")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/official_feature_importance.json")
    args = parser.parse_args()
    if not args.model.is_file() or not args.metrics.is_file():
        parser.error("Missing locally trained model/metrics; first run python scripts/train_siem.py")
    metadata = json.loads((ROOT / "data/raw/unsw_nb15/metadata.json").read_text(encoding="utf-8"))
    train_path = ROOT / "data/raw/unsw_nb15/UNSW_NB15_training-set.csv"
    checksum = sha256_file(train_path)
    documented_checksum = metadata["files"]["UNSW_NB15_training-set.csv"]["sha256"]
    if checksum != documented_checksum:
        parser.error("Official UNSW-NB15 training checksum mismatch")
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    model = load_local_model(args.model)  # trusted, locally trained file ONLY
    report = build_importance_report(
        model, metrics,
        training_sha256=checksum,
        model_sha256=sha256_file(args.model),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "training_rows": report["training_rows"],
        "feature_count": report["feature_count"],
        "importance_sum": report["importance_sum"],
        "top_10": report["features"][:10],
    }, indent=2, ensure_ascii=False))
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
