"""Export a PRIVATE, data-only Zeek research model (no pickle or test scoring).

Requires an explicit lab CIDR screen of every capture. No live capture,
network access, operational alerts, SOC writes or UNSW model loading.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.model_artifact import build_zeek_research_artifact
from evaluate_zeek_lab import load_experiment_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True, help="Private manifest v1")
    parser.add_argument("--cidr", action="append", required=True,
                        help="Explicit actual Host-only RFC1918 CIDR (repeat at most four times)")
    parser.add_argument("--output", type=Path, required=True,
                        help="New private JSON research model file; never overwritten")
    args = parser.parse_args(argv)
    try:
        manifest = args.manifest.resolve(strict=True)
        output = args.output.resolve()
        if (
            manifest.is_relative_to(ROOT) or not output.is_relative_to(manifest.parent)
            or output.is_relative_to(ROOT) or output == manifest
            or output.exists()
        ):
            raise ValueError("Model export must be a new file outside Git")
        captures, digest = load_experiment_manifest(manifest, lab_cidrs=args.cidr)
        dataset = build_labeled_lab_dataset(captures)
        artifact = build_zeek_research_artifact(
            dataset, input_manifest_sha256=digest,
        )
        payload = (json.dumps(artifact, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        # Exclusive creation. A crash while writing may leave an incomplete
        # newly created file; never overwrite it on a later attempt.
        with output.open("xb") as stream:
            stream.write(payload)
        print("Private non-executable Zeek research model exported; TEST not scored.")
        print("artifact_sha256=" + hashlib.sha256(payload).hexdigest())
        print("Record this digest independently; it is NOT a signature or label verification.")
        return 0
    except (ValueError, OSError, UnicodeError, TypeError):
        print("Private Zeek model export refused; inspect private inputs locally.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
