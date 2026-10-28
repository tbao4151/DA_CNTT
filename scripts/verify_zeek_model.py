"""Verify a PRIVATE, data-only Zeek model against a separately pinned digest.

Read-only and offline. Does NOT score traffic, create alerts or open sockets.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.trusted_model import load_pinned_zeek_research_model


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True, help="Private Zeek JSON model outside Git")
    parser.add_argument("--expected-sha256", required=True, help="Digest from a separate trusted record")
    args = parser.parse_args(argv)
    try:
        if args.model.resolve(strict=True).is_relative_to(ROOT):
            raise ValueError("Private model must remain outside repository")
        artifact = load_pinned_zeek_research_model(
            args.model, expected_sha256=args.expected_sha256,
        )
    except (ValueError, OSError):
        print("Private Zeek model verification refused; inspect local evidence.", file=sys.stderr)
        return 1
    print("Private Zeek JSON model: pinned-byte and schema checks passed.")
    print("feature_schema_version=" + str(artifact["feature_schema_version"]))
    print("This is NOT model authorship, label authenticity, VMware isolation or detection validation.")
    print("No traffic was scored and no alert/SOC case was created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
