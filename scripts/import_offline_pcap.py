"""Private, opt-in offline classic PCAP conversion using Zeek -r.

Run inside the isolated Linux VM with Zeek installed. No live capture.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.offline_pcap import import_offline_pcap


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, type=Path, help="Absolute private classic .pcap path")
    parser.add_argument("--output-dir", required=True, type=Path, help="New private directory")
    parser.add_argument("--cidr", action="append", required=True, help="Declared private lab CIDR (repeatable)")
    parser.add_argument("--confirm-offline-only", action="store_true",
                        help="Confirm this is a pre-existing authorized offline PCAP")
    args = parser.parse_args(argv)
    try:
        result = import_offline_pcap(
            args.pcap, args.output_dir, lab_cidrs=args.cidr,
            operator_confirmed_offline=args.confirm_offline_only,
        )
    except (ValueError, OSError, TypeError):
        print("Offline PCAP import refused. No network interface was captured. "
              "Inspect private files and prerequisites.", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
