"""Create a private, offline evidence inventory for a VMware Host-only Zeek capture."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.capture_evidence import build_capture_inventory, validate_private_output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--cidr", action="append", required=True)
    parser.add_argument("--origin", choices=("lab_capture", "offline_replay", "synthetic"), required=True)
    parser.add_argument("--vmware-screenshot", type=Path, required=True)
    parser.add_argument("--host-adapter-screenshot", type=Path, required=True)
    parser.add_argument("--zeek-version-file", type=Path, required=True)
    parser.add_argument("--scenario-notes", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = [
        args.log, args.vmware_screenshot, args.host_adapter_screenshot,
        args.zeek_version_file, args.scenario_notes,
    ]
    try:
        validate_private_output(args.output, inputs)
        report = build_capture_inventory(
            log_path=args.log,
            expected_log_sha256=args.expected_log_sha256,
            cidrs=args.cidr,
            origin=args.origin,
            vmware_screenshot=args.vmware_screenshot,
            host_adapter_screenshot=args.host_adapter_screenshot,
            zeek_version_file=args.zeek_version_file,
            scenario_notes=args.scenario_notes,
        )
        payload = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
    except (ValueError, OSError, UnicodeError, TypeError):
        print("Private capture inventory refused; inspect original evidence locally.", file=sys.stderr)
        return 1
    print("Private evidence inventory saved. Host-only isolation and scenario truth NOT verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
