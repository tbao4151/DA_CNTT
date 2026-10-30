"""Run two bounded offline Zeek -r imports of ONE independently pinned PCAP.

No live capture, network interface, Red Team scenario, AI scoring or SOC write.
The two private output directories must not exist before the run. Failed runs
retain their files for inspection and never emit a success JSON report.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import shutil
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.offline_pcap import _private_path, _sha256_file, import_offline_pcap
from blue_team_ai.pcap_structure import MAX_CLASSIC_PCAP_BYTES, inspect_classic_pcap_framing
from blue_team_ai.pcap_zeek_tuple import corroborate_pcap_zeek_tuples
from blue_team_ai.zeek import MAX_LOG_BYTES
from blue_team_ai.zeek_reprocessing_compare import compare_strict_zeek_reprocessing


MAX_ZEEK_BINARY_BYTES = 256 * 1024 * 1024


def _verify_pinned_zeek_binary(expected_sha256: str) -> Path:
    """Check the PATH-selected Zeek executable against an independent digest.

    This pins executable bytes, not Zeek scripts, plugins, dependencies, version
    output, runtime configuration, provenance or execution environment.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("Independent lowercase Zeek executable SHA-256 required")
    selected = shutil.which("zeek")
    if not selected:
        raise ValueError("Zeek executable not found on PATH")
    executable = Path(selected).resolve(strict=True)
    if (not executable.is_file() or not stat.S_ISREG(executable.stat().st_mode)
            or not 0 < executable.stat().st_size <= MAX_ZEEK_BINARY_BYTES):
        raise ValueError("Zeek executable is not a bounded regular file")
    if not hmac.compare_digest(_sha256_file(executable), expected_sha256):
        raise ValueError("PATH-selected Zeek executable differs from independent SHA-256")
    return executable


def _new_private_directory(path: Path) -> Path:
    """Preflight both output destinations BEFORE running the first import."""
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Absolute non-symlink output directory required")
    resolved = _private_path(path, must_exist=False)
    if resolved.exists() or resolved.is_symlink():
        raise ValueError("Each output directory must be new")
    if (not resolved.parent.is_dir() or resolved.parent.is_symlink()
            or resolved.parent.is_relative_to(ROOT)):
        raise ValueError("Output parent must be an existing private directory")
    return resolved


def _pinned_log(directory: Path, expected_sha256: str) -> bytes:
    path = directory / "conn.log"
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Generated Zeek conn.log must be a regular file")
    if not 0 < path.stat().st_size <= MAX_LOG_BYTES:
        raise ValueError("Generated Zeek conn.log exceeds bounded size")
    with path.open("rb") as source:
        data = source.read(MAX_LOG_BYTES + 1)
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha256):
        raise ValueError("Generated Zeek conn.log changed after import")
    return data


def run_two_passes(args: argparse.Namespace) -> dict[str, object]:
    if args.confirm_offline_only is not True:
        raise ValueError("Explicit operator offline confirmation required")
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_pcap_sha256):
        raise ValueError("Independent lowercase PCAP SHA-256 required")
    if type(args.timeout_seconds) is not int or not 1 <= args.timeout_seconds <= 600:
        raise ValueError("Invalid bounded timeout")
    source = _private_path(args.pcap, must_exist=True)
    if not source.is_file() or not stat.S_ISREG(source.stat().st_mode):
        raise ValueError("Original PCAP must be a regular file")
    if not 24 <= source.stat().st_size <= MAX_CLASSIC_PCAP_BYTES:
        raise ValueError("Original PCAP outside bounded size")
    with source.open("rb") as stream:
        pcap = stream.read(MAX_CLASSIC_PCAP_BYTES + 1)
    if not hmac.compare_digest(hashlib.sha256(pcap).hexdigest(), args.expected_pcap_sha256):
        raise ValueError("Original PCAP differs from independently recorded SHA-256")
    framing = inspect_classic_pcap_framing(pcap)

    first = _new_private_directory(args.first_output_dir)
    second = _new_private_directory(args.second_output_dir)
    if (first == second or first in second.parents or second in first.parents
            or first == source or second == source
            or first in source.parents or second in source.parents):
        raise ValueError("PCAP and the two output directories must be disjoint")
    # CIDR validation is repeated by each offline importer before Zeek starts.
    from blue_team_ai.lab_scope import _networks
    _networks(args.cidr)

    zeek_binary = (None if args.expected_zeek_binary_sha256 is None else
                   _verify_pinned_zeek_binary(args.expected_zeek_binary_sha256))
    reports = []
    for destination in (first, second):
        import_kwargs = {
            "lab_cidrs": args.cidr,
            "operator_confirmed_offline": True,
            "timeout_seconds": args.timeout_seconds,
        }
        if zeek_binary is not None:
            import_kwargs["zeek_executable"] = zeek_binary
        report = import_offline_pcap(source, destination, **import_kwargs)
        if not hmac.compare_digest(report["pcap_sha256"], args.expected_pcap_sha256):
            raise ValueError("Original PCAP changed during a Zeek processing pass")
        if not hmac.compare_digest(_sha256_file(source), args.expected_pcap_sha256):
            raise ValueError("Original PCAP changed after a Zeek processing pass")
        reports.append(report)
        if (zeek_binary is not None and
                _verify_pinned_zeek_binary(args.expected_zeek_binary_sha256) != zeek_binary):
            raise ValueError("PATH-selected Zeek executable changed between passes")

    first_log = _pinned_log(first, reports[0]["zeek_conn_sha256"])
    second_log = _pinned_log(second, reports[1]["zeek_conn_sha256"])
    comparison = compare_strict_zeek_reprocessing(first_log, second_log)
    corroboration1 = corroborate_pcap_zeek_tuples(pcap, first_log)
    corroboration2 = corroborate_pcap_zeek_tuples(pcap, second_log)
    if not hmac.compare_digest(_sha256_file(source), args.expected_pcap_sha256):
        raise ValueError("Original PCAP changed before final comparison")
    result = {
        "report_version": 1,
        "mode": "two_pass_offline_zeek_reprocessing",
        "pcap_sha256": args.expected_pcap_sha256,
        "first_zeek_conn_sha256": reports[0]["zeek_conn_sha256"],
        "second_zeek_conn_sha256": reports[1]["zeek_conn_sha256"],
        "pcap_packet_count": framing["packet_count"],
        "zeek_flow_count": comparison["flow_count"],
        "strict_all_non_uid_fields_equivalent": True,
        "pcap_tuple_presence_for_both_logs": (
            corroboration1["matched_zeek_flow_count"] == comparison["flow_count"]
            and corroboration2["matched_zeek_flow_count"] == comparison["flow_count"]
        ),
        "two_zeek_subprocesses_completed": True,
        "zeek_binary_version_verified": False,
        "zeek_binary_sha256_pinned": zeek_binary is not None,
        "pcap_to_log_derivation_proven": False,
        "packet_to_flow_identity_verified": False,
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "independent_labels_verified": False,
        "attack_detection_verified": False,
        "interpretation": (
            "Two separately invoked offline Zeek -r imports produced logs that "
            "agree under strict non-UID comparison and PCAP tuple presence. "
            "Operator must independently preserve Zeek version, command, "
            "authorization, capture origin and isolation evidence."
        ),
    }
    if zeek_binary is not None:
        result["zeek_binary_sha256"] = args.expected_zeek_binary_sha256
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--expected-pcap-sha256", required=True)
    parser.add_argument("--first-output-dir", type=Path, required=True)
    parser.add_argument("--second-output-dir", type=Path, required=True)
    parser.add_argument("--cidr", action="append", required=True)
    parser.add_argument("--confirm-offline-only", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--expected-zeek-binary-sha256", default=None,
                        help="Optional independent lowercase SHA-256 of the PATH-selected Zeek executable")
    args = parser.parse_args(argv)
    try:
        report = run_two_passes(args)
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError):
        print("Two-pass offline Zeek experiment refused; inspect preserved private outputs.",
              file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
