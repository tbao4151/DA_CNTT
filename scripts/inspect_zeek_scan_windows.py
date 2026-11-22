"""Read-only, SHA-pinned Zeek port-diversity diagnostic (not Blue AI scoring).

No training, attack generation, network access, operational SOC alerts, or
validation of operator-supplied scenario labels. Prints only aggregates, not
individual IPs, UIDs or private paths. Outputs no files.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from blue_team_ai.scan_window import rolling_port_diversity
from blue_team_ai.zeek import MAX_LOG_BYTES, parse_zeek_conn_log

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_MAX_LABEL_BYTES = 2 * 1024 * 1024


def _unique_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON key")
        obj[key] = value
    return obj


def _reject_constant(_value):
    raise ValueError("Non-standard JSON constant")


def _private_file(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Symlink input refused")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.is_relative_to(ROOT):
        raise ValueError("Expected private file outside Git")
    return resolved


def run(
    *, log: Path, expected_log_sha256: str, cidr: str,
    labels: Path | None = None, window_seconds: int = 10,
    min_distinct_ports: int = 5,
) -> dict[str, object]:
    if not isinstance(expected_log_sha256, str) or _HEX.fullmatch(expected_log_sha256) is None:
        raise ValueError("Invalid independent log SHA-256")
    scope = ipaddress.ip_network(cidr, strict=True)
    if not isinstance(scope, ipaddress.IPv4Network) or not scope.is_private or scope.prefixlen < 16:
        raise ValueError("Expected bounded private IPv4 Host-only scope")
    path = _private_file(log)
    with path.open("rb") as stream:
        raw = stream.read(MAX_LOG_BYTES + 1)
    if len(raw) > MAX_LOG_BYTES or hashlib.sha256(raw).hexdigest() != expected_log_sha256:
        raise ValueError("Zeek log size or SHA-256 mismatch")
    events = parse_zeek_conn_log(raw)
    for event in events:
        if (ipaddress.ip_address(event["src_ip"]) not in scope
                or ipaddress.ip_address(event["dst_ip"]) not in scope):
            raise ValueError("Out-of-scope Zeek endpoint")
    windows = rolling_port_diversity(
        events, window_seconds=window_seconds, min_distinct_ports=min_distinct_ports,
    )
    tcp_windows = [row for row in windows if row["proto"] == "tcp"]
    report = {
        "kind": "da005_offline_zeek_port_diversity_diagnostic_v1",
        "mode": "offline_retrospective_heuristic_only",
        "source_sha256": expected_log_sha256,
        "window_seconds": window_seconds,
        "min_distinct_ports": min_distinct_ports,
        "flow_count": len(events),
        "tcp_flow_count": len(tcp_windows),
        "maximum_distinct_ports_in_window": max(
            (row["distinct_destination_ports_in_window"] for row in tcp_windows),
            default=0,
        ),
        "candidate_flow_count": sum(
            bool(row["port_diversity_heuristic_candidate"]) for row in windows
        ),
        "model_training_performed": False,
        "ai_inference_performed": False,
        "live_capture": False,
        "operational_alerts_created": False,
        "scenario_label_authenticity_verified": False,
    }
    if labels is not None:
        label_file = _private_file(labels)
        if label_file.parent != path.parent or label_file == path:
            raise ValueError("Labels must be a separate sibling of original log")
        with label_file.open("rb") as stream:
            encoded = stream.read(_MAX_LABEL_BYTES + 1)
        if len(encoded) > _MAX_LABEL_BYTES:
            raise ValueError("Labels exceed size limit")
        annotation = json.loads(
            encoded.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_keys, parse_constant=_reject_constant,
        )
        if not isinstance(annotation, dict) or set(annotation) != {"source_sha256", "labels_by_uid"}:
            raise ValueError("Invalid annotation contract")
        assigned = annotation["labels_by_uid"]
        if (annotation["source_sha256"] != expected_log_sha256
                or not isinstance(assigned, dict)
                or set(assigned) != {e["uid"] for e in events}
                or any(type(value) is not int or value not in (0, 1)
                       for value in assigned.values())):
            raise ValueError("Labels do not cover exact log UIDs with 0/1 integers")
        report.update({
            "operator_label_0_count": sum(value == 0 for value in assigned.values()),
            "operator_label_1_count": sum(value == 1 for value in assigned.values()),
            "label_0_candidate_count": sum(
                row["port_diversity_heuristic_candidate"] and assigned[row["uid"]] == 0
                for row in windows
            ),
            "label_1_candidate_count": sum(
                row["port_diversity_heuristic_candidate"] and assigned[row["uid"]] == 1
                for row in windows
            ),
        })
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-log-sha256", required=True)
    parser.add_argument("--cidr", required=True)
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--window-seconds", type=int, default=10)
    parser.add_argument("--min-distinct-ports", type=int, default=5)
    options = parser.parse_args(argv)
    try:
        report = run(
            log=options.log,
            expected_log_sha256=options.expected_log_sha256,
            cidr=options.cidr,
            labels=options.labels,
            window_seconds=options.window_seconds,
            min_distinct_ports=options.min_distinct_ports,
        )
    except (ValueError, OSError, TypeError, OverflowError, UnicodeError):
        print("Private offline Zeek window diagnostic refused; verify trusted inputs.", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
