"""Offline comparison of parsed Zeek conn.log records from two pinned runs.

A normalized multiset comparison is stronger than PCAP five-tuple presence,
but is NOT proof that either log came from a particular PCAP or Zeek binary.
"""
from __future__ import annotations

from collections import Counter

from .zeek import parse_zeek_conn_log

# UID and source digest are run-specific; unparsed Zeek columns are not covered.
COMPARABLE_FIELDS = (
    "event_time_utc", "src_ip", "src_port", "dst_ip", "dst_port",
    "proto", "service", "duration_s", "orig_bytes", "resp_bytes",
    "orig_pkts", "resp_pkts",
)


def compare_parsed_zeek_reprocessing(original: bytes, reprocessed: bytes) -> dict[str, object]:
    """Fail closed unless supported normalized flow records match as multisets.

    Timestamp and direction are compared exactly; no tolerance or fuzzy
    pairing is silently applied. Duplicate records retain their multiplicity.
    """
    left = parse_zeek_conn_log(original)
    right = parse_zeek_conn_log(reprocessed)
    def records(events: list[dict]) -> Counter:
        return Counter(tuple(event[name] for name in COMPARABLE_FIELDS) for event in events)
    if records(left) != records(right):
        raise ValueError("Pinned Zeek logs differ in parsed flow values or multiplicity")
    return {
        "comparison": "exact_multiset_of_supported_parsed_zeek_fields",
        "flow_count": len(left),
        "compared_fields": list(COMPARABLE_FIELDS),
        "uid_equivalence_verified": False,
        "unparsed_zeek_fields_compared": False,
        "pcap_origin_verified": False,
        "zeek_version_or_binary_verified": False,
        "vmware_isolation_verified": False,
        "ground_truth_verified": False,
        "attack_detection_verified": False,
    }
