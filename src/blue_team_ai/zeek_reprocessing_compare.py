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


def _raw_non_uid_multiset(data: bytes) -> tuple[
    tuple[str, ...], tuple[tuple[str, str], ...] | None,
    tuple[tuple[str, str], ...], Counter
]:
    """Canonicalize raw ASCII Zeek rows without discarding unknown columns.

    Caller must first validate the entire bounded input with parse_zeek_conn_log.
    #open/#close timestamps and UID values are run-specific; all other raw
    values, including missing sentinels, are intentionally format-sensitive.
    """
    fields: tuple[str, ...] | None = None
    types: tuple[str, ...] | None = None
    sentinels: dict[str, str] = {}
    rows: list[tuple[str, ...]] = []
    for line in data.decode("utf-8", errors="strict").splitlines():
        if line.startswith("#fields\t"):
            fields = tuple(line.split("\t")[1:])
        elif line.startswith("#types\t"):
            types = tuple(line.split("\t")[1:])
        elif line.startswith(("#set_separator\t", "#unset_field\t", "#empty_field\t")):
            key, value = line.split("\t", 1)
            sentinels[key] = value
        elif line and not line.startswith("#"):
            rows.append(tuple(line.split("\t")))
    if fields is None or "uid" not in fields:
        raise ValueError("Missing required Zeek fields for strict comparison")
    names = tuple(sorted(name for name in fields if name != "uid"))
    indexes = tuple(fields.index(name) for name in names)
    declared_types = (tuple(sorted(zip(fields, types))) if types is not None else None)
    normalized = Counter(tuple(row[index] for index in indexes) for row in rows)
    return names, declared_types, tuple(sorted(sentinels.items())), normalized


def compare_strict_zeek_reprocessing(original: bytes, reprocessed: bytes) -> dict[str, object]:
    """Opt-in exact multiset comparison of ALL raw non-UID Zeek ASCII columns.

    This is stricter than parsed-field comparison, not a proof of PCAP origin.
    Raw numeric formatting and additional Zeek script fields must also agree.
    """
    report = compare_parsed_zeek_reprocessing(original, reprocessed)
    left = _raw_non_uid_multiset(original)
    right = _raw_non_uid_multiset(reprocessed)
    if left != right:
        raise ValueError("Pinned Zeek logs differ in strict non-UID raw fields or schema")
    report.update({
        "comparison": "exact_multiset_of_all_non_uid_raw_zeek_fields",
        "compared_fields": list(left[0]),
        "unparsed_zeek_fields_compared": True,
        "declared_types_compared": left[1] is not None,
        "sentinel_metadata_compared": True,
        "raw_text_formatting_sensitive": True,
    })
    return report
