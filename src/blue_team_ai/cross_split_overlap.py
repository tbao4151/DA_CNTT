"""Optional strict cross-split reuse screen for offline Zeek research inputs.

Unlike the default UID-aware identity guard, this screen deliberately ignores
Zeek UID and compares normalized event timestamp plus network five-tuple.
It may reject independent simultaneous flows with identical keys; it cannot
prove independent capture sessions or authentic attack labels. No network I/O.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from .flow_identity import flow_identity
from .zeek import parse_zeek_conn_log

_SPLITS = frozenset({"train", "validation", "test"})


def screen_uid_independent_cross_split_overlap(
    captures: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Fail closed on matching timestamp/five-tuple in different partitions.

    Input captures must already be loaded and SHA-256 pinned by the manifest
    reader. No raw addresses, timestamps, UIDs or session IDs are returned.
    """
    seen: dict[tuple[object, ...], str] = {}
    total = 0
    for capture in captures:
        split = capture["split"]
        raw = capture["log_bytes"]
        if not isinstance(split, str) or split not in _SPLITS or not isinstance(raw, bytes):
            raise ValueError("Invalid offline overlap-screen input")
        for event in parse_zeek_conn_log(raw):
            # flow_identity = (uid, timestamp, source IP/port, destination
            # IP/port, protocol). UID may change when a log is regenerated.
            key = flow_identity(event)[1:]
            previous = seen.get(key)
            if previous is not None and previous != split:
                raise ValueError("Cross-split timestamp/five-tuple overlap (UID ignored)")
            seen[key] = split
            total += 1
    return {
        "mode": "offline_zeek_uid_independent_overlap_screen_only",
        "screened_flows": total,
        "cross_split_overlaps": 0,
        "uid_excluded_from_identity": True,
        "timestamp_and_five_tuple_compared": True,
        "capture_independence_verified": False,
        "host_only_isolation_verified": False,
        "label_truth_verified": False,
        "interpretation": (
            "Optional conservative exact overlap screen. Identical timestamps "
            "and five-tuples can occur independently; a clean result does not "
            "prove host/session independence, genuine capture or attack labels."
        ),
    }
