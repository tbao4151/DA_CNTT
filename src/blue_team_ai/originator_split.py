"""Optional offline originator-IP split screen for independently pinned Zeek logs.

This is a conservative *address* separation check, not proof of host identity:
NAT, DHCP reuse, shared clients or direction changes can produce false refusals.
Only normalized Zeek originator addresses are compared; a common responder
(server) is allowed. No raw addresses or network operations are exported.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from .zeek import parse_zeek_conn_log

_SPLITS = frozenset({"train", "validation", "test"})


def screen_originator_ip_disjoint_splits(
    captures: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Refuse an originator address seen in more than one split.

    Called only after manifest SHA-256 verification. An originator address is
    not necessarily a unique physical host; a clean result cannot attest
    session independence, capture authenticity or independent labels.
    """
    if not isinstance(captures, Sequence) or isinstance(captures, (str, bytes, bytearray)):
        raise ValueError("Invalid originator split-screen input")
    owners: dict[str, str] = {}
    counts: dict[str, set[str]] = {split: set() for split in _SPLITS}
    total = 0
    for capture in captures:
        if not isinstance(capture, Mapping):
            raise ValueError("Invalid originator split-screen capture")
        split = capture.get("split")
        raw = capture.get("log_bytes")
        if not isinstance(split, str) or split not in _SPLITS or not isinstance(raw, bytes):
            raise ValueError("Invalid originator split-screen capture")
        for event in parse_zeek_conn_log(raw):
            originator = event["src_ip"]
            previous = owners.get(originator)
            if previous is not None and previous != split:
                raise ValueError("Originator address appears across research splits")
            owners[originator] = split
            counts[split].add(originator)
            total += 1
    return {
        "mode": "offline_zeek_originator_address_split_screen_only",
        "screened_flows": total,
        "unique_originator_counts": {split: len(counts[split]) for split in ("train", "validation", "test")},
        "cross_split_originator_address_overlaps": 0,
        "shared_responder_addresses_allowed": True,
        "host_identity_verified": False,
        "capture_independence_verified": False,
        "host_only_isolation_verified": False,
        "label_truth_verified": False,
        "interpretation": (
            "Optional conservative originator-address separation check. "
            "Address reuse, NAT, DHCP and flow direction may cause false refusals; "
            "a clean result does not prove independent hosts or genuine captures."
        ),
    }
