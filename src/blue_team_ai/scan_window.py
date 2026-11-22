"""Offline rolling port-diversity diagnostics on validated Zeek conn.log events.

Separate from the frozen Zeek v1 nine-feature model. This computes a
retrospective, timestamp-ordered candidate signal, NOT a trained AI
prediction, operational alert, live capture, or independently verified scan.
An event sees itself and older starts only, never later Zeek start times.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta

from .features import extract_zeek_features

MAX_EVENTS = 10_000


def rolling_port_diversity(
    events: Sequence[Mapping[str, object]], *,
    window_seconds: int = 10,
    min_distinct_ports: int = 5,
) -> list[dict[str, object]]:
    """Return one chronological-window record per input flow, in INPUT order.

    Window boundaries are inclusive [event_time - window_seconds, event_time].
    A history is scoped to (source IP, destination IP), TCP only. UID is
    retained for private attribution but NEVER treated as a model feature.
    Events are sorted by Zeek connection START timestamp; the diagnostic is
    retrospective and must not be presented as measured live alert latency.
    """
    if type(window_seconds) is not int or not 1 <= window_seconds <= 60:
        raise ValueError("window_seconds must be an integer in 1..60")
    if type(min_distinct_ports) is not int or not 2 <= min_distinct_ports <= 100:
        raise ValueError("min_distinct_ports must be an integer in 2..100")
    if (
        not isinstance(events, Sequence)
        or isinstance(events, (str, bytes, bytearray))
        or not 1 <= len(events) <= MAX_EVENTS
    ):
        raise ValueError("Expected 1..10000 validated Zeek events")

    first_digest = None
    seen_uids: set[str] = set()
    ordered = []
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise ValueError("Invalid Zeek event")
        # Enforce the existing exact offline event contract at the boundary.
        extract_zeek_features(event)
        digest, uid = event["source_sha256"], event["uid"]
        if first_digest is None:
            first_digest = digest
        if digest != first_digest or uid in seen_uids:
            raise ValueError("Mixed source digest or repeated Zeek UID")
        seen_uids.add(uid)
        timestamp = datetime.fromisoformat(event["event_time_utc"])
        if timestamp.utcoffset() != timedelta(0):
            raise ValueError("Expected UTC timestamp")
        ordered.append((timestamp, index, event))

    # Original order is preserved for reliable UID/annotation correspondence.
    ordered.sort(key=lambda item: (item[0], item[1]))
    history = defaultdict(deque)
    ports = defaultdict(Counter)
    result: list[dict[str, object] | None] = [None] * len(events)
    for timestamp, index, event in ordered:
        count = distinct = 0
        candidate = False
        if event["proto"] == "tcp":
            pair = (event["src_ip"], event["dst_ip"])
            recent = history[pair]
            port_counts = ports[pair]
            while recent and timestamp - recent[0][0] > timedelta(seconds=window_seconds):
                _, removed_port = recent.popleft()
                port_counts[removed_port] -= 1
                if port_counts[removed_port] == 0:
                    del port_counts[removed_port]
            recent.append((timestamp, event["dst_port"]))
            port_counts[event["dst_port"]] += 1
            count, distinct = len(recent), len(port_counts)
            candidate = distinct >= min_distinct_ports
        result[index] = {
            "uid": event["uid"],
            "event_time_utc": event["event_time_utc"],
            "src_ip": event["src_ip"],
            "dst_ip": event["dst_ip"],
            "proto": event["proto"],
            "dst_port": event["dst_port"],
            "connections_in_window": count,
            "distinct_destination_ports_in_window": distinct,
            "port_diversity_heuristic_candidate": candidate,
        }
    return [item for item in result if item is not None]
