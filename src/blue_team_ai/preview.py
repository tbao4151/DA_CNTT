"""Offline-only aggregate view for Zeek events; no model inference or alerting."""
from __future__ import annotations

from collections import Counter
from typing import Mapping, Sequence


def summarize_offline_flows(events: Sequence[Mapping[str, object]]) -> dict:
    """Summarize validated events from exactly one offline Zeek source.

    Do not turn missing values into zero or assign attack labels. Timestamp
    bounds are based on Zeek event timestamps, not the upload/processing time.
    """
    if not events:
        raise ValueError("No offline Zeek events to summarize")
    if any(event.get("origin") != "offline_zeek_log" for event in events):
        raise ValueError("Only offline Zeek telemetry can be previewed")
    digests = {event.get("source_sha256") for event in events}
    if len(digests) != 1 or not next(iter(digests)):
        raise ValueError("Mixed or missing Zeek source provenance")
    times = [event["event_time_utc"] for event in events]
    protocols = Counter(str(event["proto"]) for event in events)
    return {
        "flow_count": len(events),
        "unique_sources": len({event["src_ip"] for event in events}),
        "unique_destinations": len({event["dst_ip"] for event in events}),
        "first_event_utc": min(times),
        "last_event_utc": max(times),
        "source_sha256": next(iter(digests)),
        "protocol_counts": dict(sorted(protocols.items())),
    }
