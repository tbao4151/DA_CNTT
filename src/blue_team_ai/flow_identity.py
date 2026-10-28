"""Stable, conservative normalized identity for offline Zeek flow non-reuse.

This is an exact UID/time/five-tuple screen, NOT semantic deduplication.
Changing any identity field can evade it; it does not establish capture
independence, labeling truth or VMware isolation. Never used as model input.
"""
from __future__ import annotations

from collections.abc import Mapping

FLOW_IDENTITY_FIELDS = (
    "uid", "event_time_utc", "src_ip", "src_port",
    "dst_ip", "dst_port", "proto",
)


def flow_identity(event: Mapping[str, object]) -> tuple[object, ...]:
    """Return the existing normalized identity without exposing it in reports."""
    return tuple(event[field] for field in FLOW_IDENTITY_FIELDS)
