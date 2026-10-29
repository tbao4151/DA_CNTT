"""Bounded, offline Zeek conn.log reader. No capture, network access or AI inference.

The returned contract deliberately differs from UNSW-NB15 model features:
Zeek records must NOT be fed into the existing 42-feature classifier.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from datetime import datetime, timezone
from pathlib import Path

MAX_LOG_BYTES = 15 * 1024 * 1024
MAX_RECORDS = 10_000
REQUIRED = frozenset({
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"
})


def _number(value: str, name: str, *, integer: bool = False) -> float | int | None:
    if value == "-":
        return None
    try:
        number = int(value) if integer else float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid Zeek {name}") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"Invalid Zeek {name}")
    return number


def _ip(value: str, name: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"Invalid Zeek {name}") from exc


def _port(value: str, name: str) -> int:
    port = _number(value, name, integer=True)
    if port is None or port > 65535:
        raise ValueError(f"Invalid Zeek {name}")
    return port


def parse_zeek_conn_log(
    data: bytes, *, max_bytes: int = MAX_LOG_BYTES, max_records: int = MAX_RECORDS
) -> list[dict]:
    """Parse genuine Zeek ASCII TSV into provenance-tagged offline flow events.

    Rejects malformed rows rather than silently truncating them. The source SHA-256
    is computed from the exact supplied bytes; no labels or predictions are added.
    """
    if not isinstance(data, bytes):
        raise TypeError("Zeek log must be bytes")
    if max_bytes <= 0 or max_records <= 0 or len(data) > max_bytes:
        raise ValueError("Zeek log exceeds configured limits")
    if b"\x00" in data:
        raise ValueError("NUL byte in Zeek log")
    text = data.decode("utf-8", errors="strict")
    lines = text.splitlines()
    if not lines or lines[0] != "#separator \\x09":
        raise ValueError("Expected Zeek ASCII tab separator header")
    fields: list[str] | None = None
    seen_types = False
    seen_set_separator = False
    seen_open = False
    seen_unset_field = False
    seen_empty_field = False
    seen_path = False
    seen_data = False
    closed = False
    digest = hashlib.sha256(data).hexdigest()
    events: list[dict] = []
    seen_uids: set[str] = set()
    for line in lines[1:]:
        if not line:
            continue
        # Zeek writes #close when the ASCII log ends. Never merge appended
        # records or a second log segment into one source/UID namespace.
        if closed:
            raise ValueError("Zeek content after close marker")
        if line.startswith("#close"):
            if (not line.startswith("#close\t") or not line[len("#close\t"):]
                    or fields is None or not seen_data):
                raise ValueError("Invalid or premature Zeek close marker")
            closed = True
            continue
        if line.startswith("#separator"):
            raise ValueError("Duplicate Zeek separator header")
        # Zeek ASCII can declare how missing and empty string values are
        # encoded. Silently ignoring non-default sentinels would turn missing
        # service values into model categories or corrupt feature missingness.
        # Legacy minimal fixtures may omit these optional metadata headers.
        # Optional Zeek ASCII metadata must not redefine set encoding or
        # claim a second log opening. Omission remains legacy-compatible.
        if line.startswith("#set_separator"):
            if (seen_set_separator or fields is not None
                    or line != "#set_separator\t,"):
                raise ValueError("Invalid, duplicate or late Zeek set_separator marker")
            seen_set_separator = True
            continue
        if line.startswith("#open"):
            if (seen_open or fields is not None or not line.startswith("#open\t")):
                raise ValueError("Invalid, duplicate or late Zeek open marker")
            opened_at = line[len("#open\t"):]
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}", opened_at):
                raise ValueError("Invalid Zeek open marker timestamp")
            try:
                datetime.strptime(opened_at, "%Y-%m-%d-%H-%M-%S")
            except ValueError as exc:
                raise ValueError("Invalid Zeek open marker timestamp") from exc
            seen_open = True
            continue
        if line.startswith("#unset_field"):
            if seen_unset_field or seen_data or line != "#unset_field\t-":
                raise ValueError("Invalid, duplicate or late Zeek unset_field marker")
            seen_unset_field = True
            continue
        if line.startswith("#empty_field"):
            if seen_empty_field or seen_data or line != "#empty_field\t(empty)":
                raise ValueError("Invalid, duplicate or late Zeek empty_field marker")
            seen_empty_field = True
            continue
        if line.startswith("#path"):
            if seen_path or seen_data or line != "#path\tconn":
                raise ValueError("Invalid, duplicate or late Zeek conn path marker")
            seen_path = True
            continue
        if line.startswith("#fields\t"):
            if fields is not None or seen_data:
                raise ValueError("Duplicate Zeek fields header")
            fields = line.split("\t")[1:]
            if len(fields) != len(set(fields)) or not REQUIRED.issubset(fields):
                raise ValueError("Invalid or incomplete Zeek conn.log fields")
            continue
        if line.startswith("#types\t"):
            # A declared schema cannot change after records begin. Keep the
            # historical optional #types behavior for minimal offline fixtures;
            # strict field-type validation remains an explicit quality gate.
            if (fields is None or seen_types or seen_data
                    or len(line.split("\t")) - 1 != len(fields)):
                raise ValueError("Duplicate, late or mismatched Zeek types header")
            seen_types = True
            continue
        if line.startswith("#") or not line:
            continue
        if fields is None:
            raise ValueError("Zeek record before fields header")
        seen_data = True
        values = line.split("\t")
        if len(values) != len(fields):
            raise ValueError("Zeek record has wrong field count")
        if len(events) >= max_records:
            raise ValueError("Zeek log exceeds record limit")
        row = dict(zip(fields, values))
        timestamp = _number(row["ts"], "ts")
        uid = row["uid"]
        proto = row["proto"]
        if timestamp is None or not uid or uid == "-" or len(uid) > 256 or not proto or proto == "-":
            raise ValueError("Zeek record lacks timestamp, UID or protocol")
        # A single conn.log must identify each connection unambiguously. Check
        # the entire source before any downstream UI/SOC writer can select it.
        if uid in seen_uids:
            raise ValueError("Duplicate Zeek UIDs in source capture")
        seen_uids.add(uid)
        try:
            utc_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("Invalid Zeek timestamp") from exc
        events.append({
            "origin": "offline_zeek_log",
            "source_sha256": digest,
            "event_time_utc": utc_time,
            "uid": uid,
            "src_ip": _ip(row["id.orig_h"], "source IP"),
            "src_port": _port(row["id.orig_p"], "source port"),
            "dst_ip": _ip(row["id.resp_h"], "destination IP"),
            "dst_port": _port(row["id.resp_p"], "destination port"),
            "proto": proto,
            "service": (None if row.get("service", "-") == "-" else
                        "" if seen_empty_field and row["service"] == "(empty)" else
                        row["service"]),
            "duration_s": _number(row.get("duration", "-"), "duration"),
            "orig_bytes": _number(row.get("orig_bytes", "-"), "orig_bytes", integer=True),
            "resp_bytes": _number(row.get("resp_bytes", "-"), "resp_bytes", integer=True),
            "orig_pkts": _number(row.get("orig_pkts", "-"), "orig_pkts", integer=True),
            "resp_pkts": _number(row.get("resp_pkts", "-"), "resp_pkts", integer=True),
        })
    if not events:
        raise ValueError("Zeek conn.log contains no flow records")
    return events


def load_zeek_conn_log(path: str | Path) -> list[dict]:
    """Read at most MAX_LOG_BYTES + 1 bytes from a user-selected local file."""
    with Path(path).open("rb") as source:
        data = source.read(MAX_LOG_BYTES + 1)
    return parse_zeek_conn_log(data)
