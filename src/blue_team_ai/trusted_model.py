"""Bounded, SHA-256-pinned loader for PRIVATE data-only Zeek research models.

The expected digest must be recorded independently of the JSON file.
This checks byte integrity against that reference, not authorship, label truth,
VMware isolation, model performance, or suitability for operational alerts.
No pickle, executable deserialization, network access, or SOC writes.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from .model_artifact import validate_zeek_research_artifact

MAX_MODEL_BYTES = 2 * 1024 * 1024
_HEX = frozenset("0123456789abcdef")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key in Zeek model JSON")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Non-standard numeric constant in Zeek model JSON")


def load_pinned_zeek_research_model(
    path: str | Path, *, expected_sha256: str,
) -> dict[str, object]:
    """Verify exact bytes BEFORE parsing; reject unsafe or incompatible JSON.

    Rejects direct symlinks and non-regular files. O_NOFOLLOW is used where
    supported; Windows callers should also keep the private directory trusted.
    The reference SHA-256 must come from a separately preserved lab record.
    """
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(char not in _HEX for char in expected_sha256)
    ):
        raise ValueError("Expected a separately recorded lowercase SHA-256")
    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError("Zeek model symlinks are not accepted")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Zeek model must be a regular file")
            payload = stream.read(MAX_MODEL_BYTES + 1)
    except (OSError, TypeError) as exc:
        raise ValueError("Cannot read private Zeek model") from exc
    if not 0 < len(payload) <= MAX_MODEL_BYTES:
        raise ValueError("Zeek model exceeds size limit or is empty")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError("Zeek model SHA-256 does not match pinned reference")
    try:
        artifact = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise ValueError("Invalid Zeek model JSON") from exc
    validate_zeek_research_artifact(artifact)
    return artifact
