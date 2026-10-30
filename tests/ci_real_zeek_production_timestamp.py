"""CI-only acceptance of the production opt-in timestamp gate on real Zeek output.

All inputs originate from a benign synthetic PCAP and network-disabled Zeek.
The negative fixture deliberately re-pins *fabricated CI-only metadata* so
the timestamp gate, not an earlier SHA-256 mismatch, must refuse it. Neither
the synthetic model nor these self-generated pins authenticate provenance.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CIDR = "192.168.56.0/24"
GATE = "--require-pcap-zeek-timestamp-corroboration"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shift_all_fixture_packet_timestamps(data: bytes, seconds: int = 120) -> bytes:
    """Shift every complete little-endian microsecond PCAP record, not payloads."""
    if not isinstance(data, bytes) or len(data) < 24 or data[:4] != bytes.fromhex("d4c3b2a1"):
        raise ValueError("Expected complete little-endian microsecond CI PCAP")
    if type(seconds) is not int or not 2 <= seconds <= 3600:
        raise ValueError("Invalid CI timestamp shift")
    shifted = bytearray(data)
    offset = 24
    count = 0
    while offset < len(shifted):
        if offset + 16 > len(shifted):
            raise ValueError("Truncated CI packet header")
        timestamp, fraction, included, original = struct.unpack_from("<IIII", shifted, offset)
        if (included == 0 or included > original
                or offset + 16 + included > len(shifted)
                or timestamp > 0xFFFFFFFF - seconds):
            raise ValueError("Invalid CI packet length or timestamp")
        struct.pack_into("<I", shifted, offset, timestamp + seconds)
        offset += 16 + included
        count += 1
    if count < 2 or offset != len(shifted):
        raise ValueError("Expected at least two complete CI packets")
    return bytes(shifted)


def _score(
    *, model: Path, model_sha: str, log: Path, log_sha: str,
    pcap: Path, import_report: Path, import_sha: str, output: Path,
    timestamp_gate: bool,
) -> dict[str, object] | None:
    command = [
        sys.executable, str(ROOT / "scripts" / "score_zeek_new_log.py"),
        "--model", str(model), "--expected-model-sha256", model_sha,
        "--log", str(log), "--expected-log-sha256", log_sha,
        "--cidr", CIDR,
        "--offline-import-report", str(import_report),
        "--expected-offline-import-report-sha256", import_sha,
        "--offline-import-pcap", str(pcap),
        "--output", str(output),
    ]
    if timestamp_gate:
        command.append(GATE)
    completed = subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=60,
    )
    if timestamp_gate and output.name == "ci_timestamp_negative_refused.json":
        if completed.returncode != 1 or output.exists():
            raise ValueError("Production timestamp gate accepted stale synthetic PCAP")
        return None
    if completed.returncode != 0 or not output.is_file():
        raise ValueError("Production synthetic scoring acceptance failed")
    return json.loads(output.read_text(encoding="utf-8"))


def exercise_production_timestamp_gate(
    *, root: Path, model: Path, model_sha: str, log: Path,
    log_sha: str, pcap: Path, import_report: Path, import_sha: str,
    baseline_report: dict[str, object],
) -> dict[str, object]:
    """Check real-Zeek production opt-in scoring and coherent negative fixture."""
    accepted_path = log.parent / "ci_timestamp_gated_predictions.json"
    accepted = _score(
        model=model, model_sha=model_sha, log=log, log_sha=log_sha,
        pcap=pcap, import_report=import_report, import_sha=import_sha,
        output=accepted_path, timestamp_gate=True,
    )
    if accepted != baseline_report:
        raise ValueError("Opt-in timestamp gate changed research prediction semantics")

    # Mutate only packet timestamps. Make a fresh, explicitly fabricated
    # CI-only import-report copy with matching hashes to isolate the timestamp
    # check from the earlier, separately pinned integrity checks.
    shifted_pcap = root / "ci_timestamp_shifted_negative_only.pcap"
    with shifted_pcap.open("xb") as stream:
        stream.write(shift_all_fixture_packet_timestamps(pcap.read_bytes()))
    negative = root / "ci_timestamp_negative_only"
    negative.mkdir(exist_ok=False)
    negative_log = negative / "conn.log"
    shutil.copyfile(log, negative_log)
    negative_report = negative / "offline_import_report.json"
    metadata = json.loads(import_report.read_text(encoding="utf-8"))
    metadata["pcap_sha256"] = _sha(shifted_pcap.read_bytes())
    metadata["pcap_size_bytes"] = shifted_pcap.stat().st_size
    with negative_report.open("x", encoding="utf-8") as stream:
        json.dump(metadata, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    negative_sha = _sha(negative_report.read_bytes())
    common = dict(
        model=model, model_sha=model_sha, log=negative_log, log_sha=log_sha,
        pcap=shifted_pcap, import_report=negative_report, import_sha=negative_sha,
    )
    # The old production scorer has no temporal gate: it should accept the
    # deliberately re-pinned negative fixture and produce identical scores.
    legacy = _score(
        **common, output=negative / "ci_timestamp_negative_legacy.json",
        timestamp_gate=False,
    )
    if legacy != baseline_report:
        raise ValueError("Negative fixture changed non-temporal prediction semantics")
    _score(
        **common, output=negative / "ci_timestamp_negative_refused.json",
        timestamp_gate=True,
    )
    if any(negative.glob("*.sqlite3")):
        raise ValueError("Synthetic timestamp gate created unexpected SOC state")
    return {
        "production_timestamp_gate_real_zeek_synthetic_ci_passed": True,
        "production_timestamp_gate_scores_equal_legacy_ci_only": True,
        "repinned_shifted_pcap_legacy_accepted_ci_only": True,
        "repinned_shifted_pcap_timestamp_rejected_ci_only": True,
        "repinned_negative_import_metadata_authentic": False,
        "independent_capture_provenance_authenticated": False,
    }
