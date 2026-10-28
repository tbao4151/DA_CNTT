"""Explicit, bounded offline PCAP -> Zeek conn.log import for a private lab.

No live interface capture, network scanning, AI inference, or SOC writes.
The operator must supply a pre-existing classic PCAP and an installed Zeek.
"""
from __future__ import annotations

import hashlib
import json
import stat
import subprocess
from pathlib import Path

from .lab_scope import inspect_zeek_lab_scope
from .zeek import MAX_LOG_BYTES

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MAX_PCAP_BYTES = 64 * 1024 * 1024
PCAP_MAGICS = {bytes.fromhex(value) for value in (
    "a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1",
)}


def _private_path(value: str | Path, *, must_exist: bool) -> Path:
    if not isinstance(value, (str, Path)) or not str(value).strip():
        raise ValueError("Absolute private path required")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Absolute non-symlink private path required")
    resolved = path.resolve(strict=must_exist)
    if resolved.is_relative_to(REPOSITORY_ROOT):
        raise ValueError("Private PCAP and output must remain outside the repository")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def import_offline_pcap(
    pcap_path: str | Path,
    output_dir: str | Path,
    *,
    lab_cidrs: list[str],
    operator_confirmed_offline: bool,
    timeout_seconds: int = 120,
) -> dict[str, object]:
    """Run Zeek with -r ONLY; validate the generated ASCII conn.log and scope.

    An output directory must not exist before the run. On failure, preserve
    partial private files for manual inspection; never overwrite or delete them.
    This is an import, not evidence of authentic VMware Host-only capture.
    """
    if operator_confirmed_offline is not True:
        raise ValueError("Explicit offline import confirmation required")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ValueError("Invalid bounded Zeek timeout")
    source = _private_path(pcap_path, must_exist=True)
    destination = _private_path(output_dir, must_exist=False)
    if not source.is_file() or not stat.S_ISREG(source.stat().st_mode):
        raise ValueError("PCAP must be a regular file")
    size = source.stat().st_size
    if not 24 <= size <= MAX_PCAP_BYTES:
        raise ValueError("PCAP is empty, truncated or exceeds size limit")
    with source.open("rb") as stream:
        if stream.read(4) not in PCAP_MAGICS:
            raise ValueError("Only classic PCAP files are supported (not PCAPNG)")
    source_sha = _sha256_file(source)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Output directory must not already exist")
    parent = destination.parent
    if not parent.is_dir() or parent.is_symlink() or parent.is_relative_to(REPOSITORY_ROOT):
        raise ValueError("Output parent must be an existing private directory")
    if destination == source or destination in source.parents:
        raise ValueError("Output cannot contain the original PCAP")
    # Fail before creating files for invalid scope declarations.
    from .lab_scope import _networks
    _networks(lab_cidrs)

    destination.mkdir(exist_ok=False)
    try:
        # -r is an offline file reader, never -i (live network interface).
        # Do not use shell=True or execute user-provided Zeek scripts.
        completed = subprocess.run(
            ["zeek", "-r", str(source)],
            cwd=destination, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout_seconds, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise ValueError("Offline Zeek import failed; inspect private output directory") from exc
    if completed.returncode != 0:
        raise ValueError("Offline Zeek exited unsuccessfully; inspect private output directory")
    if _sha256_file(source) != source_sha:
        raise ValueError("Original PCAP changed during offline import")
    conn_log = destination / "conn.log"
    if conn_log.is_symlink() or not conn_log.is_file():
        raise ValueError("Zeek did not produce a regular ASCII conn.log")
    log_size = conn_log.stat().st_size
    if not 0 < log_size <= MAX_LOG_BYTES:
        raise ValueError("Generated Zeek conn.log is empty or exceeds parser limit")
    raw = conn_log.read_bytes()
    scope = inspect_zeek_lab_scope(raw, lab_cidrs)
    result: dict[str, object] = {
        "report_version": 1,
        "mode": "offline_classic_pcap_to_zeek_import",
        "source_kind": "operator_supplied_offline_pcap",
        "pcap_sha256": source_sha,
        "pcap_size_bytes": size,
        "zeek_conn_sha256": hashlib.sha256(raw).hexdigest(),
        "zeek_conn_size_bytes": log_size,
        "flow_count": scope["flow_count"],
        "declared_scope_sha256": scope["declared_scope_sha256"],
        "all_endpoints_within_declared_scope": True,
        "host_only_isolation_verified": False,
        "capture_authenticity_verified": False,
        "authorization_verified": False,
        "ground_truth_verified": False,
        "ai_inference_performed": False,
        "automated_alerts": False,
        "live_capture": False,
        "interpretation": (
            "Zeek processed a pre-existing classic PCAP offline. CIDR membership "
            "does not prove capture authenticity, VMware isolation, authorization "
            "or attack detection. Keep original PCAP and private Zeek logs."
        ),
    }
    with (destination / "offline_import_report.json").open("x", encoding="utf-8") as target:
        json.dump(result, target, indent=2, ensure_ascii=False, allow_nan=False)
        target.write("\n")
    return result
