"""Deterministic, benign synthetic PCAP acceptance check for a real local Zeek.

This module never opens a socket, captures an interface, or generates attacks.
It exercises the existing offline importer and independently pinned verifier.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import struct
import subprocess
from datetime import datetime
from pathlib import Path

from .offline_pcap import _private_path, import_offline_pcap
from .offline_pcap_verify import verify_offline_pcap_import
from .zeek import load_zeek_conn_log

FIXTURE_CIDR = "192.168.56.0/24"
SOURCE_IP = "192.168.56.10"
DESTINATION_IP = "192.168.56.20"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_benign_udp_pcap() -> bytes:
    """Build two local-scope UDP frames as classic Ethernet PCAP, no network I/O.

    Fixed timestamps and payloads are intentionally synthetic, not observations
    from VMware. IPv4 header checksums are computed; IPv4 UDP checksum 0 is valid.
    """
    pcap = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    src = ipaddress.IPv4Address(SOURCE_IP).packed
    dst = ipaddress.IPv4Address(DESTINATION_IP).packed
    ethernet = bytes.fromhex("0200000000200200000000100800")
    for index in range(2):
        payload = f"DA005-BENIGN-OFFLINE-{index}".encode("ascii")
        udp = struct.pack("!HHHH", 51000, 53000, 8 + len(payload), 0) + payload
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 20 + len(udp), 0xDA05 + index, 0, 64, 17, 0, src, dst,
        )
        header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
        frame = ethernet + header + udp
        pcap.extend(struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame)))
        pcap.extend(frame)
    return bytes(pcap)



def _verify_fixture_flow(conn_log: Path) -> None:
    """Require Zeek's flow to match the exact generated synthetic packet tuple.

    CIDR membership and matching hashes alone cannot establish that Zeek
    decoded *this* fixture. This is only an offline toolchain acceptance guard,
    not proof of genuine capture, isolation, attack labels or AI detection.
    """
    events = load_zeek_conn_log(conn_log)
    if len(events) != 1:
        raise ValueError("Benign smoke requires exactly one fixture flow")
    event = events[0]
    expected = {
        "src_ip": SOURCE_IP,
        "src_port": 51000,
        "dst_ip": DESTINATION_IP,
        "dst_port": 53000,
        "proto": "udp",
    }
    if any(event.get(field) != value for field, value in expected.items()):
        raise ValueError("Zeek flow does not match generated benign UDP fixture")
    # The first of two deterministic packets starts at this UTC epoch second.
    # Allow only sub-millisecond representation differences in Zeek ASCII logs.
    timestamp = datetime.fromisoformat(event["event_time_utc"]).timestamp()
    if abs(timestamp - 1700000000) > 0.001:
        raise ValueError("Zeek flow timestamp does not match synthetic PCAP")


def _zeek_version() -> str:
    try:
        completed = subprocess.run(
            ["zeek", "--version"], capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Zeek executable unavailable for offline smoke test") from exc
    version = (completed.stdout + "\n" + completed.stderr).strip()
    if completed.returncode != 0 or not version or len(version) > 512:
        raise ValueError("Could not establish local Zeek version")
    return version[:160]


def run_benign_zeek_smoke(
    output_dir: str | Path, *, operator_confirmed_synthetic: bool
) -> dict[str, object]:
    """Run actual local zeek -r on a generated benign PCAP; retain private evidence.

    The caller supplies a NEW absolute private directory. Never overwrite or
    delete prior captures, models, databases, or case evidence.
    """
    if operator_confirmed_synthetic is not True:
        raise ValueError("Explicit synthetic-only confirmation required")
    root = _private_path(output_dir, must_exist=False)
    if root.exists() or root.is_symlink():
        raise ValueError("Smoke output directory must not already exist")
    if not root.parent.is_dir() or root.parent.is_symlink():
        raise ValueError("Smoke output parent must be an existing private directory")
    version = _zeek_version()
    root.mkdir(exist_ok=False)
    pcap_path = root / "benign_synthetic.pcap"
    with pcap_path.open("xb") as target:
        target.write(build_benign_udp_pcap())
    zeek_output = root / "zeek-import"
    imported = import_offline_pcap(
        pcap_path, zeek_output, lab_cidrs=[FIXTURE_CIDR],
        operator_confirmed_offline=True,
    )
    report_path = zeek_output / "offline_import_report.json"
    report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
    verified = verify_offline_pcap_import(
        report_path, expected_report_sha256=report_sha,
        pcap_path=pcap_path, log_path=zeek_output / "conn.log",
        lab_cidrs=[FIXTURE_CIDR],
    )
    if verified["zeek_conn_sha256"] != imported["zeek_conn_sha256"]:
        raise ValueError("Offline Zeek verification mismatch")
    _verify_fixture_flow(zeek_output / "conn.log")
    result: dict[str, object] = {
        "report_version": 1,
        "source_kind": "synthetic_benign_udp_fixture",
        "execution": "local_zeek_binary_offline_file_mode",
        "zeek_version_reported": version,
        "declared_cidr": FIXTURE_CIDR,
        "pcap_sha256": imported["pcap_sha256"],
        "zeek_conn_sha256": imported["zeek_conn_sha256"],
        "offline_import_report_sha256": report_sha,
        "flow_count": imported["flow_count"],
        "fixture_flow_identity_verified": True,
        "fixture_event_time_verified": True,
        "import_and_verification_succeeded": True,
        "vmware_capture_performed": False,
        "host_only_isolation_verified": False,
        "attack_ground_truth_verified": False,
        "ai_scoring_performed": False,
        "soc_case_created": False,
        "interpretation": (
            "Synthetic benign offline Zeek smoke only. Not a VMware capture, "
            "attack detection, network isolation proof or measured AI performance."
        ),
    }
    with (root / "smoke_report.json").open("x", encoding="utf-8") as target:
        json.dump(result, target, indent=2, ensure_ascii=False, allow_nan=False)
        target.write("\n")
    return result
