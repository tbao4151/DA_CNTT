"""Offline synthetic contract tests. Never run VMware or capture traffic."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_vmware_session_record.py"
CHECKS = ("authorization", "vmware_hostonly_adapters", "guest_route_review", "capture_origin")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _setup(tmp_path: Path):
    private = tmp_path / "private"
    private.mkdir()
    checks = {}
    for key in CHECKS:
        raw = ("synthetic-" + key).encode()
        (private / (key + ".txt")).write_bytes(raw)
        checks[key] = {"status": "PASS", "path": key + ".txt", "sha256": _sha(raw)}
    chain = {
        "report_version": 1, "mode": "offline_private_lab_evidence_consistency_only",
        "configuration_snapshots_consistent": True,
        "offline_pcap_zeek_import_consistent": True,
        "independent_original_pcap_zeek_pins_verified": True,
        "independent_original_pcap_zeek_pins_required": True,
        "pcap_framing_required": True, "pcap_framing_verified": True,
        "pcap_packet_count": 4, "zeek_flow_count": 1,
        "vmware_isolation_verified": False, "capture_authenticity_verified": False,
        "traffic_authorized": False, "independent_labels_verified": False,
        "ai_inference_performed": False, "operational_alerts_created": False,
        "soc_case_created": False, "live_detection_latency_measured": False,
    }
    record = {"record_version": 1, "session_id": "session-001", "checks": checks}
    return private, record, chain


def _run(private: Path, record: dict, chain: dict, *, mutate=None):
    record_raw = json.dumps(record).encode()
    chain_raw = json.dumps(chain).encode()
    record_path, chain_path = private / "record.json", private / "chain.json"
    record_path.write_bytes(record_raw)
    chain_path.write_bytes(chain_raw)
    args = [sys.executable, str(SCRIPT), "--record", str(record_path),
            "--expected-record-sha256", _sha(record_raw),
            "--chain-report", str(chain_path), "--expected-chain-sha256", _sha(chain_raw)]
    if mutate:
        mutate(args, private)
    return subprocess.run(args, capture_output=True, text=True)


def test_valid_synthetic_record_is_only_ready_for_human_review(tmp_path):
    private, record, chain = _setup(tmp_path)
    result = _run(private, record, chain)
    assert result.returncode == 0, result.stderr
    obj = json.loads(result.stdout)
    assert obj["ready_for_human_evidence_review"] is True
    assert obj["manual_evidence_hashes_checked"] == 4
    assert obj["vmware_isolation_verified_by_software"] is False
    assert obj["operator_authorization_verified_by_software"] is False
    assert obj["attack_detection_validated"] is False
    assert "synthetic-" not in result.stdout
    assert str(private) not in result.stdout


def test_not_measured_is_recorded_but_not_accepted(tmp_path):
    private, record, chain = _setup(tmp_path)
    record["checks"]["capture_origin"] = {"status": "NOT_MEASURED"}
    result = _run(private, record, chain)
    assert result.returncode == 2
    assert json.loads(result.stdout)["ready_for_human_evidence_review"] is False


@pytest.mark.parametrize("kind", [
    "tampered_evidence", "symlink", "traversal", "missing_pin", "fake_chain",
    "unframed", "bad_record_pin", "duplicate_json", "oversized_evidence",
])
def test_invalid_or_unsupported_evidence_refused_without_leaking_paths(tmp_path, kind):
    private, record, chain = _setup(tmp_path)
    if kind == "traversal":
        record["checks"]["authorization"]["path"] = "../private/authorization.txt"
    elif kind == "missing_pin":
        del record["checks"]["authorization"]["sha256"]
    elif kind == "fake_chain":
        chain["vmware_isolation_verified"] = True
    elif kind == "unframed":
        chain["pcap_framing_verified"] = False

    def mutate(args, root):
        if kind == "tampered_evidence":
            (root / "authorization.txt").write_bytes(b"changed")
        elif kind == "symlink":
            original = root / "authorization.txt"
            alias = root / "alias.txt"
            alias.symlink_to(original)
            rec = json.loads((root / "record.json").read_text())
            rec["checks"]["authorization"]["path"] = "alias.txt"
            raw = json.dumps(rec).encode()
            (root / "record.json").write_bytes(raw)
            args[args.index("--expected-record-sha256") + 1] = _sha(raw)
        elif kind == "bad_record_pin":
            args[args.index("--expected-record-sha256") + 1] = "0" * 64
        elif kind == "duplicate_json":
            raw = (root / "record.json").read_bytes()
            raw = raw.replace(b'"record_version": 1,', b'"record_version": 1, "record_version": 1,')
            (root / "record.json").write_bytes(raw)
            args[args.index("--expected-record-sha256") + 1] = _sha(raw)
        elif kind == "oversized_evidence":
            (root / "authorization.txt").write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    result = _run(private, record, chain, mutate=mutate)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "refused" in result.stderr
    assert str(private) not in result.stderr
