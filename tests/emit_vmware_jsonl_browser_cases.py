"""Generate strict JSONL cross-stack QA inputs; NEVER probes, SSH, or AI inference.

This script intentionally uses the real stepwise CLI and exclusive UTF-8
writer, while forcing mocked network functions for its "completed" case.
The only non-mocked execution is DRY-RUN, which has execution OFF.
Evidence files here are test fixtures and MUST NOT be cited as VM captures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_vmware_progress_file as writer
import run_vmware_stepwise as stepwise

NOW = datetime(2026, 11, 19, 5, tzinfo=timezone.utc)
SOURCE, TARGET, CIDR = "192.168.77.1", "192.168.77.20", "192.168.77.0/24"


def fixture_raw() -> bytes:
    header = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
    rows = [
        f"{ts.timestamp():.3f}\t{uid}\t{SOURCE}\t54321\t{TARGET}\t22\ttcp"
        for ts, uid in [(NOW, "CmockOne"), (NOW + timedelta(seconds=3), "CmockTwo")]
    ]
    return (header + "\n".join(rows) + "\n").encode("utf-8")


def mocked_probe_receipt() -> dict[str, object]:
    return {
        "kind": "da005_benign_vmware_hostonly_network_stimulus",
        "mode": "BENIGN_LAB_EXECUTION",
        "scenario_id": "connection_shift",
        "scope": {"source_ip": SOURCE, "target_ip": TARGET, "cidr": CIDR},
        "network_attempts": 2,
        "planned_attempts": 2,
        "private_receipt_filename": "mock_probe_receipt.json",
        "events": [
            {"scenario_id": "connection_shift", "protocol": "tcp",
             "port": 22, "attempted_at_utc": NOW.isoformat()},
            {"scenario_id": "connection_shift", "protocol": "tcp",
             "port": 22, "attempted_at_utc": (NOW + timedelta(seconds=3)).isoformat()},
        ],
    }


def generate(output_dir: Path) -> dict[str, Path]:
    if not output_dir.is_absolute() or output_dir.is_symlink() or not output_dir.is_dir():
        raise ValueError("Need an existing absolute private QA output directory")
    if output_dir.resolve(strict=True).is_relative_to(ROOT):
        raise ValueError("Never save the simulated cases in the Git checkout")
    known = output_dir / "mock_known_hosts"
    if known.exists():
        raise ValueError("QA output directory must be fresh; mock known_hosts exists")
    known.write_text("synthetic key used for network-free QA only\n", encoding="utf-8")
    common = [
        "--source-ip", SOURCE, "--target-ip", TARGET,
        "--cidr", CIDR, "--scenario", "connection_shift",
        "--user", "mock_ubuntu", "--known-hosts", str(known),
        "--output-dir", str(output_dir), "--settle-s", "0",
    ]

    # Real CLI dry-run: no monkeypatching and no SSH/probes.
    dry = output_dir / "python_dryrun.jsonl"
    assert writer.run_to_file(jsonl_file=dry, cli_args=common) == 0
    assert [json.loads(line)["status"] for line in dry.read_text(encoding="utf-8").splitlines()] == ["dry_run", "dry_run"]

    # Mocked "execute" *never* touches a socket: neither stimulus nor SSH nor
    # Blue model can execute, although the original stepwise event emitter does.
    complete = output_dir / "python_mock_completed.jsonl"
    raw = fixture_raw()

    def fake_stimulus(**kwargs):
        return mocked_probe_receipt() if kwargs["execute"] else {"network_attempts": 0}

    def fake_fetch(**_kwargs):
        name = "mock_conn.log"
        (output_dir / name).write_bytes(raw)
        return {
            "local_log_filename": name,
            "log_sha256": hashlib.sha256(raw).hexdigest(),
            "flow_count": 2,
        }

    def forbid(**_kwargs):
        raise AssertionError("Network/SSH/AI call prohibited in QA")

    with (
        patch.object(stepwise.stimulus, "run", side_effect=fake_stimulus),
        patch.object(stepwise.stimulus, "send_benign_probe", side_effect=forbid),
        patch.object(stepwise.collector, "fetch", side_effect=fake_fetch),
        patch.object(stepwise.blue, "run_bridge", side_effect=forbid),
        patch.object(stepwise.time, "sleep", side_effect=forbid),
    ):
        assert writer.run_to_file(
            jsonl_file=complete,
            cli_args=[*common, "--execute", "--operator-confirmed-hostonly"],
        ) == 0

    mock_rows = [json.loads(row) for row in complete.read_text(encoding="utf-8").splitlines()]
    assert len(mock_rows) == 10
    assert [(r["stage"], r["status"]) for r in mock_rows[:-1]] == [
        ("preflight", "completed"), ("red", "running"), ("red", "completed"),
        ("zeek", "running"), ("zeek", "completed"), ("blue", "skipped"),
        ("audit", "running"), ("audit", "completed"), ("soc", "skipped"),
    ]
    assert mock_rows[-1]["status"] == "completed"
    assert mock_rows[-1]["result"]["network_attempts"] == 2
    assert mock_rows[-1]["result"]["captured_log_flow_count"] == 2
    assert mock_rows[-1]["result"]["soc_alerts_created"] is False
    assert "192.168." not in complete.read_text(encoding="utf-8")
    assert str(output_dir) not in complete.read_text(encoding="utf-8")

    # An explicit execute WITHOUT authorization is fail-closed before any packet.
    refused = output_dir / "python_no_consent.jsonl"
    with patch.object(stepwise.stimulus, "send_benign_probe", side_effect=forbid):
        assert writer.run_to_file(jsonl_file=refused, cli_args=[*common, "--execute"]) == 1
    rows = [json.loads(line) for line in refused.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1 and rows[0]["status"] == "refused"
    assert rows[0]["attack_executed"] is False

    return {"dry_run": dry, "mock_completed": complete, "refused": refused}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    opts = parser.parse_args(argv)
    outputs = generate(opts.output_dir)
    print("Generated network-free Python->JSONL QA cases: " + ", ".join(outputs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
