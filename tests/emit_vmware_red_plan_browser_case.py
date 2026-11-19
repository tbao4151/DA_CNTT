"""Emit genuine Python v2 UCB1 planning receipt and dry-run JSONL for Chromium.

ALL network and SSH functions are explicitly forbidden; this fixture is not
physical VMware evidence, a live attack, or a verified Blue prediction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_vmware_session_profile as launcher
import run_vmware_stepwise as stepwise


def generate(output_dir: Path) -> dict[str, Path]:
    if not output_dir.is_absolute() or output_dir.is_symlink() or not output_dir.is_dir():
        raise ValueError("Only an existing absolute private test directory is allowed")
    if output_dir.resolve(strict=True).is_relative_to(ROOT):
        raise ValueError("Do not place private QA fixture files inside Git")
    known_hosts = output_dir / "mock_known_hosts"
    if not known_hosts.is_file():
        raise ValueError("Create a mock known_hosts in the private QA folder before this test")

    profile = {
        "version": 2,
        "source_ip": "192.168.77.1",
        "target_ip": "192.168.77.20",
        "cidr": "192.168.77.0/24",
        "scenario_id": "dns_variation",
        "username": "mock_ubuntu",
        "known_hosts": str(known_hosts),
        "output_dir": str(output_dir),
        "stop_file": str(output_dir / "DA005_STOP.flag"),
        "attempts": 2,
        "settle_s": 0,
        "model_path": None,
        "expected_model_sha256": None,
        "red_policy": {
            "strategy": "ucb1", "seed": 42,
            "feedback": [
                {"scenario_id": "baseline_web", "blue_flagged": True},
                {"scenario_id": "dns_variation", "blue_flagged": False},
                {"scenario_id": "connection_shift", "blue_flagged": True},
            ],
            "expected_scenario_id": "dns_variation",
        },
    }
    profile_path = output_dir / "mock_operator_profile_v2.json"
    with profile_path.open("x", encoding="utf-8") as stream:
        json.dump(profile, stream, sort_keys=True, allow_nan=False)
        stream.write("\n")
    sha256 = hashlib.sha256(profile_path.read_bytes()).hexdigest()

    progress = output_dir / "python_ucb1.jsonl"
    def forbidden(**_kwargs):
        raise AssertionError("Network, SSH and inference are forbidden in this dry-run")
    with (
        patch.object(stepwise.stimulus, "send_benign_probe", side_effect=forbidden),
        patch.object(stepwise.collector, "fetch", side_effect=forbidden),
        patch.object(stepwise.blue, "run_bridge", side_effect=forbidden),
    ):
        assert launcher.run_profile(
            config_file=profile_path, expected_sha256=sha256,
            jsonl_file=progress, execute=False,
        ) == 0

    plan_file = output_dir / "python_ucb1.red-plan.json"
    receipt = json.loads(plan_file.read_text(encoding="utf-8"))
    assert receipt["profile_sha256"] == sha256
    assert receipt["strategy"] == "ucb1"
    assert receipt["selected_scenario_id"] == "dns_variation"
    assert receipt["feedback_count"] == 3
    assert receipt["planning_only"] is True
    assert receipt["attack_executed"] is False
    assert receipt["verified_ai_detection"] is False
    assert receipt["soc_alerts_created"] is False
    for private in ("192.168.", str(output_dir)):
        assert private not in plan_file.read_text(encoding="utf-8")
        assert private not in progress.read_text(encoding="utf-8")
    rows = [json.loads(row) for row in progress.read_text(encoding="utf-8").splitlines()]
    assert [row["status"] for row in rows] == ["dry_run", "dry_run"]
    assert rows[-1]["result"]["network_attempts"] == 0
    assert rows[-1]["result"]["ssh_fetch_performed"] is False
    return {"profile": profile_path, "progress": progress, "plan": plan_file}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    options = parser.parse_args(argv)
    outputs = generate(options.output_dir)
    print("Created network-free SHA-pinned Python UCB1 planning and dry-run test cases: "
          + ", ".join(outputs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
