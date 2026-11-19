"""Launch one PRIVATE, SHA-256-pinned operator-assisted VMware lab session.

Uses the existing bounded benign traffic -> Zeek SCP -> optional pinned Blue
research scoring pipeline. Not autonomous attack AI, verified detection, SOC
alerting, or an API execution endpoint. DRY-RUN and zero sockets by default.
This utility does not modify VMware networking or verify physical isolation.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from pathlib import Path

import run_hostonly_benign_traffic as stimulus
import run_vmware_progress_file as writer
import run_vmware_stepwise as stepwise
from red_team_ai.scenario_policy import choose_scenario

ROOT = Path(__file__).resolve().parents[1]
MAX_CONFIG_BYTES = 16 * 1024
PIN = re.compile(r"[0-9a-f]{64}\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
REQUIRED = frozenset({
    "version", "source_ip", "target_ip", "cidr", "scenario_id",
    "username", "known_hosts", "output_dir", "stop_file",
    "attempts", "settle_s", "model_path", "expected_model_sha256",
})

REQUIRED_V2 = REQUIRED | {"red_policy"}
RED_POLICY_KEYS = frozenset({"strategy", "seed", "feedback", "expected_scenario_id"})
MAX_OPERATOR_FEEDBACK = 128


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON configuration key")
        obj[key] = value
    return obj


def _private_regular(path: Path, *, limit: int) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Configuration must be absolute, non-symlink and private")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(ROOT):
        raise ValueError("Configuration must not be stored in source repository")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Configuration must be a regular file")
        raw = stream.read(limit + 1)
    if len(raw) == 0 or len(raw) > limit:
        raise ValueError("Configuration file is missing, empty or oversized")
    return raw


def _private_string_path(value: object, *, purpose: str) -> Path:
    if not isinstance(value, str) or len(value) == 0 or len(value) > 480:
        raise ValueError("Invalid private " + purpose + " path")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Private " + purpose + " path must be absolute and not a symlink")
    return path


def load_config(config_file: Path, expected_sha256: str) -> dict[str, object]:
    """Validate a pinned private operator profile without creating or executing anything."""
    if not isinstance(expected_sha256, str) or PIN.fullmatch(expected_sha256) is None:
        raise ValueError("Independently recorded lowercase SHA-256 is required")
    raw = _private_regular(config_file, limit=MAX_CONFIG_BYTES)
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
        raise ValueError("Private operator profile SHA-256 mismatch")
    obj = json.loads(
        raw.decode("utf-8", errors="strict"), object_pairs_hook=_no_duplicate_keys,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
    )
    if not isinstance(obj, dict) or type(obj.get("version")) is not int:
        raise ValueError("Operator profile must declare an integer version")
    version = obj["version"]
    if version not in (1, 2) or set(obj) != (REQUIRED if version == 1 else REQUIRED_V2):
        raise ValueError("Operator profile contains unsupported version or properties")
    for field in ("source_ip", "target_ip", "cidr"):
        if not isinstance(obj[field], str):
            raise ValueError("Expected canonical IPv4/CIDR text")
    stimulus.validate_scope(
        source_ip=obj["source_ip"], target_ip=obj["target_ip"], cidr=obj["cidr"],
    )
    if type(obj["scenario_id"]) is not str or obj["scenario_id"] not in stimulus.SCENARIOS:
        raise ValueError("Scenario must be a catalogued bounded benign probe")
    if type(obj["username"]) is not str or USER.fullmatch(obj["username"]) is None:
        raise ValueError("Guest SSH username must be a bounded Linux account")
    if type(obj["attempts"]) is not int or not 1 <= obj["attempts"] <= 4:
        raise ValueError("Only 1..4 bounded probes allowed")
    if type(obj["settle_s"]) is not int or not 0 <= obj["settle_s"] <= 5:
        raise ValueError("Only 0..5 seconds capture flush wait allowed")

    output_dir = _private_string_path(obj["output_dir"], purpose="output directory")
    output = stimulus._private_dir(output_dir)
    known = _private_string_path(obj["known_hosts"], purpose="SSH known_hosts")
    known_resolved = known.resolve(strict=True)
    if not known_resolved.is_file() or known_resolved.is_relative_to(ROOT):
        raise ValueError("Pinned SSH known_hosts must be a regular private file outside Git")
    if not isinstance(obj["stop_file"], str):
        raise ValueError("STOP marker must be a canonical private absolute path")
    stop_file = _private_string_path(obj["stop_file"], purpose="STOP marker")
    if stop_file.parent.resolve(strict=True) != output or stop_file.name != "DA005_STOP.flag":
        raise ValueError("STOP marker must share the exact private evidence directory")
    # Validate marker's location/symlink before creating a file. A preexisting
    # marker refuses executable runs at the existing stepwise boundary.
    stepwise._make_stop_checker(stop_file, output)

    model_path, model_pin = obj["model_path"], obj["expected_model_sha256"]
    if (model_path is None) != (model_pin is None):
        raise ValueError("Pinned Blue model and independent hash must appear together")
    if model_path is not None:
        model = _private_string_path(model_path, purpose="Blue research model")
        if model.resolve(strict=True).is_relative_to(ROOT):
            raise ValueError("Blue research model may not be in Git")
        if not isinstance(model_pin, str) or PIN.fullmatch(model_pin) is None:
            raise ValueError("Expected lowercase SHA-256 for private Blue model")
    if version == 2:
        # The offline planner cannot expand the existing fixed benign scenario
        # catalog. The operator must independently approve the exact decision
        # by pinning it as scenario_id AND expected_scenario_id in this file.
        _red_plan(obj)
    return obj


def _red_plan(profile: dict[str, object]) -> dict[str, object]:
    """Recompute an unverified UCB1/random label inside an approved v2 profile."""
    if profile["version"] != 2:
        raise ValueError("Red planner is only permitted in profile v2")
    policy = profile.get("red_policy")
    if not isinstance(policy, dict) or set(policy) != RED_POLICY_KEYS:
        raise ValueError("Red policy must include only four fixed parameters")
    feedback = policy["feedback"]
    if not isinstance(feedback, list) or len(feedback) > MAX_OPERATOR_FEEDBACK:
        raise ValueError("Red policy feedback must be a bounded operator-entered list")
    result = choose_scenario(
        feedback, strategy=policy["strategy"], seed=policy["seed"],
    )
    if (
        type(policy["expected_scenario_id"]) is not str
        or policy["expected_scenario_id"] != profile["scenario_id"]
        or result["scenario_id"] != policy["expected_scenario_id"]
        or result["execution_enabled"] is not False
        or result["network_access"] is not False
    ):
        raise ValueError("Operator-approved scenario differs from deterministic offline policy")
    return result


def _write_red_plan_receipt(
    *, jsonl_file: Path, decision: dict[str, object], profile_sha256: str,
    profile: dict[str, object],
) -> Path:
    """Write a private non-executing plan receipt, before the stepwise CLI."""
    receipt = jsonl_file.with_name(jsonl_file.stem + ".red-plan.json")
    if receipt.exists() or receipt.is_symlink():
        raise ValueError("Private Red planner receipt already exists")
    payload = {
        "kind": "da005_operator_approved_red_policy_v1",
        "profile_sha256": profile_sha256,
        "strategy": decision["strategy"],
        "seed": profile["red_policy"]["seed"],
        "selected_scenario_id": decision["scenario_id"],
        "feedback_count": decision["feedback_count"],
        "feedback_origin": "operator_entered_unverified",
        "policy_reproducible_from_pinned_profile": True,
        "planning_only": True,
        "attack_executed": False,
        "verified_ai_detection": False,
        "soc_alerts_created": False,
    }
    # The receipt never contains network IPs, source paths or feedback rows.
    with receipt.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return receipt


def run_profile(
    *,
    config_file: Path,
    expected_sha256: str,
    jsonl_file: Path,
    execute: bool = False,
    operator_confirmed_hostonly: bool = False,
) -> int:
    """One operator command; delegates all networking to existing safe runner."""
    profile = load_config(config_file, expected_sha256)
    if execute:
        if operator_confirmed_hostonly is not True:
            raise ValueError("Explicit operator Host-only confirmation is mandatory")
    elif operator_confirmed_hostonly:
        raise ValueError("No live execution confirmation on a dry-run")
    if not jsonl_file.is_absolute() or jsonl_file.suffix.lower() != ".jsonl" or jsonl_file.is_symlink():
        raise ValueError("Output progress JSONL must be an absolute new file")
    private_dir = stimulus._private_dir(Path(profile["output_dir"]))
    if jsonl_file.parent.resolve(strict=True) != private_dir:
        raise ValueError("JSONL must be created inside exactly the approved private evidence directory")
    if jsonl_file.resolve(strict=False) in (
        config_file.resolve(strict=True), Path(profile["known_hosts"]).resolve(strict=True),
    ):
        raise ValueError("Progress must not overlap configuration or pinned SSH material")
    if execute and Path(profile["stop_file"]).exists():
        # Refuse before even creating a new JSONL file.
        raise ValueError("STOP marker exists: no new execution may begin")
    if jsonl_file.exists() or jsonl_file.is_symlink():
        raise ValueError("Progress JSONL already exists")
    if profile["version"] == 2:
        # Decision is calculated from the profile's immutable, SHA-pinned
        # operator feedback and must match two explicitly approved labels.
        # Store only a non-executable plan receipt. No runtime feedback loops
        # or post-hoc relabeling are performed here.
        decision = _red_plan(profile)
        _write_red_plan_receipt(
            jsonl_file=jsonl_file,
            decision=decision,
            profile_sha256=expected_sha256,
            profile=profile,
        )

    args = [
        "--source-ip", profile["source_ip"],
        "--target-ip", profile["target_ip"],
        "--cidr", profile["cidr"],
        "--scenario", profile["scenario_id"],
        "--user", profile["username"],
        "--known-hosts", profile["known_hosts"],
        "--output-dir", profile["output_dir"],
        "--stop-file", profile["stop_file"],
        "--attempts", str(profile["attempts"]),
        "--settle-s", str(profile["settle_s"]),
    ]
    if profile["model_path"] is not None:
        args += ["--model", profile["model_path"],
                 "--expected-model-sha256", profile["expected_model_sha256"]]
    if execute:
        args += ["--execute", "--operator-confirmed-hostonly"]
    return writer.run_to_file(jsonl_file=jsonl_file, cli_args=args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--expected-config-sha256", required=True)
    parser.add_argument("--jsonl-file", type=Path, required=True)
    parser.add_argument("--execute", action="store_true", help="OFF by default; approved benign Host-only probes only")
    parser.add_argument("--operator-confirmed-hostonly", action="store_true")
    args = parser.parse_args(argv)
    try:
        exit_code = run_profile(
            config_file=args.config_file,
            expected_sha256=args.expected_config_sha256,
            jsonl_file=args.jsonl_file,
            execute=args.execute,
            operator_confirmed_hostonly=args.operator_confirmed_hostonly,
        )
    except (ValueError, OSError, TypeError, UnicodeError, RecursionError):
        print("DA005 operator session refused. Check private profile pins, consent and fresh paths.",
              file=sys.stderr)
        return 1
    if exit_code == 0:
        print("DA005 operator session wrote private JSONL; review in local /vmware-progress.")
    else:
        print("DA005 operator session was refused or interrupted; inspect private JSONL status.",
              file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
