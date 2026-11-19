"""Private operator one-command profile tests. No physical packets, SSH or VM access."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import run_vmware_session_profile as launcher
import run_vmware_stepwise as stepwise
import verify_vmware_progress_jsonl as audit
from test_vmware_stepwise import fake_raw, fake_receipt


def fixture_profile(tmp_path: Path) -> tuple[Path, dict]:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ssh = tmp_path / "known_hosts"
    ssh.write_text("test-only fake host key\n", encoding="utf-8")
    config = {
        "version": 1,
        "source_ip": "192.168.77.1",
        "target_ip": "192.168.77.20",
        "cidr": "192.168.77.0/24",
        "scenario_id": "connection_shift",
        "username": "ubuntu",
        "known_hosts": str(ssh),
        "output_dir": str(evidence),
        "stop_file": str(evidence / "DA005_STOP.flag"),
        "attempts": 2,
        "settle_s": 0,
        "model_path": None,
        "expected_model_sha256": None,
    }
    path = tmp_path / "operator-profile.json"
    path.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
    return path, config


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_real_cli_profile_to_jsonl_dry_run_has_no_network_and_sha_audit(monkeypatch, tmp_path):
    path, config = fixture_profile(tmp_path)
    monkeypatch.setattr(stepwise.stimulus, "send_benign_probe",
                        lambda **kwargs: pytest.fail("No packets allowed in dry-run"))
    monkeypatch.setattr(stepwise.collector, "fetch",
                        lambda **kwargs: pytest.fail("No SCP allowed in dry-run"))
    output = Path(config["output_dir"]) / "session-001.jsonl"
    assert launcher.run_profile(config_file=path, expected_sha256=digest(path),
                                jsonl_file=output) == 0
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [row["status"] for row in rows] == ["dry_run", "dry_run"]
    assert rows[-1]["result"]["network_attempts"] == 0
    assert rows[-1]["result"]["ssh_fetch_performed"] is False
    assert audit.audit(output, digest(output))["terminal_status"] == "dry_run"


def test_mocked_operator_execute_to_full_jsonl_and_auditor(monkeypatch, tmp_path):
    path, config = fixture_profile(tmp_path)
    attempts = []
    ssh_fetch = []
    raw = fake_raw()

    def fake_run(**kwargs):
        attempts.append(kwargs)
        if kwargs["execute"]:
            assert kwargs["stop_requested"]() is False
            return fake_receipt()
        return {"network_attempts": 0}

    def fake_fetch(**kwargs):
        ssh_fetch.append(kwargs)
        log = Path(config["output_dir"]) / "conn.log"
        log.write_bytes(raw)
        return {
            "local_log_filename": "conn.log",
            "log_sha256": hashlib.sha256(raw).hexdigest(),
            "flow_count": 2,
        }

    monkeypatch.setattr(stepwise.stimulus, "run", fake_run)
    monkeypatch.setattr(stepwise.collector, "fetch", fake_fetch)
    monkeypatch.setattr(stepwise.time, "sleep",
                        lambda _seconds: pytest.fail("Unexpected wait"))
    output = Path(config["output_dir"]) / "session-002.jsonl"
    assert launcher.run_profile(config_file=path, expected_sha256=digest(path),
                                jsonl_file=output, execute=True,
                                operator_confirmed_hostonly=True) == 0
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 10
    assert rows[-1]["status"] == "completed"
    assert rows[-1]["result"]["network_attempts"] == 2
    assert rows[-1]["result"]["blue_research_scoring_performed"] is False
    assert rows[-1]["result"]["attack_executed"] is False
    assert rows[-1]["result"]["operational_ai_detection_verified"] is False
    assert rows[-1]["result"]["soc_alerts_created"] is False
    assert len(attempts) == 2 and len(ssh_fetch) == 1
    assert attempts[-1]["scenario_id"] == "connection_shift"
    assert attempts[-1]["count"] == 2
    assert ssh_fetch[0]["host"] == "192.168.77.20"
    assert audit.audit(output, digest(output))["terminal_status"] == "completed"


def test_mocked_operator_profile_runs_optional_pinned_blue_research(monkeypatch, tmp_path):
    """The same command routes the *optional* model to the Blue research bridge."""
    path, config = fixture_profile(tmp_path)
    model = tmp_path / "private_zeek_research.json"
    model.write_text('{"private_test_only":true}\n', encoding="utf-8")
    config["model_path"] = str(model)
    config["expected_model_sha256"] = digest(model)
    path.write_text(json.dumps(config) + "\n", encoding="utf-8")
    observed = []
    raw = fake_raw()

    def validate_model(model_file, *, expected_sha256):
        observed.append("model_pinned_before_traffic")
        assert model_file == model
        assert expected_sha256 == digest(model)

    def fake_stimulus(**kwargs):
        if kwargs["execute"]:
            assert observed == ["model_pinned_before_traffic"]
            observed.append("red_probe_mocked")
            return fake_receipt()
        return {"network_attempts": 0}

    def fake_blue(**kwargs):
        observed.append("blue_research_mocked")
        assert kwargs["model_path"] == model
        assert kwargs["expected_model_sha256"] == digest(model)
        assert kwargs["host"] == "192.168.77.20"
        (Path(config["output_dir"]) / "conn.log").write_bytes(raw)
        return {
            "log_file": "conn.log",
            "log_sha256": hashlib.sha256(raw).hexdigest(),
            "flow_count": 2,
            "report_file": "conn.research.json",
            "research_candidate_count": 1,
        }

    monkeypatch.setattr(stepwise.blue, "load_pinned_zeek_research_model", validate_model)
    monkeypatch.setattr(stepwise.stimulus, "run", fake_stimulus)
    monkeypatch.setattr(stepwise.blue, "run_bridge", fake_blue)
    monkeypatch.setattr(stepwise.collector, "fetch",
                        lambda **_args: pytest.fail("Blue bridge owns its own Zeek fetch"))
    progress = Path(config["output_dir"]) / "optional-blue.jsonl"
    assert launcher.run_profile(config_file=path, expected_sha256=digest(path),
                                jsonl_file=progress, execute=True,
                                operator_confirmed_hostonly=True) == 0
    assert observed == [
        "model_pinned_before_traffic", "red_probe_mocked",
        "blue_research_mocked",
    ]
    rows = [json.loads(line) for line in progress.read_text(encoding="utf-8").splitlines()]
    blue_stage = next(row for row in rows if row.get("stage") == "blue")
    assert blue_stage["status"] == "completed"
    assert blue_stage["counts"]["research_candidate_count"] == 1
    assert blue_stage["operational_ai_detection_verified"] is False
    assert blue_stage["soc_alerts_created"] is False
    assert rows[-1]["result"]["blue_research_scoring_performed"] is True
    assert rows[-1]["result"]["research_candidate_count"] == 1
    assert rows[-1]["result"]["operational_ai_detection_verified"] is False
    assert audit.audit(progress, digest(progress))["terminal_status"] == "completed"


def test_execute_refused_without_both_confirmation_and_fresh_stop(monkeypatch, tmp_path):
    path, config = fixture_profile(tmp_path)
    progress = Path(config["output_dir"]) / "phase.jsonl"
    monkeypatch.setattr(launcher.writer, "run_to_file",
                        lambda **kwargs: pytest.fail("Execution gate must refuse first"))
    with pytest.raises(ValueError, match="confirmation"):
        launcher.run_profile(config_file=path, expected_sha256=digest(path),
                             jsonl_file=progress, execute=True)
    with pytest.raises(ValueError, match="dry-run"):
        launcher.run_profile(config_file=path, expected_sha256=digest(path),
                             jsonl_file=progress, operator_confirmed_hostonly=True)
    Path(config["stop_file"]).write_bytes(b"")
    with pytest.raises(ValueError, match="STOP marker"):
        launcher.run_profile(config_file=path, expected_sha256=digest(path),
                             jsonl_file=progress, execute=True,
                             operator_confirmed_hostonly=True)
    assert not progress.exists()


def test_rejects_wrong_hash_and_noncanonical_digest(tmp_path):
    path, _config = fixture_profile(tmp_path)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        launcher.load_config(path, "0" * 64)
    with pytest.raises(ValueError, match="lowercase"):
        launcher.load_config(path, "A" * 64)


@pytest.mark.parametrize("mutation", [
    {"version": 1.0},
    {"version": True},
    {"attempts": 5},
    {"attempts": True},
    {"settle_s": 10},
    {"scenario_id": "port_scan"},
    {"source_ip": "8.8.8.8"},
    {"target_ip": "192.168.78.20"},
    {"cidr": "192.168.0.0/16"},
    {"username": "guest;rm -rf"},
    {"model_path": "/tmp/nonexistent-model"},
    {"expected_model_sha256": "a" * 64},
    {"surplus": "ignored_not_allowed"},
])
def test_strict_profile_never_accepts_unknown_unsafe_or_partial_fields(tmp_path, mutation):
    path, profile = fixture_profile(tmp_path)
    profile.update(mutation)
    path.write_text(json.dumps(profile) + "\n", encoding="utf-8")
    with pytest.raises((ValueError, OSError)):
        launcher.load_config(path, digest(path))


def test_rejects_duplicate_json_property_and_nonfinite_number(tmp_path):
    path, _ = fixture_profile(tmp_path)
    data = path.read_text(encoding="utf-8").rstrip()
    path.write_text(data[:-1] + ',"version":1}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        launcher.load_config(path, digest(path))
    path.write_text('{"version":NaN}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Nonfinite"):
        launcher.load_config(path, digest(path))


def test_wrong_directory_and_existing_jsonl_do_not_start_runner(monkeypatch, tmp_path):
    path, config = fixture_profile(tmp_path)
    monkeypatch.setattr(launcher.writer, "run_to_file",
                        lambda **kwargs: pytest.fail("No out of scope file creation"))
    with pytest.raises(ValueError, match="exactly"):
        launcher.run_profile(config_file=path, expected_sha256=digest(path),
                             jsonl_file=tmp_path / "outside.jsonl")
    with pytest.raises(ValueError, match="absolute"):
        launcher.run_profile(config_file=path, expected_sha256=digest(path),
                             jsonl_file=Path("relative.jsonl"))
    progress = Path(config["output_dir"]) / "session.jsonl"
    progress.write_text("old evidence\n", encoding="utf-8")
    # Original exclusive writer handles overwrite refusal.
    monkeypatch.undo()
    with pytest.raises(ValueError, match="already exist"):
        launcher.run_profile(config_file=path, expected_sha256=digest(path),
                             jsonl_file=progress)
    assert progress.read_text(encoding="utf-8") == "old evidence\n"


def test_refuses_symlink_to_private_profile_without_reading(monkeypatch, tmp_path):
    path, _profile = fixture_profile(tmp_path)
    link = tmp_path / "link.json"
    try:
        link.symlink_to(path)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink permission not granted")
    with pytest.raises(ValueError, match="non-symlink"):
        launcher.load_config(link, digest(path))


def test_cli_reports_only_generic_error_not_private_paths(tmp_path, capsys):
    path, config = fixture_profile(tmp_path)
    rc = launcher.main([
        "--config-file", str(path),
        "--expected-config-sha256", "0" * 64,
        "--jsonl-file", str(Path(config["output_dir"]) / "x.jsonl"),
    ])
    printed = capsys.readouterr()
    assert rc == 1
    assert "refused" in printed.err
    assert str(path) not in printed.err
    assert "192.168." not in printed.err
    assert printed.out == ""


def _profile_v2(tmp_path: Path, *, strategy="ucb1", seed=42):
    path, config = fixture_profile(tmp_path)
    feedback = [
        {"scenario_id": "baseline_web", "blue_flagged": True},
        {"scenario_id": "dns_variation", "blue_flagged": False},
        {"scenario_id": "connection_shift", "blue_flagged": True},
    ]
    config["version"] = 2
    config["scenario_id"] = "dns_variation"
    config["red_policy"] = {
        "strategy": strategy,
        "seed": seed,
        "feedback": feedback,
        "expected_scenario_id": "dns_variation",
    }
    path.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
    return path, config


def test_pinned_ucb1_v2_dryrun_records_truthful_private_planner_receipt(monkeypatch, tmp_path):
    path, config = _profile_v2(tmp_path)
    monkeypatch.setattr(stepwise.stimulus, "send_benign_probe",
                        lambda **kw: pytest.fail("Never call socket in dry-run"))
    monkeypatch.setattr(stepwise.collector, "fetch",
                        lambda **kw: pytest.fail("Never fetch Zeek in dry-run"))
    out = Path(config["output_dir"]) / "policy-dryrun.jsonl"
    assert launcher.run_profile(config_file=path, expected_sha256=digest(path), jsonl_file=out) == 0
    plan_file = out.with_name("policy-dryrun.red-plan.json")
    assert plan_file.is_file()
    receipt = json.loads(plan_file.read_text(encoding="utf-8"))
    assert receipt == {
        "kind": "da005_operator_approved_red_policy_v1",
        "profile_sha256": digest(path),
        "strategy": "ucb1",
        "seed": 42,
        "selected_scenario_id": "dns_variation",
        "feedback_count": 3,
        "feedback_origin": "operator_entered_unverified",
        "policy_reproducible_from_pinned_profile": True,
        "planning_only": True,
        "attack_executed": False,
        "verified_ai_detection": False,
        "soc_alerts_created": False,
    }
    assert "192.168." not in plan_file.read_text(encoding="utf-8")
    assert str(tmp_path) not in plan_file.read_text(encoding="utf-8")
    assert audit.audit(out, digest(out))["terminal_status"] == "dry_run"


def test_pinned_ucb1_selected_benign_scenario_reaches_actual_stepwise_runner_only_when_consented(
    monkeypatch, tmp_path,
):
    path, config = _profile_v2(tmp_path)
    calls = []
    raw = fake_raw().replace(b"\t22\ttcp", b"\t53\tudp")
    def mock_benign_traffic(**kw):
        calls.append(("stimulus", kw["scenario_id"], kw["execute"]))
        if kw["execute"]:
            receipt = fake_receipt()
            receipt["scenario_id"] = "dns_variation"
            for event in receipt["events"]:
                event["scenario_id"] = "dns_variation"
                event["protocol"] = "udp"
                event["port"] = 53
            return receipt
        return {"network_attempts": 0}
    def fake_fetch(**kw):
        calls.append(("zeek", kw["host"]))
        log = Path(config["output_dir"]) / "conn.log"
        log.write_bytes(raw)
        return {"local_log_filename": "conn.log",
                "log_sha256": hashlib.sha256(raw).hexdigest(), "flow_count": 2}
    monkeypatch.setattr(stepwise.stimulus, "run", mock_benign_traffic)
    monkeypatch.setattr(stepwise.collector, "fetch", fake_fetch)
    output = Path(config["output_dir"]) / "ucb1-execute.jsonl"
    with pytest.raises(ValueError, match="confirmation"):
        launcher.run_profile(config_file=path, expected_sha256=digest(path),
                             jsonl_file=output, execute=True)
    assert not calls and not output.exists()
    assert not output.with_name("ucb1-execute.red-plan.json").exists()
    assert launcher.run_profile(
        config_file=path, expected_sha256=digest(path), jsonl_file=output,
        execute=True, operator_confirmed_hostonly=True,
    ) == 0
    assert calls == [("stimulus", "dns_variation", False),
                     ("stimulus", "dns_variation", True),
                     ("zeek", "192.168.77.20")]
    assert audit.audit(output, digest(output))["terminal_status"] == "completed"
    rows = [json.loads(row) for row in output.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["result"]["attack_executed"] is False
    assert rows[-1]["result"]["operational_ai_detection_verified"] is False
    assert rows[-1]["result"]["soc_alerts_created"] is False


def test_pinned_v2_random_plan_requires_exact_human_approval(monkeypatch, tmp_path):
    path, config = _profile_v2(tmp_path, strategy="random", seed=123)
    from red_team_ai.scenario_policy import choose_scenario
    result = choose_scenario(config["red_policy"]["feedback"], strategy="random", seed=123)
    config["scenario_id"] = result["scenario_id"]
    config["red_policy"]["expected_scenario_id"] = result["scenario_id"]
    path.write_text(json.dumps(config) + "\n", encoding="utf-8")
    output = Path(config["output_dir"]) / "random.jsonl"
    assert launcher.run_profile(
        config_file=path, expected_sha256=digest(path), jsonl_file=output,
    ) == 0
    receipt = json.loads(output.with_name("random.red-plan.json").read_text(encoding="utf-8"))
    assert receipt["strategy"] == "random"
    assert receipt["selected_scenario_id"] == result["scenario_id"]
    assert receipt["planning_only"] is True
    assert audit.audit(output, digest(output))["terminal_status"] == "dry_run"


@pytest.mark.parametrize("corruption", [
    {"version": 3},
    {"red_policy": {}},
    {"red_policy": {"strategy": "unsupported", "seed": 42, "feedback": [], "expected_scenario_id": "dns_variation"}},
    {"red_policy": {"strategy": "ucb1", "seed": True, "feedback": [], "expected_scenario_id": "dns_variation"}},
    {"scenario_id": "baseline_web"},
    {"red_policy": {"strategy": "ucb1", "seed": 42,
                    "feedback": [{"scenario_id": "dns_variation", "blue_flagged": "true"}],
                    "expected_scenario_id": "dns_variation"}},
    {"red_policy": {"strategy": "ucb1", "seed": 42,
                    "feedback": [{"scenario_id": "dns_variation", "blue_flagged": False, "packet": "arbitrary"}],
                    "expected_scenario_id": "dns_variation"}},
    {"red_policy": {"strategy": "ucb1", "seed": 42,
                    "feedback": [{"scenario_id": "baseline_web", "blue_flagged": True}] * 129,
                    "expected_scenario_id": "dns_variation"}},
])
def test_invalid_v2_policy_cannot_start_runner_or_create_evidence(tmp_path, corruption):
    path, config = _profile_v2(tmp_path)
    config.update(corruption)
    path.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
    out = Path(config["output_dir"]) / "refused.jsonl"
    with pytest.raises(ValueError):
        launcher.run_profile(
            config_file=path, expected_sha256=digest(path), jsonl_file=out,
        )
    assert not out.exists()
    assert not out.with_name("refused.red-plan.json").exists()


def test_v2_policy_source_hash_mismatch_or_receipt_collision_blocks_execution(tmp_path):
    path, config = _profile_v2(tmp_path)
    out = Path(config["output_dir"]) / "collision.jsonl"
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        launcher.run_profile(
            config_file=path, expected_sha256="0" * 64, jsonl_file=out,
        )
    receipt = out.with_name("collision.red-plan.json")
    receipt.write_text("existing independently saved plan\n", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        launcher.run_profile(
            config_file=path, expected_sha256=digest(path), jsonl_file=out,
        )
    assert not out.exists()
    assert receipt.read_text(encoding="utf-8") == "existing independently saved plan\n"


def test_same_evidence_directory_rejects_overlapping_profile_sessions(monkeypatch, tmp_path):
    """A second SHA-pinned session cannot mix receipts with the first run."""
    path, config = fixture_profile(tmp_path)
    folder = Path(config["output_dir"])
    first = folder / "first.jsonl"
    second = folder / "second.jsonl"
    lock = folder / "DA005_ACTIVE_SESSION.lock"
    calls = []

    def nested_without_network(*, jsonl_file, cli_args):
        calls.append(jsonl_file.name)
        assert lock.is_file()
        with pytest.raises(ValueError, match="session may be active"):
            launcher.run_profile(
                config_file=path, expected_sha256=digest(path), jsonl_file=second,
            )
        assert not second.exists()
        return 0

    monkeypatch.setattr(launcher.writer, "run_to_file", nested_without_network)
    assert launcher.run_profile(
        config_file=path, expected_sha256=digest(path), jsonl_file=first,
    ) == 0
    assert calls == ["first.jsonl"]
    assert not lock.exists()


def test_existing_session_lock_fails_closed_without_touching_evidence(tmp_path):
    path, config = _profile_v2(tmp_path)
    folder = Path(config["output_dir"])
    lock = folder / "DA005_ACTIVE_SESSION.lock"
    lock.write_text("unverified prior run — do not remove automatically", encoding="utf-8")
    progress = folder / "must-not-run.jsonl"
    with pytest.raises(ValueError, match="session may be active"):
        launcher.run_profile(
            config_file=path, expected_sha256=digest(path), jsonl_file=progress,
        )
    assert not progress.exists()
    assert not progress.with_name("must-not-run.red-plan.json").exists()
    assert lock.read_text(encoding="utf-8").startswith("unverified prior run")


def test_profile_session_lock_is_cleaned_on_runner_exception(monkeypatch, tmp_path):
    path, config = fixture_profile(tmp_path)
    folder = Path(config["output_dir"])
    lock = folder / "DA005_ACTIVE_SESSION.lock"

    def fail_before_network(*, jsonl_file, cli_args):
        assert lock.exists()
        raise OSError("synthetic local writer error")

    monkeypatch.setattr(launcher.writer, "run_to_file", fail_before_network)
    with pytest.raises(OSError, match="synthetic local writer error"):
        launcher.run_profile(
            config_file=path, expected_sha256=digest(path),
            jsonl_file=folder / "runner-error.jsonl",
        )
    assert not lock.exists()


def test_v1_profile_has_no_policy_receipt_for_backwards_compatibility(tmp_path):
    path, config = fixture_profile(tmp_path)
    progress = Path(config["output_dir"]) / "old-profile.jsonl"
    assert launcher.run_profile(
        config_file=path, expected_sha256=digest(path), jsonl_file=progress,
    ) == 0
    assert audit.audit(progress, digest(progress))["terminal_status"] == "dry_run"
    assert not progress.with_name("old-profile.red-plan.json").exists()


def test_validate_only_readonly_without_blue_creates_nothing(monkeypatch, tmp_path, capsys):
    path, config = fixture_profile(tmp_path)
    private = Path(config["output_dir"])
    before = sorted(p.name for p in private.iterdir())
    monkeypatch.setattr(launcher.writer, "run_to_file",
                        lambda **kw: pytest.fail("Validate-only must not write JSONL"))
    monkeypatch.setattr(stepwise.stimulus, "send_benign_probe",
                        lambda **kw: pytest.fail("Validate-only must not send traffic"))
    monkeypatch.setattr(stepwise.collector, "fetch",
                        lambda **kw: pytest.fail("Validate-only must not use SSH"))
    assert launcher.main([
        "--config-file", str(path), "--expected-config-sha256", digest(path),
        "--validate-only",
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["kind"] == "da005_private_profile_readiness_v1"
    assert output["profile_sha256_verified"] is True
    assert output["blue_model_pinned_and_schema_verified"] is False
    assert output["network_activity_performed"] is False
    assert output["operational_ai_detection_verified"] is False
    assert sorted(p.name for p in private.iterdir()) == before
    assert str(path) not in json.dumps(output)
    assert config["target_ip"] not in json.dumps(output)


@pytest.mark.parametrize("execute", [False, True])
def test_require_blue_refuses_without_model_before_creating_receipts(tmp_path, execute):
    path, config = _profile_v2(tmp_path)
    folder = Path(config["output_dir"])
    output = folder / "strict-blue.jsonl"
    with pytest.raises(ValueError, match="Blue research model is required"):
        launcher.run_profile(
            config_file=path, expected_sha256=digest(path), jsonl_file=output,
            execute=execute, operator_confirmed_hostonly=execute,
            require_blue_research=True,
        )
    assert not output.exists()
    assert not output.with_name("strict-blue.red-plan.json").exists()
    assert not (folder / "DA005_ACTIVE_SESSION.lock").exists()


def test_validate_only_required_blue_checks_pinned_model_without_packets(monkeypatch, tmp_path, capsys):
    path, config = _profile_v2(tmp_path)
    folder = Path(config["output_dir"])
    model = tmp_path / "private-data-only.json"
    model.write_text('{"placeholder":"offline test"}\n', encoding="utf-8")
    config["model_path"] = str(model)
    config["expected_model_sha256"] = digest(model)
    path.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
    loaded = []

    def verify_model(model_file, *, expected_sha256):
        loaded.append(model_file)
        assert model_file == model
        assert expected_sha256 == digest(model)
        assert not list(folder.iterdir())

    monkeypatch.setattr(stepwise.blue, "load_pinned_zeek_research_model", verify_model)
    monkeypatch.setattr(launcher.writer, "run_to_file",
                        lambda **kw: pytest.fail("Validate-only must not write JSONL"))
    assert launcher.main([
        "--config-file", str(path), "--expected-config-sha256", digest(path),
        "--validate-only", "--require-blue-research",
    ]) == 0
    readiness = json.loads(capsys.readouterr().out)
    assert readiness["profile_version"] == 2
    assert readiness["red_policy_approved_offline"] is True
    assert readiness["blue_model_pinned_and_schema_verified"] is True
    assert readiness["blue_model_required"] is True
    assert readiness["vmware_isolation_verified"] is False
    assert loaded == [model]
    assert not list(folder.iterdir())


def test_required_blue_invalid_pinned_model_refused_before_jsonl(monkeypatch, tmp_path):
    path, config = fixture_profile(tmp_path)
    folder = Path(config["output_dir"])
    model = tmp_path / "private-model.json"
    model.write_text('{"not_a_real_model":true}\n', encoding="utf-8")
    config["model_path"] = str(model)
    config["expected_model_sha256"] = digest(model)
    path.write_text(json.dumps(config) + "\n", encoding="utf-8")
    monkeypatch.setattr(launcher.writer, "run_to_file",
                        lambda **kw: pytest.fail("Model must be verified first"))
    output = folder / "must-not-create.jsonl"
    with pytest.raises(ValueError):
        launcher.run_profile(
            config_file=path, expected_sha256=digest(path), jsonl_file=output,
            require_blue_research=True,
        )
    assert not output.exists()
    assert not list(folder.iterdir())


@pytest.mark.parametrize("extra", [
    ["--execute"],
    ["--operator-confirmed-hostonly"],
    ["--jsonl-file", "unused.jsonl"],
])
def test_validate_only_refuses_execution_or_output_flags(tmp_path, capsys, extra):
    path, config = fixture_profile(tmp_path)
    assert launcher.main([
        "--config-file", str(path), "--expected-config-sha256", digest(path),
        "--validate-only", *extra,
    ]) == 1
    result = capsys.readouterr()
    assert "refused" in result.err and result.out == ""
    assert not list(Path(config["output_dir"]).iterdir())


def test_required_blue_dryrun_still_has_no_network_and_no_false_detection(monkeypatch, tmp_path):
    path, config = fixture_profile(tmp_path)
    model = tmp_path / "test-only-data-model.json"
    model.write_text('{"test_only":true}\n', encoding="utf-8")
    config["model_path"] = str(model)
    config["expected_model_sha256"] = digest(model)
    path.write_text(json.dumps(config) + "\n", encoding="utf-8")
    monkeypatch.setattr(stepwise.blue, "load_pinned_zeek_research_model",
                        lambda *args, **kwargs: {"test_only": True})
    monkeypatch.setattr(stepwise.stimulus, "send_benign_probe",
                        lambda **kw: pytest.fail("No sockets in strict dry-run"))
    monkeypatch.setattr(stepwise.collector, "fetch",
                        lambda **kw: pytest.fail("No SCP in strict dry-run"))
    output = Path(config["output_dir"]) / "strict-dryrun.jsonl"
    assert launcher.run_profile(
        config_file=path, expected_sha256=digest(path), jsonl_file=output,
        require_blue_research=True,
    ) == 0
    rows = [json.loads(row) for row in output.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["status"] == "dry_run"
    assert rows[-1]["result"]["network_attempts"] == 0
    assert rows[-1]["result"]["blue_research_scoring_performed"] is False
    assert audit.audit(output, digest(output))["terminal_status"] == "dry_run"
