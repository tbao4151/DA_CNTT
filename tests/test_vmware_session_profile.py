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
