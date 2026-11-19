"""Network-free acceptance tests for SHA-pinned VMware progress JSONL audit."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import verify_vmware_progress_jsonl as verifier
from emit_vmware_jsonl_browser_cases import generate


def pin(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copied_mutation(tmp_path: Path, origin: Path, mutate) -> Path:
    rows = [json.loads(line) for line in origin.read_text(encoding="utf-8").splitlines()]
    mutate(rows)
    target = tmp_path / "changed.jsonl"
    target.write_text(
        "\n".join(json.dumps(obj, ensure_ascii=False) for obj in rows) + "\n",
        encoding="utf-8",
    )
    return target


def test_real_python_dryrun_mock_complete_and_refusal_are_audited(tmp_path):
    outputs = generate(tmp_path)
    expected = {"dry_run": (1, "dry_run"), "mock_completed": (9, "completed"), "refused": (0, "refused")}
    for name, path in outputs.items():
        report = verifier.audit(path, pin(path))
        assert report["kind"] == "da005_vmware_progress_file_audit_v1"
        assert report["terminal_status"] == expected[name][1]
        assert report["stage_events"] == expected[name][0]
        assert report["jsonl_integrity_screen_passed"] is True
        assert report["vmware_isolation_verified"] is False
        assert report["physical_capture_authenticity_verified"] is False
        assert report["attack_executed"] is False
        assert report["operational_ai_detection_verified"] is False
        assert report["soc_alerts_created"] is False
        assert "192.168." not in json.dumps(report)
        assert str(tmp_path) not in json.dumps(report)


def test_cli_prints_only_redacted_receipt(tmp_path, capsys):
    path = generate(tmp_path)["dry_run"]
    assert verifier.main(["--jsonl-file", str(path), "--expected-sha256", pin(path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["progress_sha256"] == pin(path)
    assert out["terminal_status"] == "dry_run"
    assert "source_ip" not in out


def test_refuses_unpinned_and_altered_file(tmp_path):
    path = generate(tmp_path)["dry_run"]
    with pytest.raises(ValueError, match="SHA-256"):
        verifier.audit(path, "0" * 64)
    with pytest.raises(ValueError, match="lowercase"):
        verifier.audit(path, "ABCDEF")
    with pytest.raises(ValueError, match="absolute"):
        verifier.audit(Path("relative.jsonl"), pin(path))


def test_refuses_conflicting_end_counter_even_with_new_matching_digest(tmp_path):
    path = generate(tmp_path)["mock_completed"]
    changed = copied_mutation(tmp_path, path, lambda rows: rows[-1]["result"].update({"network_attempts": 4}))
    with pytest.raises(ValueError, match="Probe count"):
        verifier.audit(changed, pin(changed))


def test_refuses_forged_verified_attack_flag_and_unredacted_private_path(tmp_path):
    path = generate(tmp_path)["mock_completed"]
    changed = copied_mutation(tmp_path, path, lambda rows: rows[1].update({"attack_executed": True}))
    with pytest.raises(ValueError, match="unverified"):
        verifier.audit(changed, pin(changed))
    changed.unlink()
    changed = copied_mutation(tmp_path, path, lambda rows: rows[-1]["result"].update({"log_filename": "private.log"}))
    with pytest.raises(ValueError, match="redacted"):
        verifier.audit(changed, pin(changed))


def test_refuses_missing_phase_nonfinite_and_duplicate_json_key(tmp_path):
    path = generate(tmp_path)["mock_completed"]
    changed = copied_mutation(tmp_path, path, lambda rows: rows.pop(3))
    with pytest.raises(ValueError, match="order"):
        verifier.audit(changed, pin(changed))
    changed.write_text('{"kind":NaN}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Non-finite"):
        verifier.audit(changed, pin(changed))
    changed.write_text('{"kind":1,"kind":2}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        verifier.audit(changed, pin(changed))


def test_refuses_missing_final_newline_and_extra_junk(tmp_path):
    path = generate(tmp_path)["dry_run"]
    changed = tmp_path / "changed.jsonl"
    changed.write_bytes(path.read_bytes().rstrip(b"\n"))
    with pytest.raises(ValueError, match="Incomplete"):
        verifier.audit(changed, pin(changed))
    changed.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="empty"):
        verifier.audit(changed, pin(changed))


def test_refuses_skipped_blue_claiming_model_inference(tmp_path):
    path = generate(tmp_path)["mock_completed"]
    changed = copied_mutation(
        tmp_path, path,
        lambda rows: rows[-1]["result"].update({
            "blue_research_scoring_performed": True, "research_candidate_count": 1,
        })
    )
    with pytest.raises(ValueError, match="Blue stage"):
        verifier.audit(changed, pin(changed))


def test_refuses_bool_counters_and_out_of_order_seq(tmp_path):
    path = generate(tmp_path)["mock_completed"]
    changed = copied_mutation(tmp_path, path, lambda rows: rows[2]["counts"].update({"attempted_probes": True}))
    with pytest.raises(ValueError, match="Invalid count"):
        verifier.audit(changed, pin(changed))
    changed.unlink()
    changed = copied_mutation(tmp_path, path, lambda rows: rows[2].update({"seq": 99}))
    with pytest.raises(ValueError, match="sequence"):
        verifier.audit(changed, pin(changed))


def test_protected_jsonl_never_inside_repository_or_symlink(tmp_path):
    path = generate(tmp_path)["dry_run"]
    link = tmp_path / "indirect.jsonl"
    try:
        link.symlink_to(path)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValueError, match="symlink"):
        verifier.audit(link, pin(path))


def test_cli_returns_generic_error_without_leaking_paths(tmp_path, capsys):
    path = generate(tmp_path)["dry_run"]
    assert verifier.main(["--jsonl-file", str(path), "--expected-sha256", "0" * 64]) == 1
    msg = capsys.readouterr()
    assert "refused" in msg.err
    assert str(path) not in msg.err
    assert "192.168." not in msg.err
    assert msg.out == ""
