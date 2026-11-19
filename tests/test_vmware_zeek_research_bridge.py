"""Network-free bridge contract tests: real data cannot be presented as live alerts."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_vmware_zeek_research as bridge


def setup_paths(tmp_path: Path):
    evidence = tmp_path / "private"
    evidence.mkdir()
    model = evidence / "zeek-model.json"
    model.write_text("test-only-mock-model", encoding="utf-8")
    known = evidence / "known_hosts"
    known.write_text("test-only-mock-key", encoding="utf-8")
    return evidence, model, known


def kwargs(evidence, model, known):
    return {
        "host": "192.168.77.20",
        "cidr": "192.168.77.0/24",
        "username": "ubuntu",
        "known_hosts": known,
        "output_dir": evidence,
        "model_path": model,
        "expected_model_sha256": "a" * 64,
    }


def test_pinned_model_is_validated_before_any_ssh(monkeypatch, tmp_path):
    evidence, model, known = setup_paths(tmp_path)
    calls = []
    def reject(*args, **kwargs):
        calls.append("verify")
        raise ValueError("untrusted model")

    monkeypatch.setattr(bridge, "load_pinned_zeek_research_model", reject)
    monkeypatch.setattr(
        bridge, "fetch",
        lambda **kwargs: pytest.fail("SSH fetch must not occur before model validation"),
    )
    with pytest.raises(ValueError, match="untrusted model"):
        bridge.run_bridge(**kwargs(evidence, model, known))
    assert calls == ["verify"]


def test_successful_bridge_calls_real_scoring_contract_and_labels_honestly(monkeypatch, tmp_path):
    evidence, model, known = setup_paths(tmp_path)
    captured = []
    log_name = "zeek_conn_20261119T040000Z_abcdef123456.log"
    raw = b"synthetic local test fixture only"
    log_sha = hashlib.sha256(raw).hexdigest()

    monkeypatch.setattr(
        bridge, "load_pinned_zeek_research_model",
        lambda path, *, expected_sha256: captured.append(("validate_model", expected_sha256)),
    )
    def fake_fetch(**params):
        captured.append(("fetch", params["host"]))
        (evidence / log_name).write_bytes(raw)
        return {"local_log_filename": log_name, "log_sha256": log_sha, "flow_count": 2}

    def fake_score(argv):
        captured.append(("score", argv))
        result = {
            "source_sha256": log_sha,
            "model_sha256": "a" * 64,
            "mode": "offline_new_zeek_research_inference_only",
            "live_capture": False, "automated_alerts": False, "soc_cases_created": False,
            "flow_count": 2, "research_candidate_count": 1,
        }
        path = Path(argv[argv.index("--output") + 1])
        path.write_text(json.dumps(result), encoding="utf-8")
        return 0
    monkeypatch.setattr(bridge, "fetch", fake_fetch)
    monkeypatch.setattr(bridge.score_zeek_new_log, "main", fake_score)
    result = bridge.run_bridge(**kwargs(evidence, model, known))
    assert [part[0] for part in captured] == ["validate_model", "fetch", "score"]
    argv = captured[2][1]
    assert argv[argv.index("--expected-log-sha256") + 1] == log_sha
    assert argv[argv.index("--expected-model-sha256") + 1] == "a" * 64
    assert argv[argv.index("--cidr") + 1] == "192.168.77.0/24"
    assert result["flow_count"] == 2
    assert result["research_candidate_count"] == 1
    assert result["operational_attack_detection_verified"] is False
    assert result["host_only_isolation_verified"] is False
    assert result["automated_alerts"] is False
    assert result["red_team_execution_performed"] is False
    assert result["report_sha256"] == hashlib.sha256(
        (evidence / log_name.replace(".log", ".research.json")).read_bytes()
    ).hexdigest()


@pytest.mark.parametrize("mutation", [
    {"live_capture": True},
    {"automated_alerts": True},
    {"soc_cases_created": True},
    {"model_sha256": "b" * 64},
    {"source_sha256": "b" * 64},
    {"flow_count": 100},
    {"research_candidate_count": 100},
    {"mode": "operational_attack_detection"},
])
def test_misleading_or_mismatched_scoring_is_refused(monkeypatch, tmp_path, mutation):
    evidence, model, known = setup_paths(tmp_path)
    name = "zeek_conn_20261119T040000Z_abcdef123456.log"
    raw = b"mock fixture"
    sha = hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(bridge, "load_pinned_zeek_research_model", lambda *_a, **_k: {})
    def fetch_mock(**_kwargs):
        (evidence / name).write_bytes(raw)
        return {"local_log_filename": name, "log_sha256": sha, "flow_count": 1}
    def score_mock(args):
        report = {
            "source_sha256": sha, "model_sha256": "a" * 64,
            "mode": "offline_new_zeek_research_inference_only",
            "live_capture": False, "automated_alerts": False,
            "soc_cases_created": False, "flow_count": 1,
            "research_candidate_count": 0,
        }
        report.update(mutation)
        Path(args[args.index("--output") + 1]).write_text(json.dumps(report), encoding="utf-8")
        return 0
    monkeypatch.setattr(bridge, "fetch", fetch_mock)
    monkeypatch.setattr(bridge.score_zeek_new_log, "main", score_mock)
    with pytest.raises(RuntimeError, match="not bound"):
        bridge.run_bridge(**kwargs(evidence, model, known))


def test_manifest_is_all_or_none_and_forwarded(monkeypatch, tmp_path):
    evidence, model, known = setup_paths(tmp_path)
    manifest = evidence / "manifest.json"
    manifest.write_text("mock", encoding="utf-8")
    monkeypatch.setattr(
        bridge, "fetch", lambda **_kw: pytest.fail("No SSH on invalid manifest input")
    )
    with pytest.raises(ValueError, match="together"):
        bridge.run_bridge(**kwargs(evidence, model, known), manifest_path=manifest)
    with pytest.raises(ValueError, match="together"):
        bridge.run_bridge(
            **kwargs(evidence, model, known),
            expected_manifest_sha256="b" * 64,
        )


def test_scoring_refusal_preserves_capture_and_no_report(monkeypatch, tmp_path):
    evidence, model, known = setup_paths(tmp_path)
    name = "zeek_conn_20261119T040000Z_abcdef123456.log"
    data = b"mock"
    monkeypatch.setattr(bridge, "load_pinned_zeek_research_model", lambda *_a, **_k: {})
    def mock_fetch(**_kw):
        (evidence / name).write_bytes(data)
        return {"local_log_filename": name,
                "log_sha256": hashlib.sha256(data).hexdigest(), "flow_count": 1}
    monkeypatch.setattr(bridge, "fetch", mock_fetch)
    monkeypatch.setattr(bridge.score_zeek_new_log, "main", lambda args: 1)
    with pytest.raises(RuntimeError, match="preserved read-only capture"):
        bridge.run_bridge(**kwargs(evidence, model, known))
    assert (evidence / name).read_bytes() == data
    assert not list(evidence.glob("*.research.json"))


def test_reject_receipt_path_traversal(monkeypatch, tmp_path):
    evidence, model, known = setup_paths(tmp_path)
    monkeypatch.setattr(bridge, "load_pinned_zeek_research_model", lambda *_a, **_k: {})
    monkeypatch.setattr(bridge, "fetch", lambda **_kw: {
        "local_log_filename": "../escape.log",
        "log_sha256": "a" * 64,
        "flow_count": 1,
    })
    with pytest.raises(RuntimeError, match="Invalid capture file name"):
        bridge.run_bridge(**kwargs(evidence, model, known))


def test_actual_research_scorer_on_mocked_transport(monkeypatch, tmp_path):
    """Only the SSH transport is mocked; model validation and scoring are real."""
    from blue_team_ai.model_artifact import build_zeek_research_artifact
    from test_zeek_offline_baseline import _dataset
    from test_zeek_new_log_inference import _log

    evidence, model_file, known = setup_paths(tmp_path)
    artifact = build_zeek_research_artifact(
        _dataset(), input_manifest_sha256="a" * 64
    )
    model_bytes = json.dumps(artifact, allow_nan=False).encode("utf-8")
    model_file.write_bytes(model_bytes)
    model_sha = hashlib.sha256(model_bytes).hexdigest()

    raw = _log()
    log_name = "zeek_conn_20261119T040000Z_abcdef123456.log"

    def mock_ssh_fetch(**params):
        assert params["host"] == "192.168.56.20"
        (evidence / log_name).write_bytes(raw)
        return {
            "local_log_filename": log_name,
            "log_sha256": hashlib.sha256(raw).hexdigest(),
            "flow_count": 2,
        }

    monkeypatch.setattr(bridge, "fetch", mock_ssh_fetch)
    summary = bridge.run_bridge(
        host="192.168.56.20", cidr="192.168.56.0/24",
        username="ubuntu", known_hosts=known, output_dir=evidence,
        model_path=model_file, expected_model_sha256=model_sha,
    )
    assert summary["flow_count"] == 2
    assert summary["model_sha256"] == model_sha
    report = json.loads((evidence / log_name.replace(".log", ".research.json")).read_text())
    assert len(report["predictions"]) == 2
    assert report["model_sha256"] == model_sha
    assert report["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["labels_used"] is False
    assert report["automated_alerts"] is False
    assert report["operational_attack_detection_verified"] is False
