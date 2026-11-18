"""FastAPI /api/v1 adapter integration tests using isolated tmp_path state."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import api.main as api_main
from siem_ai.model import fit_and_evaluate
from test_zeek_new_log_ui_partition import _prepared


@pytest.fixture()
def isolated_client(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    rows = []
    for i in range(128):
        attack = i % 2
        rows.append({
            "id": i + 1,
            "proto": "tcp" if attack else "udp",
            "service": "http" if attack else "dns",
            "state": "FIN" if attack else "CON",
            "dur": 1.5 if attack else 0.2,
            "sbytes": 1000 if attack else 100,
            "dbytes": 500 if attack else 50,
            "spkts": 10 if attack else 1,
            "dpkts": 5 if attack else 1,
            "rate": 1000 if attack else 10,
            "ct_srv_src": 16 if attack else 1,
            "label": attack,
            "attack_cat": "Exploits" if attack else "Normal",
        })
    df = pd.DataFrame(rows)
    df.to_csv(data_dir / "UNSW_NB15_testing-set.csv", index=False)

    model, metrics = fit_and_evaluate(df.iloc[:96], df.iloc[96:])
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    joblib.dump(model, artifacts_dir / "unsw_binary_rf.joblib")
    (artifacts_dir / "metrics.json").write_text(json.dumps(metrics), encoding="utf-8")

    monkeypatch.setattr(api_main, "SOC_DB_PATH", tmp_path / "soc_cases.sqlite3")
    monkeypatch.setattr(api_main, "CYBER_LAB_DB_PATH", tmp_path / "cyber_lab_cases.sqlite3")
    monkeypatch.setattr(api_main, "DATA_DIR", data_dir)
    monkeypatch.setattr(api_main, "ARTIFACT_PATH", artifacts_dir / "unsw_binary_rf.joblib")
    monkeypatch.setattr(api_main, "METRICS_PATH", artifacts_dir / "metrics.json")

    api_main._MODEL_CACHE.update({"signature": None, "path": None, "model": None})
    api_main._OFFICIAL_DF_CACHE.clear()
    api_main._UPLOAD_CACHE.clear()
    api_main._ZEEK_LOG_CACHE.clear()
    api_main._ZEEK_TRACE_CACHE.clear()
    api_main._NEW_LOG_SESSION_CACHE.clear()
    api_main._RED_TEAM_SESSIONS.clear()

    return TestClient(api_main.create_app())


def test_health_and_system_status(isolated_client):
    health = isolated_client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    status = isolated_client.get("/api/v1/system/status")
    assert status.status_code == 200
    body = status.json()
    assert body["live_capture_enabled"] is False
    assert body["red_team_execution_enabled"] is False
    assert body["dataset"]["unsw_test_available"] is True
    assert body["model"]["trained_local_artifact_available"] is True


def test_dataset_overview_hunting_evaluation_alerts_and_soc_lifecycle(isolated_client):
    ov = isolated_client.get("/api/v1/dataset/overview?source=official&sample_size=128")
    assert ov.status_code == 200
    ov_json = ov.json()
    assert ov_json["kpis"]["flows_read"] == 128
    assert ov_json["provenance"]["predictions_available"] is True
    assert ov_json["priority_distribution"] is not None

    hunt = isolated_client.get("/api/v1/dataset/hunting?source=official&sample_size=128&protocols=tcp&only_ai_attacks=true")
    assert hunt.status_code == 200
    hunt_json = hunt.json()
    assert hunt_json["total_filtered"] > 0
    assert all(row["proto"] == "tcp" for row in hunt_json["rows"])

    csv_export = isolated_client.get("/api/v1/dataset/hunting/export-csv?source=official&sample_size=128&protocols=tcp")
    assert csv_export.status_code == 200
    assert "text/csv" in csv_export.headers["content-type"]

    eval_resp = isolated_client.get("/api/v1/dataset/evaluation?source=official&sample_size=128")
    assert eval_resp.status_code == 200
    eval_json = eval_resp.json()
    assert eval_json["benchmark_metrics"]["confusion_matrix"]["tp"] > 0
    assert eval_json["feature_importance"]["source_kind"] == "local_trained_model"
    assert eval_json["sample_threshold_diagnostics"]["status"] == "ok"

    alerts_resp = isolated_client.get("/api/v1/dataset/alerts?source=official&sample_size=128&threshold=0.80")
    assert alerts_resp.status_code == 200
    alerts_json = alerts_resp.json()
    assert alerts_json["total_alerts"] > 0
    top_alert = alerts_json["alerts"][0]

    created = isolated_client.post(
        "/api/v1/soc/cases",
        json={
            "source": "official",
            "sample_size": 128,
            "row_index": top_alert["row_index"],
            "flow_ref": top_alert["flow_ref"],
        },
    )
    assert created.status_code == 200
    case_id = created.json()["case_id"]

    updated = isolated_client.patch(
        f"/api/v1/soc/cases/{case_id}",
        json={"state": "Investigating", "analyst_note": "Checked via FastAPI test"},
    )
    assert updated.status_code == 200

    detail = isolated_client.get(f"/api/v1/soc/cases/{case_id}")
    assert detail.status_code == 200
    assert detail.json()["case"]["state"] == "Investigating"
    assert len(detail.json()["case_events"]) == 2

    exported = isolated_client.get(f"/api/v1/soc/cases/{case_id}/export")
    assert exported.status_code == 200
    assert exported.json()["case"]["case_id"] == case_id


def test_csv_upload_validation_rejects_duplicate_headers(isolated_client):
    bad_csv = b"proto,proto,service,state,dur,sbytes,dbytes,spkts,dpkts\ntcp,tcp,http,FIN,1,10,10,1,1\n"
    resp = isolated_client.post(
        "/api/v1/dataset/upload-csv",
        files={"file": ("bad.csv", bad_csv, "text/csv")},
        data={"limit": "100"},
    )
    assert resp.status_code == 422
    assert "Duplicate CSV column names" in resp.json()["detail"]


def test_untrained_mode_returns_honest_absence_states(isolated_client, monkeypatch, tmp_path):
    monkeypatch.setattr(api_main, "ARTIFACT_PATH", tmp_path / "missing_model.joblib")
    api_main._MODEL_CACHE.update({"signature": None, "path": None, "model": None})

    ov = isolated_client.get("/api/v1/dataset/overview?source=official&sample_size=100")
    assert ov.status_code == 200
    assert ov.json()["provenance"]["predictions_available"] is False
    assert ov.json()["kpis"]["ai_predicted_attacks"] is None

    alerts = isolated_client.get("/api/v1/dataset/alerts?source=official&sample_size=100")
    assert alerts.status_code == 200
    assert alerts.json()["predictions_available"] is False


def test_cyber_lab_parse_and_manual_case(isolated_client):
    sample = isolated_client.post("/api/v1/cyber-lab/load-sample-fixture")
    assert sample.status_code == 200
    body = sample.json()
    assert body["is_synthetic_demo"] is True
    assert body["summary"]["flow_count"] == 5
    sha = body["summary"]["source_sha256"]

    # Missing consent fails closed
    refused = isolated_client.post(
        "/api/v1/cyber-lab/manual-case",
        json={"source_sha256": sha, "record_index": 0, "consent": False},
    )
    assert refused.status_code == 422

    created = isolated_client.post(
        "/api/v1/cyber-lab/manual-case",
        json={"source_sha256": sha, "record_index": 0, "consent": True},
    )
    assert created.status_code == 200
    assert created.json()["verdict"] == "Unclassified"
    assert created.json()["verified_export"]["typed_zeek_event"]["uid"] == "Csynth000000000001"


def test_red_team_planning_and_synthetic_benchmark(isolated_client):
    state = isolated_client.get("/api/v1/red-team/state?session_id=t1")
    assert state.status_code == 200
    assert state.json()["execution_enabled"] is False
    assert state.json()["network_access"] is False

    proposed = isolated_client.post(
        "/api/v1/red-team/propose",
        json={"session_id": "t1", "strategy": "ucb1", "seed": 42},
    )
    assert proposed.status_code == 200
    pid = proposed.json()["audit"]["pending_proposal_id"]
    assert pid == 1

    fb = isolated_client.post(
        "/api/v1/red-team/feedback",
        json={"session_id": "t1", "proposal_id": pid, "blue_flagged": True, "confirm": True},
    )
    assert fb.status_code == 200
    assert fb.json()["audit"]["manual_feedback_count"] == 1

    bench = isolated_client.post(
        "/api/v1/red-team/synthetic-benchmark",
        json={"rounds": 30, "trials": 3, "seed": 42},
    )
    assert bench.status_code == 200
    assert bench.json()["execution_enabled"] is False
    assert "ucb1" in bench.json()["policies"]


def test_new_log_review_verify_create_and_read_only_viewer(isolated_client, tmp_path):
    prep_dir = tmp_path / "private_zeek"
    prep_dir.mkdir()
    values, manifest = _prepared(prep_dir)
    db_path = prep_dir / "private_soc.sqlite3"

    verify_resp = isolated_client.post(
        "/api/v1/new-log-review/verify",
        files={
            "log_file": ("new.log", values["source_data"], "text/plain"),
            "report_file": ("report.json", values["report_data"], "application/json"),
        },
        data={
            "model_path": str(values["model_path"]),
            "expected_model_sha256": values["expected_model_sha256"],
            "expected_log_sha256": values["expected_log_sha256"],
            "manifest_path": str(manifest),
            "expected_manifest_sha256": values["declared_manifest_sha256"],
            "cidr_input": ",".join(values["lab_cidrs"]),
        },
    )
    assert verify_resp.status_code == 200
    verify_json = verify_resp.json()
    assert len(verify_json["candidates"]) > 0
    token = verify_json["review_token"]
    rec_idx = verify_json["candidates"][0]["record_index"]

    created = isolated_client.post(
        "/api/v1/new-log-review/create-case",
        data={
            "review_token": token,
            "db_path": str(db_path),
            "record_index": str(rec_idx),
            "analyst_confirmed": "true",
            "operator_confirmed_authorized": "true",
            "operator_confirmed_new_capture": "true",
        },
    )
    assert created.status_code == 200
    cid = created.json()["case_id"]

    listed = isolated_client.post(
        "/api/v1/new-log-review/private-cases/list",
        json={"db_path": str(db_path)},
    )
    assert listed.status_code == 200
    assert len(listed.json()["cases"]) == 1

    detail = isolated_client.post(
        "/api/v1/new-log-review/private-cases/detail",
        json={"db_path": str(db_path), "case_id": cid},
    )
    assert detail.status_code == 200
    assert detail.json()["case"]["verdict"] == "Unclassified"


def test_valid_label_free_csv_upload_and_cyber_lab_trace_review(isolated_client, tmp_path):
    from test_zeek_trace_review import _fixture

    valid_csv = (
        "proto,service,state,dur,sbytes,dbytes,spkts,dpkts,rate,ct_srv_src\n"
        "tcp,http,FIN,1.2,900,450,8,4,800,15\n"
        "udp,dns,CON,0.1,80,40,1,1,12,1\n"
    ).encode("utf-8")
    up = isolated_client.post(
        "/api/v1/dataset/upload-csv",
        files={"file": ("unlabeled.csv", valid_csv, "text/csv")},
        data={"limit": "100"},
    )
    assert up.status_code == 200
    uid = up.json()["upload_id"]
    assert up.json()["has_ground_truth_label"] is False

    ov = isolated_client.get(f"/api/v1/dataset/overview?source=upload&sample_size=100&upload_id={uid}")
    assert ov.status_code == 200
    assert ov.json()["kpis"]["flows_read"] == 2
    assert ov.json()["kpis"]["ground_truth_attacks"] is None

    ev = isolated_client.get(f"/api/v1/dataset/evaluation?source=upload&sample_size=100&upload_id={uid}")
    assert ev.status_code == 200
    assert ev.json()["sample_threshold_diagnostics"]["status"] == "counts_only"

    zeek_dir = tmp_path / "zeek_trace"
    zeek_dir.mkdir()
    raw_log, trace_report = _fixture(zeek_dir)
    parsed = isolated_client.post(
        "/api/v1/cyber-lab/parse-log",
        files={"file": ("host2.log", raw_log, "text/plain")},
    )
    assert parsed.status_code == 200
    src_sha = parsed.json()["summary"]["source_sha256"]

    trace_bytes = json.dumps(trace_report, allow_nan=False).encode("utf-8")
    reviewed = isolated_client.post(
        "/api/v1/cyber-lab/review-trace",
        data={"source_sha256": src_sha},
        files={"trace_file": ("trace.json", trace_bytes, "application/json")},
    )
    assert reviewed.status_code == 200
    rev_json = reviewed.json()
    assert rev_json["flow_count"] == 2
    if rev_json["candidates"]:
        rec_idx = rev_json["candidates"][0]["record_index"]
        rc = isolated_client.post(
            "/api/v1/cyber-lab/research-candidate-case",
            json={
                "source_sha256": src_sha,
                "trace_sha256": rev_json["trace_sha256"],
                "record_index": rec_idx,
                "analyst_confirmed": True,
            },
        )
        assert rc.status_code == 200
        assert rc.json()["verdict"] == "Unclassified"

