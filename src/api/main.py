"""FastAPI application exposing DA005 Sentinel Lab services over /api/v1.

All ML inference, CSV/Zeek validation, SHA-256 verification, and SQLite
mutations delegate directly to existing tested modules in src/ and scripts/.
Importing this module performs no network I/O, model loading, or DB writes.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import sys
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT / "src"
SCRIPTS_DIR = ROOT / "scripts"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from blue_team_ai.case_workspace import list_private_zeek_cases, read_private_zeek_case
from blue_team_ai.labeled_dataset import build_labeled_lab_dataset
from blue_team_ai.new_log_review import MAX_NEW_LOG_REPORT_BYTES
from blue_team_ai.new_log_workspace import prepare_new_log_review
from blue_team_ai.offline_pcap_verify import verify_offline_pcap_import
from blue_team_ai.preview import summarize_offline_flows
from blue_team_ai.research_triage import create_research_candidate_case
from blue_team_ai.trace_review import MAX_PRIVATE_TRACE_BYTES, review_private_zeek_trace
from blue_team_ai.triage import create_offline_review_case
from blue_team_ai.verified_report import export_verified_offline_case
from blue_team_ai.zeek import MAX_LOG_BYTES, parse_zeek_conn_log
from evaluate_zeek_lab import MAX_MANIFEST_BYTES, load_experiment_manifest
from red_team_ai.planning_audit import (
    MAX_PROPOSALS,
    append_manual_feedback,
    append_proposal,
    export_planning_audit,
    extract_manual_feedback,
)
from red_team_ai.scenario_policy import SCENARIOS, choose_scenario, summarize_feedback
from red_team_ai.synthetic_benchmark import compare_synthetic_policies
from siem_ai.case_report import export_case_report
from siem_ai.core import (
    CASE_STATES,
    NON_FEATURE_FIELDS,
    assess_signal,
    case_evidence,
    case_history,
    create_case,
    flow_id,
    list_cases,
    update_case,
    validate_flows,
)
from siem_ai.explain import global_feature_importance
from siem_ai.export import safe_csv_bytes
from siem_ai.hunting import filter_hunting_flows
from siem_ai.model import load_local_model, model_artifact_signature, predict_batch
from siem_ai.official_comparison import load_official_comparison
from siem_ai.thresholds import threshold_diagnostics
from siem_ai.ui_components import priority_band_from_probability
from siem_ai.upload import MAX_CSV_BYTES, MAX_PREVIEW_ROWS, read_uploaded_flows
from triage_zeek_new_log import create_ui_candidate_case

from .schemas import (
    CreateCaseRequest,
    CyberLabManualCaseRequest,
    CyberLabResearchCaseRequest,
    PrivateCaseDetailRequest,
    PrivateCasesListRequest,
    RedTeamFeedbackRequest,
    RedTeamProposeRequest,
    RedTeamResetRequest,
    RedTeamSyntheticBenchmarkRequest,
    UpdateCaseRequest,
)

# Configurable paths (overridable in tests without touching real runtime DBs)
SOC_DB_PATH = ROOT / "runtime" / "soc_cases.sqlite3"
CYBER_LAB_DB_PATH = ROOT / "runtime" / "cyber_lab_cases.sqlite3"
DATA_DIR = ROOT / "data" / "raw" / "unsw_nb15"
ARTIFACT_PATH = ROOT / "artifacts" / "unsw_binary_rf.joblib"
METRICS_PATH = ROOT / "artifacts" / "metrics.json"
OFFICIAL_METRICS_PATH = ROOT / "reports" / "official_baseline_metrics.json"
OFFICIAL_COMPARISON_PATH = ROOT / "reports" / "official_locked_threshold_comparison.json"
OFFICIAL_IMPORTANCE_PATH = ROOT / "reports" / "official_global_feature_importance.json"

MAX_CACHED_UPLOADS = 8
MAX_CACHED_ZEEK_LOGS = 8
MAX_CACHED_TRACES = 8
MAX_CACHED_NEW_LOG_SESSIONS = 6

_MODEL_CACHE: dict[str, Any] = {"signature": None, "path": None, "model": None}
_OFFICIAL_DF_CACHE: OrderedDict[tuple[str, int, int, int], pd.DataFrame] = OrderedDict()
_UPLOAD_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_ZEEK_LOG_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_ZEEK_TRACE_CACHE: OrderedDict[str, bytes] = OrderedDict()
_NEW_LOG_SESSION_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_RED_TEAM_SESSIONS: dict[str, list[dict[str, object]]] = {}

_SYNTHETIC_ZEEK_SAMPLE = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tconn\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\n"
    "1730000100.125000\tCsynth000000000001\t192.168.56.101\t51234\t192.168.56.20\t80\ttcp\thttp\t0.142\t412\t1890\tSF\t6\t5\n"
    "1730000101.402000\tCsynth000000000002\t192.168.56.101\t53112\t192.168.56.10\t53\tudp\tdns\t0.018\t64\t148\tSF\t1\t1\n"
    "1730000103.880000\tCsynth000000000003\t192.168.56.102\t49811\t192.168.56.20\t22\ttcp\tssh\t1.920\t1240\t2180\tSF\t14\t12\n"
    "1730000106.015000\tCsynth000000000004\t192.168.56.103\t60412\t192.168.56.20\t445\ttcp\t-\t0.002\t0\t0\tREJ\t1\t1\n"
    "1730000108.550000\tCsynth000000000005\t192.168.56.101\t51990\t192.168.56.20\t443\ttcp\tssl\t0.510\t820\t4320\tSF\t9\t10\n"
).encode("utf-8")


def _put_lru(cache: OrderedDict, key: Any, value: Any, max_size: int) -> None:
    if key in cache:
        cache.move_to_end(key)
    cache[key] = value
    while len(cache) > max_size:
        cache.popitem(last=False)


def _json_safe(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (bool, str)):
        return value
    if isinstance(value, (np.bool_,)):
        return bool(value)
    if isinstance(value, (int, np.integer)):
        return int(value)
    if isinstance(value, (float, np.floating)):
        fval = float(value)
        return fval if math.isfinite(fval) else None
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if pd.isna(value):
        return None
    return str(value)


def _load_cached_model():
    if not ARTIFACT_PATH.is_file():
        return None, None
    try:
        sig = model_artifact_signature(ARTIFACT_PATH)
        if (
            _MODEL_CACHE["model"] is not None
            and _MODEL_CACHE["path"] == str(ARTIFACT_PATH)
            and _MODEL_CACHE["signature"] == sig
        ):
            return _MODEL_CACHE["model"], None
        model = load_local_model(ARTIFACT_PATH)
        _MODEL_CACHE["path"] = str(ARTIFACT_PATH)
        _MODEL_CACHE["signature"] = sig
        _MODEL_CACHE["model"] = model
        return model, None
    except Exception as exc:
        return None, f"Không thể tải mô hình cục bộ: {exc}"


def _read_official_csv(sample_size: int) -> pd.DataFrame:
    source = DATA_DIR / "UNSW_NB15_testing-set.csv"
    if not source.is_file():
        raise HTTPException(
            status_code=404,
            detail="Chưa có bộ dữ liệu UNSW-NB15 test. Hãy chạy python scripts/download_unsw_nb15.py.",
        )
    stat = source.stat()
    key = (str(source), int(stat.st_mtime_ns), int(stat.st_size), int(sample_size))
    if key in _OFFICIAL_DF_CACHE:
        _OFFICIAL_DF_CACHE.move_to_end(key)
        return _OFFICIAL_DF_CACHE[key].copy()
    df = pd.read_csv(source, nrows=sample_size)
    _put_lru(_OFFICIAL_DF_CACHE, key, df, 4)
    return df.copy()


def _prepare_dataset_results(
    *,
    source: str = "official",
    sample_size: int = 2500,
    upload_id: str | None = None,
) -> dict[str, Any]:
    if not 1 <= sample_size <= MAX_PREVIEW_ROWS:
        raise HTTPException(status_code=400, detail=f"sample_size phải nằm trong 1..{MAX_PREVIEW_ROWS:,}")

    if source == "upload":
        if not upload_id or upload_id not in _UPLOAD_CACHE:
            raise HTTPException(
                status_code=404,
                detail="Không tìm thấy phiên CSV đã tải lên (hoặc phiên đã hết hạn). Hãy tải lại tệp CSV.",
            )
        cached_upload = _UPLOAD_CACHE[upload_id]
        raw_frame = cached_upload["frame"].head(sample_size).copy()
        source_display = f"CSV tải lên: {cached_upload['filename']}"
        source_kind = "uploaded_csv"
    elif source == "official":
        raw_frame = _read_official_csv(sample_size)
        source_display = "UNSW-NB15 testing-set.csv"
        source_kind = "historical_unsw_test"
    else:
        raise HTTPException(status_code=400, detail="Tham số source phải là 'official' hoặc 'upload'.")

    try:
        frame = validate_flows(raw_frame)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    model, model_error = _load_cached_model()
    predictions = None
    if model is not None:
        try:
            predictions = predict_batch(model, frame)
        except (ValueError, KeyError) as exc:
            model_error = f"Dữ liệu chưa tương thích với mô hình: {exc}"
            predictions = None

    results = frame.reset_index(drop=True).copy()
    if predictions is not None:
        results["AI_verdict"] = predictions["verdict"].to_numpy()
        results["AI_attack_probability"] = predictions["attack_probability"].to_numpy()
    records = results.to_dict("records")
    results["flow_ref"] = [flow_id(row) for row in records]
    results["row_index"] = list(range(len(results)))

    return {
        "results": results,
        "model": model,
        "predictions_available": predictions is not None,
        "model_error": model_error,
        "source_display": source_display,
        "source_kind": source_kind,
        "sample_size": sample_size,
    }


def _serialize_flow_row(row_dict: dict[str, Any]) -> dict[str, Any]:
    evidence = {
        str(k): _json_safe(v)
        for k, v in row_dict.items()
        if k not in NON_FEATURE_FIELDS and k != "row_index"
    }
    prob = _json_safe(row_dict.get("AI_attack_probability"))
    band = priority_band_from_probability(prob)
    risk, reasons = assess_signal(row_dict)
    return {
        "row_index": int(row_dict.get("row_index", 0)),
        "flow_ref": str(row_dict.get("flow_ref", "")),
        "proto": _json_safe(row_dict.get("proto")),
        "service": _json_safe(row_dict.get("service")),
        "state": _json_safe(row_dict.get("state")),
        "dur": _json_safe(row_dict.get("dur")),
        "sbytes": _json_safe(row_dict.get("sbytes")),
        "dbytes": _json_safe(row_dict.get("dbytes")),
        "spkts": _json_safe(row_dict.get("spkts")),
        "dpkts": _json_safe(row_dict.get("dpkts")),
        "rate": _json_safe(row_dict.get("rate")),
        "AI_verdict": _json_safe(row_dict.get("AI_verdict")),
        "AI_attack_probability": prob,
        "priority_band": {
            "code": band["code"],
            "label": band["label"],
            "rank": band["rank"],
        },
        "label": _json_safe(row_dict.get("label")),
        "attack_cat": _json_safe(row_dict.get("attack_cat")),
        "signal_score": int(risk),
        "signal_reasons": reasons,
        "flow_evidence": evidence,
    }


def _count_existing_cases(db_path: Path) -> int:
    if not db_path.is_file():
        return 0
    try:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM cases").fetchone()
            return int(row[0]) if row else 0
    except sqlite3.Error:
        return 0


def _list_cases_safe(db_path: Path, state_filter: str | None = None) -> list[dict[str, Any]]:
    if not db_path.is_file():
        return []
    df = list_cases(db_path)
    if state_filter and state_filter != "ALL":
        df = df[df["state"] == state_filter]
    return [_json_safe(rec) for rec in df.to_dict("records")]


def create_app() -> FastAPI:
    app = FastAPI(
        title="DA005 Sentinel Lab API",
        version="1.0.0",
        description="FastAPI adapter layer over DA005 tested Python SIEM/SOC, Blue Team Zeek, and Red Team planning modules.",
    )

    cors_origins_env = os.environ.get("DA005_CORS_ORIGINS", "")
    origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    if cors_origins_env.strip():
        origins.extend(
            item.strip() for item in cors_origins_env.split(",") if item.strip()
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(dict.fromkeys(origins)),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # System & Health
    # ------------------------------------------------------------------
    @app.get("/api/v1/health")
    def health():
        return {
            "status": "ok",
            "service": "da005-sentinel-api",
            "version": "1.0.0",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/v1/system/status")
    def system_status():
        dataset_path = DATA_DIR / "UNSW_NB15_testing-set.csv"
        model_ready = ARTIFACT_PATH.is_file()
        model_err = None
        if model_ready:
            _, model_err = _load_cached_model()
            if model_err:
                model_ready = False

        return {
            "status": "ok",
            "mode": "offline_research_console",
            "live_capture_enabled": False,
            "red_team_execution_enabled": False,
            "vmware_environment_status": "not_checked_offline_only",
            "dataset": {
                "unsw_test_available": dataset_path.is_file(),
                "unsw_test_path": "data/raw/unsw_nb15/UNSW_NB15_testing-set.csv",
            },
            "model": {
                "trained_local_artifact_available": model_ready,
                "artifact_path": "artifacts/unsw_binary_rf.joblib",
                "error": model_err,
            },
            "reports": {
                "local_metrics_available": METRICS_PATH.is_file(),
                "official_baseline_available": OFFICIAL_METRICS_PATH.is_file(),
                "official_comparison_available": OFFICIAL_COMPARISON_PATH.is_file(),
                "official_importance_available": OFFICIAL_IMPORTANCE_PATH.is_file(),
            },
            "soc_store": {
                "dataset_cases_count": _count_existing_cases(SOC_DB_PATH),
                "cyber_lab_cases_count": _count_existing_cases(CYBER_LAB_DB_PATH),
                "case_states": list(CASE_STATES),
            },
            "active_uploads": len(_UPLOAD_CACHE),
        }

    # ------------------------------------------------------------------
    # Module 1: Dataset SOC (/api/v1/dataset/* & /api/v1/soc/*)
    # ------------------------------------------------------------------
    @app.post("/api/v1/dataset/upload-csv")
    async def upload_dataset_csv(
        file: UploadFile = File(...),
        limit: int = Form(default=2500),
    ):
        if not 1 <= limit <= MAX_PREVIEW_ROWS:
            raise HTTPException(
                status_code=400,
                detail=f"Giới hạn đọc xem trước phải từ 1 đến {MAX_PREVIEW_ROWS:,} dòng.",
            )
        raw = await file.read(MAX_CSV_BYTES + 1)
        if len(raw) > MAX_CSV_BYTES:
            raise HTTPException(status_code=413, detail="Giới hạn mỗi tệp CSV là 15 MiB.")
        try:
            frame = read_uploaded_flows(raw, limit=limit)
            frame = validate_flows(frame)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=f"Tệp CSV không hợp lệ: {exc}") from exc

        upload_id = uuid.uuid4().hex[:16]
        filename = Path(file.filename or "uploaded.csv").name
        _put_lru(
            _UPLOAD_CACHE,
            upload_id,
            {
                "filename": filename,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
                "frame": frame,
            },
            MAX_CACHED_UPLOADS,
        )
        return {
            "upload_id": upload_id,
            "filename": filename,
            "sha256": _UPLOAD_CACHE[upload_id]["sha256"],
            "rows_loaded": int(len(frame)),
            "has_ground_truth_label": "label" in frame.columns,
        }

    @app.get("/api/v1/dataset/overview")
    def dataset_overview(
        source: str = Query(default="official"),
        sample_size: int = Query(default=2500, ge=100, le=10000),
        upload_id: str | None = Query(default=None),
    ):
        ctx = _prepare_dataset_results(source=source, sample_size=sample_size, upload_id=upload_id)
        results: pd.DataFrame = ctx["results"]
        preds_ok: bool = ctx["predictions_available"]

        has_label = "label" in results.columns and not results["label"].isna().all()
        attack_observed = int((results["label"] == 1).sum()) if has_label else None
        ai_attack = int((results["AI_verdict"] == "Attack").sum()) if preds_ok else None

        priority_dist = None
        if preds_ok:
            probs = results["AI_attack_probability"]
            priority_dist = {
                "critical": int((probs >= 0.90).sum()),
                "high": int(((probs >= 0.80) & (probs < 0.90)).sum()),
                "medium": int(((probs >= 0.65) & (probs < 0.80)).sum()),
                "low": int(((probs >= 0.50) & (probs < 0.65)).sum()),
                "normal": int((probs < 0.50).sum()),
            }

        proto_counts = [
            {"name": str(k), "count": int(v)}
            for k, v in results["proto"].astype(str).value_counts().head(10).items()
        ]
        attack_cat_counts = None
        if "attack_cat" in results.columns:
            attack_cat_counts = [
                {"name": str(k), "count": int(v)}
                for k, v in results["attack_cat"].fillna("Normal").astype(str).value_counts().head(10).items()
            ]

        filter_options = {
            "protocols": sorted(results["proto"].dropna().astype(str).unique().tolist()),
            "services": sorted(results["service"].dropna().astype(str).unique().tolist()),
            "states": sorted(results["state"].dropna().astype(str).unique().tolist()),
        }

        cases = _list_cases_safe(SOC_DB_PATH)
        return {
            "provenance": {
                "source_display": ctx["source_display"],
                "source_kind": ctx["source_kind"],
                "rows_loaded": int(len(results)),
                "sample_size_limit": sample_size,
                "live_capture_enabled": False,
                "has_original_ip_or_timestamp": False,
                "predictions_available": preds_ok,
                "model_error": ctx["model_error"],
                "notice": (
                    "Dữ liệu lịch sử UNSW-NB15 (ngoại tuyến), không chứa IP và timestamp sự kiện gốc; "
                    "thứ tự bản ghi không phải chuỗi thời gian thực."
                ),
            },
            "kpis": {
                "flows_read": int(len(results)),
                "ground_truth_attacks": attack_observed,
                "ai_predicted_attacks": ai_attack,
                "soc_cases_total": len(cases),
            },
            "priority_distribution": priority_dist,
            "protocol_distribution": proto_counts,
            "attack_category_distribution": attack_cat_counts,
            "filter_options": filter_options,
            "recent_cases": cases[:5],
        }

    @app.get("/api/v1/dataset/hunting")
    def dataset_hunting(
        source: str = Query(default="official"),
        sample_size: int = Query(default=2500, ge=100, le=10000),
        upload_id: str | None = Query(default=None),
        protocols: list[str] = Query(default=[]),
        services: list[str] = Query(default=[]),
        states: list[str] = Query(default=[]),
        only_ai_attacks: bool = Query(default=False),
        min_attack_probability: float | None = Query(default=None, ge=0.0, le=1.0),
        search: str = Query(default=""),
        sort_by: str = Query(default="row_index"),
        sort_dir: str = Query(default="asc"),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=25, ge=5, le=200),
    ):
        ctx = _prepare_dataset_results(source=source, sample_size=sample_size, upload_id=upload_id)
        results: pd.DataFrame = ctx["results"]
        preds_ok: bool = ctx["predictions_available"]

        if (only_ai_attacks or min_attack_probability is not None) and not preds_ok:
            raise HTTPException(
                status_code=400,
                detail="Không thể lọc theo kết quả AI khi chưa có mô hình cục bộ.",
            )

        filtered = filter_hunting_flows(
            results,
            protocols=protocols,
            services=services,
            states=states,
            only_ai_attacks=only_ai_attacks,
            min_attack_probability=min_attack_probability,
        )

        q = search.strip().lower()
        if q:
            mask = (
                filtered["flow_ref"].astype(str).str.lower().str.contains(q, regex=False)
                | filtered["proto"].astype(str).str.lower().str.contains(q, regex=False)
                | filtered["service"].astype(str).str.lower().str.contains(q, regex=False)
                | filtered["state"].astype(str).str.lower().str.contains(q, regex=False)
            )
            if "attack_cat" in filtered.columns:
                mask = mask | filtered["attack_cat"].fillna("").astype(str).str.lower().str.contains(q, regex=False)
            filtered = filtered.loc[mask]

        allowed_sorts = {
            "row_index", "proto", "service", "state", "dur", "sbytes", "dbytes",
            "rate", "AI_attack_probability", "label",
        }
        sort_col = sort_by if sort_by in allowed_sorts and sort_by in filtered.columns else "row_index"
        ascending = sort_dir.lower() != "desc"
        filtered = filtered.sort_values(sort_col, ascending=ascending, kind="stable")

        total_filtered = int(len(filtered))
        total_pages = max(1, (total_filtered + page_size - 1) // page_size)
        safe_page = min(page, total_pages)
        start = (safe_page - 1) * page_size
        page_df = filtered.iloc[start : start + page_size]

        rows = [_serialize_flow_row(rec) for rec in page_df.to_dict("records")]
        return {
            "predictions_available": preds_ok,
            "total_loaded": int(len(results)),
            "total_filtered": total_filtered,
            "page": safe_page,
            "page_size": page_size,
            "total_pages": total_pages,
            "rows": rows,
        }

    @app.get("/api/v1/dataset/hunting/export-csv")
    def dataset_hunting_export_csv(
        source: str = Query(default="official"),
        sample_size: int = Query(default=2500, ge=100, le=10000),
        upload_id: str | None = Query(default=None),
        protocols: list[str] = Query(default=[]),
        services: list[str] = Query(default=[]),
        states: list[str] = Query(default=[]),
        only_ai_attacks: bool = Query(default=False),
        min_attack_probability: float | None = Query(default=None, ge=0.0, le=1.0),
        search: str = Query(default=""),
    ):
        ctx = _prepare_dataset_results(source=source, sample_size=sample_size, upload_id=upload_id)
        results: pd.DataFrame = ctx["results"]
        if (only_ai_attacks or min_attack_probability is not None) and not ctx["predictions_available"]:
            raise HTTPException(
                status_code=400,
                detail="Không thể lọc theo kết quả AI khi chưa có mô hình cục bộ.",
            )
        filtered = filter_hunting_flows(
            results,
            protocols=protocols,
            services=services,
            states=states,
            only_ai_attacks=only_ai_attacks,
            min_attack_probability=min_attack_probability,
        )
        q = search.strip().lower()
        if q:
            mask = (
                filtered["flow_ref"].astype(str).str.lower().str.contains(q, regex=False)
                | filtered["proto"].astype(str).str.lower().str.contains(q, regex=False)
                | filtered["service"].astype(str).str.lower().str.contains(q, regex=False)
                | filtered["state"].astype(str).str.lower().str.contains(q, regex=False)
            )
            filtered = filtered.loc[mask]

        fields = [
            c for c in [
                "flow_ref", "proto", "service", "state", "dur", "sbytes", "dbytes",
                "rate", "AI_verdict", "AI_attack_probability", "label", "attack_cat",
            ]
            if c in filtered.columns
        ]
        csv_bytes = safe_csv_bytes(filtered[fields])
        return Response(
            content=csv_bytes,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="da005_hunting_results.csv"'},
        )

    @app.get("/api/v1/dataset/evaluation")
    def dataset_evaluation(
        source: str = Query(default="official"),
        sample_size: int = Query(default=2500, ge=100, le=10000),
        upload_id: str | None = Query(default=None),
    ):
        ctx = _prepare_dataset_results(source=source, sample_size=sample_size, upload_id=upload_id)
        results: pd.DataFrame = ctx["results"]
        preds_ok: bool = ctx["predictions_available"]
        model = ctx["model"]

        benchmark_data = None
        if METRICS_PATH.is_file() or OFFICIAL_METRICS_PATH.is_file():
            report_file = METRICS_PATH if METRICS_PATH.is_file() else OFFICIAL_METRICS_PATH
            metrics = json.loads(report_file.read_text(encoding="utf-8"))
            cm = metrics["confusion_matrix_0_1"]
            tn, fp = int(cm[0][0]), int(cm[0][1])
            fn, tp = int(cm[1][0]), int(cm[1][1])
            report = metrics["classification_report"]
            benchmark_data = {
                "source_file": report_file.name,
                "source_kind": "local_artifacts" if report_file == METRICS_PATH else "archived_official_report",
                "train_size": int(metrics["train_size"]),
                "test_size": int(metrics["test_size"]),
                "attack_precision": float(report["1"]["precision"]),
                "attack_recall": float(report["1"]["recall"]),
                "attack_f1": float(report["1"]["f1-score"]),
                "average_precision_attack": float(metrics["average_precision_attack"]),
                "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            }

        comparison_data = None
        if OFFICIAL_COMPARISON_PATH.is_file():
            try:
                comparison_data = load_official_comparison(OFFICIAL_COMPARISON_PATH)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                comparison_data = {"error": str(exc)}

        importance_data = None
        if model is not None:
            try:
                imp_df = global_feature_importance(model)
                importance_data = {
                    "source_kind": "local_trained_model",
                    "note": (
                        "MDI / Gini importance trên mô hình Random Forest cục bộ. "
                        "Không phải giải thích nhân quả hay giải thích cho từng flow."
                    ),
                    "features": [
                        {
                            "rank": idx + 1,
                            "feature": str(row["feature"]),
                            "importance": float(row["importance"]),
                            "importance_percent": float(row["importance_percent"]),
                            "encoded_dimensions": int(row["encoded_dimensions"]),
                        }
                        for idx, row in imp_df.iterrows()
                    ],
                }
            except (ValueError, KeyError, AttributeError):
                importance_data = None

        if importance_data is None and OFFICIAL_IMPORTANCE_PATH.is_file():
            archived = json.loads(OFFICIAL_IMPORTANCE_PATH.read_text(encoding="utf-8"))
            importance_data = {
                "source_kind": "archived_official_report",
                "note": (
                    "Đọc từ báo cáo official đã lưu (reports/official_global_feature_importance.json). "
                    "Chưa tải mô hình cục bộ."
                ),
                "features": [
                    {
                        "rank": int(item["rank"]),
                        "feature": str(item["feature"]),
                        "importance": float(item["mdi_importance"]),
                        "importance_percent": float(item["mdi_percent"]),
                        "encoded_dimensions": int(item["encoded_dimensions"]),
                    }
                    for item in archived.get("features", [])
                ],
            }

        sample_diag: dict[str, Any] = {"status": "not_available", "rows": []}
        if not preds_ok:
            sample_diag = {
                "status": "no_model",
                "message": "Chưa có mô hình cục bộ để chẩn đoán ngưỡng trên mẫu đang tải.",
                "rows": [],
            }
        elif "label" not in results.columns:
            sample_diag = {
                "status": "counts_only",
                "message": "Dữ liệu không có nhãn gốc 0/1; chỉ hiển thị số cảnh báo theo ngưỡng.",
                "rows": [
                    {
                        "threshold": t,
                        "alerts": int((results["AI_attack_probability"] >= t).sum()),
                    }
                    for t in (0.5, 0.6, 0.7, 0.8, 0.9)
                ],
            }
        elif results["label"].isna().any() or not results["label"].isin([0, 1]).all():
            sample_diag = {
                "status": "invalid_labels",
                "message": "Nhãn gốc phải đầy đủ và chỉ gồm 0/1; bỏ qua đánh giá theo ngưỡng.",
                "rows": [],
            }
        else:
            diag_df = threshold_diagnostics(
                results["label"].to_numpy(),
                results["AI_attack_probability"].to_numpy(),
            )
            sample_diag = {
                "status": "ok",
                "message": (
                    "Phân tích chẩn đoán trên mẫu đang tải (không phải benchmark toàn bộ tập test, "
                    "không dùng để tối ưu ngưỡng)."
                ),
                "rows": [_json_safe(r) for r in diag_df.to_dict("records")],
            }

        return {
            "predictions_available": preds_ok,
            "local_model_loaded": model is not None,
            "benchmark_metrics": benchmark_data,
            "locked_threshold_comparison": comparison_data,
            "feature_importance": importance_data,
            "sample_threshold_diagnostics": sample_diag,
        }

    @app.get("/api/v1/dataset/alerts")
    def dataset_alerts(
        source: str = Query(default="official"),
        sample_size: int = Query(default=2500, ge=100, le=10000),
        upload_id: str | None = Query(default=None),
        threshold: float = Query(default=0.80, ge=0.50, le=0.99),
        priority: str = Query(default="ALL"),
        limit: int = Query(default=300, ge=1, le=500),
    ):
        ctx = _prepare_dataset_results(source=source, sample_size=sample_size, upload_id=upload_id)
        results: pd.DataFrame = ctx["results"]
        if not ctx["predictions_available"]:
            return {
                "predictions_available": False,
                "threshold": threshold,
                "total_alerts": 0,
                "priority_counts": {"CRIT": 0, "HIGH": 0, "MED": 0, "LOW": 0},
                "alerts": [],
                "message": "Chưa có mô hình AI cục bộ. Chạy python scripts/train_siem.py để tạo mô hình.",
            }

        alerts_df = results[results["AI_attack_probability"] >= threshold].sort_values(
            "AI_attack_probability", ascending=False, kind="stable"
        )
        p_series = alerts_df["AI_attack_probability"]
        priority_counts = {
            "CRIT": int((p_series >= 0.90).sum()),
            "HIGH": int(((p_series >= 0.80) & (p_series < 0.90)).sum()),
            "MED": int(((p_series >= 0.65) & (p_series < 0.80)).sum()),
            "LOW": int(((p_series >= 0.50) & (p_series < 0.65)).sum()),
        }

        serialized = [_serialize_flow_row(rec) for rec in alerts_df.head(limit).to_dict("records")]
        if priority != "ALL":
            serialized = [item for item in serialized if item["priority_band"]["code"] == priority]

        return {
            "predictions_available": True,
            "threshold": threshold,
            "total_alerts": int(len(alerts_df)),
            "displayed_count": len(serialized),
            "priority_counts": priority_counts,
            "alerts": serialized,
        }

    # ------------------------------------------------------------------
    # SOC Cases (/api/v1/soc/cases)
    # ------------------------------------------------------------------
    @app.get("/api/v1/soc/cases")
    def soc_list_cases(state: str = Query(default="ALL")):
        if state != "ALL" and state not in CASE_STATES:
            raise HTTPException(status_code=400, detail="Trạng thái case không hợp lệ.")
        cases = _list_cases_safe(SOC_DB_PATH, state_filter=state)
        return {"cases": cases, "case_states": list(CASE_STATES)}

    @app.post("/api/v1/soc/cases")
    def soc_create_case(payload: CreateCaseRequest):
        ctx = _prepare_dataset_results(
            source=payload.source,
            sample_size=payload.sample_size,
            upload_id=payload.upload_id,
        )
        results: pd.DataFrame = ctx["results"]
        if not ctx["predictions_available"]:
            raise HTTPException(
                status_code=400,
                detail="Không thể tạo case AI khi chưa có mô hình cục bộ.",
            )
        if payload.row_index >= len(results):
            raise HTTPException(status_code=404, detail="Không tìm thấy bản ghi flow theo row_index.")
        row = results.iloc[payload.row_index].to_dict()
        if str(row.get("flow_ref")) != payload.flow_ref:
            raise HTTPException(
                status_code=409,
                detail="flow_ref không khớp với bản ghi hiện tại; vui lòng làm mới danh sách.",
            )
        row.pop("row_index", None)
        try:
            case_id = create_case(
                SOC_DB_PATH,
                row=row,
                verdict=str(row["AI_verdict"]),
                confidence=float(row["AI_attack_probability"]),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "case_id": case_id,
            "message": f"Đã lưu case #{case_id} trong SQLite cục bộ.",
        }

    @app.get("/api/v1/soc/cases/{case_id}")
    def soc_get_case(case_id: int):
        cases = _list_cases_safe(SOC_DB_PATH)
        match = next((c for c in cases if int(c["case_id"]) == case_id), None)
        if match is None:
            raise HTTPException(status_code=404, detail="Không tìm thấy hồ sơ SOC.")
        try:
            evidence = case_evidence(SOC_DB_PATH, case_id)
            history_df = case_history(SOC_DB_PATH, case_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {
            "case": match,
            "flow_evidence": _json_safe(evidence),
            "case_events": [_json_safe(rec) for rec in history_df.to_dict("records")],
            "case_states": list(CASE_STATES),
        }

    @app.patch("/api/v1/soc/cases/{case_id}")
    def soc_update_case(case_id: int, payload: UpdateCaseRequest):
        if payload.state not in CASE_STATES:
            raise HTTPException(status_code=422, detail="Trạng thái xử lý không hợp lệ.")
        try:
            update_case(SOC_DB_PATH, case_id, payload.state, payload.analyst_note)
        except ValueError as exc:
            msg = str(exc)
            code = 404 if "not found" in msg.lower() else 422
            raise HTTPException(status_code=code, detail=msg) from exc
        return {"case_id": case_id, "state": payload.state, "message": "Đã cập nhật hồ sơ SOC."}

    @app.get("/api/v1/soc/cases/{case_id}/export")
    def soc_export_case(case_id: int):
        try:
            report_bytes = export_case_report(SOC_DB_PATH, case_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(
            content=report_bytes,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="da005_soc_case_{case_id}.json"'},
        )

    # ------------------------------------------------------------------
    # Module 2: Cyber Lab (/api/v1/cyber-lab/*)
    # ------------------------------------------------------------------
    def _parse_and_cache_zeek(raw_bytes: bytes, filename: str, *, is_synthetic_demo: bool = False) -> dict[str, Any]:
        if len(raw_bytes) > MAX_LOG_BYTES:
            raise HTTPException(status_code=413, detail="Tệp Zeek vượt quá giới hạn 15 MiB.")
        try:
            events = parse_zeek_conn_log(raw_bytes)
            summary = summarize_offline_flows(events)
        except (ValueError, TypeError, UnicodeDecodeError, OverflowError) as exc:
            raise HTTPException(status_code=422, detail=f"Không thể đọc Zeek conn.log: {exc}") from exc

        sha256 = str(summary["source_sha256"])
        _put_lru(
            _ZEEK_LOG_CACHE,
            sha256,
            {"bytes": raw_bytes, "filename": filename, "events": events, "summary": summary},
            MAX_CACHED_ZEEK_LOGS,
        )
        preview_rows = [
            {
                "record_index": idx,
                "row_number": idx + 1,
                **{k: _json_safe(v) for k, v in ev.items()},
            }
            for idx, ev in enumerate(events[:500])
        ]
        return {
            "filename": filename,
            "is_synthetic_demo": is_synthetic_demo,
            "summary": summary,
            "preview_count": len(preview_rows),
            "events": preview_rows,
        }

    @app.post("/api/v1/cyber-lab/parse-log")
    async def cyber_lab_parse_log(file: UploadFile = File(...)):
        raw = await file.read(MAX_LOG_BYTES + 1)
        filename = Path(file.filename or "conn.log").name
        return _parse_and_cache_zeek(raw, filename, is_synthetic_demo=False)

    @app.post("/api/v1/cyber-lab/load-sample-fixture")
    def cyber_lab_load_sample_fixture():
        return _parse_and_cache_zeek(
            _SYNTHETIC_ZEEK_SAMPLE,
            "synthetic_demo_conn.log",
            is_synthetic_demo=True,
        )

    @app.post("/api/v1/cyber-lab/review-trace")
    async def cyber_lab_review_trace(
        source_sha256: str = Form(...),
        trace_file: UploadFile = File(...),
    ):
        if source_sha256 not in _ZEEK_LOG_CACHE:
            raise HTTPException(status_code=404, detail="Chưa nạp conn.log tương ứng trong phiên.")
        trace_bytes = await trace_file.read(MAX_PRIVATE_TRACE_BYTES + 1)
        if len(trace_bytes) > MAX_PRIVATE_TRACE_BYTES:
            raise HTTPException(status_code=413, detail="Trace JSON vượt giới hạn 16 MiB.")
        entry = _ZEEK_LOG_CACHE[source_sha256]
        events = entry["events"]
        try:
            trace_review = review_private_zeek_trace(entry["bytes"], trace_bytes)
        except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
            raise HTTPException(status_code=422, detail=f"Không thể đối chiếu trace nghiên cứu: {exc}") from exc

        trace_sha256 = hashlib.sha256(trace_bytes).hexdigest()
        _put_lru(_ZEEK_TRACE_CACHE, trace_sha256, trace_bytes, MAX_CACHED_TRACES)

        candidates = []
        for row in trace_review["rows"]:
            if row["predicted_attack"]:
                idx = int(row["record_index"])
                ev = events[idx]
                band = priority_band_from_probability(row["attack_probability"])
                candidates.append({
                    "record_index": idx,
                    "zeek_row": idx + 1,
                    "uid": row["uid"],
                    "attack_probability": float(row["attack_probability"]),
                    "priority_band": {"code": band["code"], "label": band["label"], "rank": band["rank"]},
                    "event_time_utc": ev["event_time_utc"],
                    "src_ip": ev["src_ip"],
                    "dst_ip": ev["dst_ip"],
                    "proto": ev["proto"],
                    "selectable_for_case": idx < 500,
                })
        candidates.sort(key=lambda item: item["attack_probability"], reverse=True)
        return {
            "source_sha256": source_sha256,
            "trace_sha256": trace_sha256,
            "flow_count": int(trace_review["flow_count"]),
            "candidate_count": int(trace_review["candidate_count"]),
            "selected_threshold": float(trace_review["selected_threshold"]),
            "candidates": candidates[:500],
        }

    @app.post("/api/v1/cyber-lab/manual-case")
    def cyber_lab_manual_case(payload: CyberLabManualCaseRequest):
        if payload.consent is not True:
            raise HTTPException(status_code=422, detail="Cần xác nhận đây là log được phép xử lý.")
        if payload.source_sha256 not in _ZEEK_LOG_CACHE:
            raise HTTPException(status_code=404, detail="Chưa nạp conn.log tương ứng trong phiên.")
        source_data = _ZEEK_LOG_CACHE[payload.source_sha256]["bytes"]
        try:
            case_id = create_offline_review_case(
                CYBER_LAB_DB_PATH,
                source_data=source_data,
                record_index=payload.record_index,
            )
            verified_bytes = export_verified_offline_case(
                CYBER_LAB_DB_PATH,
                case_id=case_id,
                source_data=source_data,
                record_index=payload.record_index,
            )
        except (ValueError, TypeError, OSError, sqlite3.Error) as exc:
            raise HTTPException(status_code=422, detail=f"Không thể lưu hồ sơ: {exc}") from exc
        return {
            "case_id": case_id,
            "verdict": "Unclassified",
            "verified_export": json.loads(verified_bytes.decode("utf-8")),
        }

    @app.post("/api/v1/cyber-lab/research-candidate-case")
    def cyber_lab_research_candidate_case(payload: CyberLabResearchCaseRequest):
        if payload.analyst_confirmed is not True:
            raise HTTPException(status_code=422, detail="Cần xác nhận đã xem bằng chứng trước khi mở hồ sơ.")
        if payload.source_sha256 not in _ZEEK_LOG_CACHE or payload.trace_sha256 not in _ZEEK_TRACE_CACHE:
            raise HTTPException(status_code=404, detail="Không tìm thấy log hoặc trace tương ứng trong phiên.")
        source_data = _ZEEK_LOG_CACHE[payload.source_sha256]["bytes"]
        trace_data = _ZEEK_TRACE_CACHE[payload.trace_sha256]
        try:
            case_id = create_research_candidate_case(
                CYBER_LAB_DB_PATH,
                source_data=source_data,
                trace_data=trace_data,
                record_index=payload.record_index,
                analyst_confirmed=payload.analyst_confirmed,
            )
            verified_bytes = export_verified_offline_case(
                CYBER_LAB_DB_PATH,
                case_id=case_id,
                source_data=source_data,
                record_index=payload.record_index,
            )
        except (ValueError, TypeError, OSError, sqlite3.Error) as exc:
            raise HTTPException(status_code=422, detail=f"Không thể mở hồ sơ nghiên cứu: {exc}") from exc
        return {
            "case_id": case_id,
            "verdict": "Unclassified",
            "verified_export": json.loads(verified_bytes.decode("utf-8")),
        }

    # ------------------------------------------------------------------
    # Module 3: Red Team Lab (/api/v1/red-team/*)
    # ------------------------------------------------------------------
    def _red_team_state_payload(session_id: str) -> dict[str, Any]:
        events = _RED_TEAM_SESSIONS.setdefault(session_id, [])
        audit = export_planning_audit(events)
        feedback = extract_manual_feedback(events)
        summary = summarize_feedback(feedback)
        pending_id = audit["pending_proposal_id"]
        pending_plan = None
        if pending_id is not None:
            last_prop = audit["events"][-1]
            pending_plan = choose_scenario(
                feedback,
                strategy=str(last_prop["strategy"]),
                seed=int(last_prop["seed"]),
            )
        return {
            "session_id": session_id,
            "execution_enabled": False,
            "network_access": False,
            "max_proposals": MAX_PROPOSALS,
            "scenarios": [
                {
                    "scenario_id": s.scenario_id,
                    "title": s.title,
                    "objective": s.objective,
                    "category": s.category,
                }
                for s in SCENARIOS
            ],
            "audit": audit,
            "summary": summary,
            "pending_plan": pending_plan,
        }

    @app.get("/api/v1/red-team/state")
    def red_team_state(session_id: str = Query(default="default")):
        return _red_team_state_payload(session_id)

    @app.post("/api/v1/red-team/propose")
    def red_team_propose(payload: RedTeamProposeRequest):
        events = _RED_TEAM_SESSIONS.setdefault(payload.session_id, [])
        feedback = extract_manual_feedback(events)
        try:
            plan = choose_scenario(feedback, strategy=payload.strategy, seed=payload.seed)
            updated = append_proposal(
                events,
                plan,
                seed=payload.seed,
                recorded_at_utc=datetime.now(timezone.utc).isoformat(),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        _RED_TEAM_SESSIONS[payload.session_id] = updated
        return _red_team_state_payload(payload.session_id)

    @app.post("/api/v1/red-team/feedback")
    def red_team_feedback(payload: RedTeamFeedbackRequest):
        if payload.confirm is not True:
            raise HTTPException(
                status_code=422,
                detail="Cần xác nhận đây là quan sát thủ công chưa được kiểm chứng.",
            )
        events = _RED_TEAM_SESSIONS.setdefault(payload.session_id, [])
        try:
            updated = append_manual_feedback(
                events,
                proposal_id=payload.proposal_id,
                blue_flagged=payload.blue_flagged,
                recorded_at_utc=datetime.now(timezone.utc).isoformat(),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        _RED_TEAM_SESSIONS[payload.session_id] = updated
        return _red_team_state_payload(payload.session_id)

    @app.post("/api/v1/red-team/reset")
    def red_team_reset(payload: RedTeamResetRequest):
        _RED_TEAM_SESSIONS[payload.session_id] = []
        return _red_team_state_payload(payload.session_id)

    @app.post("/api/v1/red-team/synthetic-benchmark")
    def red_team_synthetic_benchmark(payload: RedTeamSyntheticBenchmarkRequest):
        try:
            result = compare_synthetic_policies(
                rounds=payload.rounds,
                trials=payload.trials,
                seed=payload.seed,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return result

    # ------------------------------------------------------------------
    # Module 4: New Log Review (/api/v1/new-log-review/*)
    # ------------------------------------------------------------------
    @app.post("/api/v1/new-log-review/verify")
    async def new_log_review_verify(
        log_file: UploadFile = File(...),
        report_file: UploadFile = File(...),
        model_path: str = Form(...),
        expected_model_sha256: str = Form(...),
        expected_log_sha256: str = Form(...),
        manifest_path: str = Form(...),
        expected_manifest_sha256: str = Form(...),
        cidr_input: str = Form(...),
        offline_import_report_path: str = Form(default=""),
        offline_import_report_sha256: str = Form(default=""),
        offline_import_pcap_path: str = Form(default=""),
    ):
        log_bytes = await log_file.read(MAX_LOG_BYTES + 1)
        report_bytes = await report_file.read(MAX_NEW_LOG_REPORT_BYTES + 1)
        if len(log_bytes) > MAX_LOG_BYTES or len(report_bytes) > MAX_NEW_LOG_REPORT_BYTES:
            raise HTTPException(status_code=413, detail="Tệp vượt giới hạn kích thước; không xử lý.")
        cidrs = [part.strip() for part in cidr_input.split(",") if part.strip()]
        if not 1 <= len(cidrs) <= 4:
            raise HTTPException(status_code=422, detail="Phải khai báo từ 1 đến 4 CIDR được phép.")

        try:
            manifest = Path(manifest_path.strip())
            if manifest.is_symlink():
                raise ValueError("Manifest symlink refused")
            manifest = manifest.resolve(strict=True)
            if not manifest.is_file() or manifest.is_relative_to(ROOT):
                raise ValueError("Manifest must be a private regular file outside Git")
            with manifest.open("rb") as stream:
                manifest_bytes = stream.read(MAX_MANIFEST_BYTES + 1)
            expected_manifest = expected_manifest_sha256.strip()
            if (
                not 0 < len(manifest_bytes) <= MAX_MANIFEST_BYTES
                or len(expected_manifest) != 64
                or any(ch not in "0123456789abcdef" for ch in expected_manifest)
                or hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest
            ):
                raise ValueError("Pinned manifest SHA-256 mismatch")
            captures, loaded_manifest_sha = load_experiment_manifest(manifest, lab_cidrs=cidrs)
            if loaded_manifest_sha != expected_manifest:
                raise ValueError("Manifest changed during validation")
            dataset = build_labeled_lab_dataset(captures)

            pcap_options = (
                offline_import_report_path.strip(),
                offline_import_report_sha256.strip(),
                offline_import_pcap_path.strip(),
            )
            if any(pcap_options) and not all(pcap_options):
                raise ValueError("All three pinned PCAP fields are required")
            pinned_pcap = None
            if all(pcap_options):
                import_report = Path(pcap_options[0])
                pinned_pcap = verify_offline_pcap_import(
                    import_report,
                    expected_report_sha256=pcap_options[1],
                    pcap_path=Path(pcap_options[2]),
                    log_path=import_report.parent / "conn.log",
                    lab_cidrs=cidrs,
                )
                if (
                    pinned_pcap["zeek_conn_sha256"] != expected_log_sha256.strip()
                    or hashlib.sha256(log_bytes).hexdigest() != pinned_pcap["zeek_conn_sha256"]
                ):
                    raise ValueError("Uploaded Zeek log differs from pinned PCAP import")

            verified_result = prepare_new_log_review(
                source_data=log_bytes,
                report_data=report_bytes,
                model_path=model_path.strip(),
                expected_log_sha256=expected_log_sha256.strip(),
                expected_model_sha256=expected_model_sha256.strip(),
                lab_cidrs=cidrs,
                declared_dataset=dataset,
                declared_manifest_sha256=expected_manifest,
                declared_captures=captures,
            )
        except (ValueError, TypeError, OSError, UnicodeError, OverflowError, RecursionError) as exc:
            raise HTTPException(
                status_code=422,
                detail="Từ chối xác minh. Kiểm tra tệp và SHA-256 riêng tư trên máy; không hiển thị dữ liệu nhạy cảm.",
            ) from exc

        review_token = uuid.uuid4().hex[:16]
        _put_lru(
            _NEW_LOG_SESSION_CACHE,
            review_token,
            {
                "log_bytes": log_bytes,
                "report_bytes": report_bytes,
                "model_path": model_path.strip(),
                "manifest_path": manifest_path.strip(),
                "expected_manifest_sha256": expected_manifest,
                "expected_log_sha256": expected_log_sha256.strip(),
                "expected_model_sha256": expected_model_sha256.strip(),
                "lab_cidrs": cidrs,
                "pcap_options": pcap_options,
            },
            MAX_CACHED_NEW_LOG_SESSIONS,
        )

        candidates = []
        for row in verified_result["candidate_rows"]:
            prob = float(row["P(Attack) research"])
            band = priority_band_from_probability(prob)
            candidates.append({
                "zeek_row": int(row["Zeek row"]),
                "record_index": int(row["Zeek row"]) - 1,
                "uid": row["UID"],
                "attack_probability": prob,
                "priority_band": {"code": band["code"], "label": band["label"], "rank": band["rank"]},
                "event_time_utc": row["Zeek time UTC"],
                "src_ip": row["Source IP"],
                "dst_ip": row["Destination IP"],
            })

        review = verified_result["review"]
        return {
            "review_token": review_token,
            "flow_count": int(review["flow_count"]),
            "research_candidate_count": int(review["research_candidate_count"]),
            "visible_flow_count": int(verified_result["visible_flow_count"]),
            "validation_threshold": float(verified_result["validation_threshold"]),
            "manifest_sha256": verified_result["declared_partition_check"]["manifest_sha256"],
            "report_sha256": review["report_sha256"],
            "declared_scope_sha256": verified_result["declared_scope_sha256"],
            "pcap_verified": pinned_pcap is not None,
            "candidates": candidates,
        }

    @app.post("/api/v1/new-log-review/create-case")
    def new_log_review_create_case(
        review_token: str = Form(...),
        db_path: str = Form(...),
        record_index: int = Form(...),
        analyst_confirmed: bool = Form(...),
        operator_confirmed_authorized: bool = Form(...),
        operator_confirmed_new_capture: bool = Form(...),
        research_queue_path: str = Form(default=""),
        research_queue_sha: str = Form(default=""),
        research_queue_ref: str = Form(default=""),
    ):
        if review_token not in _NEW_LOG_SESSION_CACHE:
            raise HTTPException(status_code=404, detail="Phiên xác minh NEW-log không tồn tại hoặc đã hết hạn.")
        session = _NEW_LOG_SESSION_CACHE[review_token]
        pcap_options = session["pcap_options"]
        try:
            case_id = create_ui_candidate_case(
                db_path=db_path.strip(),
                model_path=session["model_path"],
                manifest_path=session["manifest_path"],
                expected_manifest_sha256=session["expected_manifest_sha256"],
                source_data=session["log_bytes"],
                report_data=session["report_bytes"],
                expected_log_sha256=session["expected_log_sha256"],
                expected_model_sha256=session["expected_model_sha256"],
                lab_cidrs=session["lab_cidrs"],
                record_index=record_index,
                analyst_confirmed=analyst_confirmed,
                operator_confirmed_authorized=operator_confirmed_authorized,
                operator_confirmed_new_capture=operator_confirmed_new_capture,
                offline_import_report_path=(pcap_options[0] or None),
                offline_import_report_sha256=(pcap_options[1] or None),
                offline_import_pcap_path=(pcap_options[2] or None),
                research_alert_bundle_path=(research_queue_path.strip() or None),
                expected_research_alert_bundle_sha256=(research_queue_sha.strip() or None),
                research_alert_ref=(research_queue_ref.strip() or None),
            )
        except (ValueError, TypeError, OSError, UnicodeError, OverflowError, RecursionError) as exc:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Từ chối ghi SOC. Kiểm tra lại xác nhận, model, manifest, "
                    "log, CIDR, research queue và SQLite riêng tư; không có kết luận tấn công."
                ),
            ) from exc
        return {
            "case_id": case_id,
            "verdict": "Unclassified",
            "message": f"SOC case #{case_id} (Unclassified). Có thể là hồ sơ đã tồn tại; không xác nhận tấn công.",
        }

    @app.post("/api/v1/new-log-review/private-cases/list")
    def new_log_review_private_cases_list(payload: PrivateCasesListRequest):
        try:
            return list_private_zeek_cases(payload.db_path.strip())
        except (ValueError, OSError, sqlite3.DatabaseError, TypeError) as exc:
            raise HTTPException(
                status_code=422,
                detail="Không thể đọc hồ sơ SOC riêng tư. Kiểm tra tệp SQLite hiện có, quyền truy cập và định dạng.",
            ) from exc

    @app.post("/api/v1/new-log-review/private-cases/detail")
    def new_log_review_private_cases_detail(payload: PrivateCaseDetailRequest):
        try:
            return read_private_zeek_case(payload.db_path.strip(), payload.case_id)
        except (ValueError, OSError, sqlite3.DatabaseError, TypeError) as exc:
            raise HTTPException(
                status_code=422,
                detail="Không thể đọc chi tiết hồ sơ SOC riêng tư.",
            ) from exc

    # Bounded offline-only replay sessions; no VMware access or model inference.
    from .live_sessions import create_live_router
    app.include_router(create_live_router(_SYNTHETIC_ZEEK_SAMPLE))

    return app


app = create_app()
