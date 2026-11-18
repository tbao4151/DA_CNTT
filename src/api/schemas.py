"""Pydantic request and response schemas for DA005 Sentinel Lab API v1."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class PriorityBand(BaseModel):
    code: str
    label: str
    rank: int


class CreateCaseRequest(BaseModel):
    source: Literal["official", "upload"] = "official"
    sample_size: int = Field(default=2500, ge=100, le=10000)
    upload_id: str | None = None
    row_index: int = Field(..., ge=0)
    flow_ref: str = Field(..., min_length=1, max_length=64)


class UpdateCaseRequest(BaseModel):
    state: str = Field(..., min_length=1, max_length=64)
    analyst_note: str = Field(..., min_length=1, max_length=2000)


class CyberLabManualCaseRequest(BaseModel):
    source_sha256: str = Field(..., min_length=64, max_length=64)
    record_index: int = Field(..., ge=0, lt=500)
    consent: bool


class CyberLabResearchCaseRequest(BaseModel):
    source_sha256: str = Field(..., min_length=64, max_length=64)
    trace_sha256: str = Field(..., min_length=64, max_length=64)
    record_index: int = Field(..., ge=0, lt=500)
    analyst_confirmed: bool


class RedTeamProposeRequest(BaseModel):
    session_id: str = Field(default="default", min_length=1, max_length=64)
    strategy: Literal["ucb1", "random"] = "ucb1"
    seed: int = Field(default=42, ge=0, le=1_000_000)


class RedTeamFeedbackRequest(BaseModel):
    session_id: str = Field(default="default", min_length=1, max_length=64)
    proposal_id: int = Field(..., ge=1)
    blue_flagged: bool
    confirm: bool


class RedTeamResetRequest(BaseModel):
    session_id: str = Field(default="default", min_length=1, max_length=64)


class RedTeamSyntheticBenchmarkRequest(BaseModel):
    rounds: int = Field(default=120, ge=3, le=500)
    trials: int = Field(default=12, ge=2, le=40)
    seed: int = Field(default=42, ge=0, le=1_000_000)


class PrivateCasesListRequest(BaseModel):
    db_path: str = Field(..., min_length=1, max_length=512)


class PrivateCaseDetailRequest(BaseModel):
    db_path: str = Field(..., min_length=1, max_length=512)
    case_id: int = Field(..., ge=1)


class ApiErrorResponse(BaseModel):
    detail: str
    code: str = "bad_request"
    meta: dict[str, Any] | None = None
