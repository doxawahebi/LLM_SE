"""Spec request/response schemas."""

from datetime import datetime

from pydantic import BaseModel


class SpecSummary(BaseModel):
    spec_id: str
    run_id: str
    rule_id: str | None
    file: str | None
    line: int | None
    message: str | None
    phase1_status: str
    phase2_status: str
    phase3_status: str
    current_turn: int
    turn_count_total: int
    phase2_outcome: str | None
    phase3_verdict: str | None
    intervention_pending: bool
    last_event_at: datetime | None

    class Config:
        from_attributes = True


class SpecDetail(SpecSummary):
    snippet: str | None
    entrypoint: str | None
    assertion_template: str | None
    trace: list | None
    suspect_calls: list | None
    pointer_vars: list | None
    length_vars: list | None
    bounds_hints: list | None
    build_context: dict | None
    refine_count: int
    phase2_error: str | None
    phase3_error: str | None
    worker_id: str | None
    artifacts_root: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class RequeueRequest(BaseModel):
    reset_turn: bool = False


class SkipRequest(BaseModel):
    reason: str


class BulkRequeueRequest(BaseModel):
    spec_ids: list[str]


class BulkSkipRequest(BaseModel):
    spec_ids: list[str]
    reason: str
