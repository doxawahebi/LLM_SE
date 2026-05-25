"""Verdict schemas."""

from datetime import datetime

from pydantic import BaseModel


class VerdictSummary(BaseModel):
    verdict_id: str
    spec_id: str
    verdict: str
    cwe: str | None
    asan_type: str | None
    file: str | None
    line: int | None
    func: str | None
    dedup_key: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class VerdictDetail(VerdictSummary):
    inputs: list | None
    asan_report_ref: str | None
    replay_driver_ref: str | None
    verified_bug_json: dict | None

    class Config:
        from_attributes = True


class CompareResult(BaseModel):
    in_a_only: list[VerdictSummary]
    in_b_only: list[VerdictSummary]
    shared: list[VerdictSummary]
