"""Turn schemas."""

from datetime import datetime

from pydantic import BaseModel


class TurnSummary(BaseModel):
    turn_id: str
    spec_id: str
    turn_number: int
    kind: str
    summary: str | None
    tokens_consumed: int | None
    klee_seconds: int | None
    duration_ms: int | None
    started_at: datetime
    ended_at: datetime | None

    class Config:
        from_attributes = True


class TurnDetail(TurnSummary):
    payload_ref: str | None

    class Config:
        from_attributes = True
