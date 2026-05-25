"""SSE event message schemas."""

from datetime import datetime

from pydantic import BaseModel


class EventMessage(BaseModel):
    topic: str
    sequence: int
    timestamp: datetime
    kind: str  # state_change|counter_diff|new_turn|log_line|worker_heartbeat|resync_required
    payload: dict


class BatchedEventMessage(BaseModel):
    topic: str
    sequence: int
    batch: list[EventMessage]
