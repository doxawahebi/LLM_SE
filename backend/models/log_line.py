"""LogLine ORM model."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


def _new_id() -> str:
    return str(uuid.uuid4())


class LogLine(Base):
    __tablename__ = "log_lines"
    __table_args__ = (Index("ix_log_lines_run_created", "run_id", "created_at"),)

    log_id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    run_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    spec_id: Mapped[str | None] = mapped_column(String, nullable=True)
    worker_id: Mapped[str | None] = mapped_column(String, nullable=True)
    level: Mapped[str] = mapped_column(String, nullable=False)  # error|warn|info|debug
    source: Mapped[str] = mapped_column(String, nullable=False)
    message: Mapped[str] = mapped_column(String, nullable=False)
    fields: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class ExportJob(Base):
    """Tracks async tarball export jobs."""

    __tablename__ = "export_jobs"

    job_id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    spec_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    export_type: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, default="pending")
    artifact_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IdempotencyKey(Base):
    """Caches POST responses for idempotent re-delivery."""

    __tablename__ = "idempotency_keys"

    key_id: Mapped[str] = mapped_column(String, primary_key=True)  # user_id:endpoint:key
    response_body: Mapped[str] = mapped_column(String, nullable=False)
    status_code: Mapped[int] = mapped_column(default=200)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
