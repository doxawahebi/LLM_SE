"""Run ORM model."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def _new_id() -> str:
    return str(uuid.uuid4())


class Run(Base):
    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String, nullable=False)
    project_zip_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    build_command: Mapped[str | None] = mapped_column(String, nullable=True)
    codeql_build_mode: Mapped[str] = mapped_column(String, default="autodetect")

    # JSONB columns
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    counters: Mapped[dict] = mapped_column(JSONB, default=dict)
    phase1_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    status: Mapped[str] = mapped_column(String, default="created", index=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    specs: Mapped[list["Spec"]] = relationship(back_populates="run", lazy="noload")  # type: ignore[name-defined]
