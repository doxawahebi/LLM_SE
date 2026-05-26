"""InterruptPoint ORM model."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


def _new_id() -> str:
    return str(uuid.uuid4())


class InterruptPoint(Base):
    __tablename__ = "interrupt_points"

    interrupt_id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.run_id"), nullable=False)
    spec_id: Mapped[str | None] = mapped_column(String, ForeignKey("specs.spec_id"), nullable=True)
    function_name: Mapped[str] = mapped_column(String, nullable=False)
    # phase column removed — derivable from function_name prefix (phase1_*, phase2_*, phase3_*)
    scope: Mapped[str] = mapped_column(String, nullable=False, default="spec")  # "run" | "spec"
    turn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String, default="waiting")  # "waiting" | "resumed" | "skipped"
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String, nullable=True)  # user_id
    input_files: Mapped[list] = mapped_column(JSONB, default=list)  # list[InterruptInputFile] dicts
    option_overrides: Mapped[dict] = mapped_column(JSONB, default=dict)  # per-function defaults at interrupt time
    # Backend-internal: what the user submitted on resume (not in shared contracts)
    resume_files: Mapped[list] = mapped_column(JSONB, default=list)  # [{name, artifact_ref}]
    resume_overrides: Mapped[dict] = mapped_column(JSONB, default=dict)
    # Track valid artifact_refs uploaded via /files endpoint
    uploaded_artifact_refs: Mapped[list] = mapped_column(JSONB, default=list)
