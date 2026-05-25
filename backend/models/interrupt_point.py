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
    phase: Mapped[int] = mapped_column(Integer, nullable=False)
    turn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String, default="waiting")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    resumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    modified_files: Mapped[list] = mapped_column(JSONB, default=list)
    option_overrides: Mapped[dict] = mapped_column(JSONB, default=dict)
