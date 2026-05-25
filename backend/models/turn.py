"""Turn ORM model — append-only audit log of Phase 2."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def _new_id() -> str:
    return str(uuid.uuid4())


class Turn(Base):
    __tablename__ = "turns"
    __table_args__ = (Index("ix_turns_spec_number", "spec_id", "turn_number"),)

    turn_id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    spec_id: Mapped[str] = mapped_column(ForeignKey("specs.spec_id"), nullable=False)
    turn_number: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)  # explore|author|compile_fail|klee_run|refinement|intervention|terminal
    summary: Mapped[str | None] = mapped_column(String, nullable=True)
    payload_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    tokens_consumed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    klee_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    started_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    spec: Mapped["Spec"] = relationship(back_populates="turns")  # type: ignore[name-defined]
