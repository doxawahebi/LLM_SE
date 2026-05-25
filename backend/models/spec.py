"""Spec ORM model."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def _new_id() -> str:
    return str(uuid.uuid4())


class Spec(Base):
    __tablename__ = "specs"
    __table_args__ = (
        Index("ix_specs_run_phase2", "run_id", "phase2_status"),
        Index("ix_specs_run_phase3", "run_id", "phase3_status"),
        Index("ix_specs_lease", "worker_id", "locked_until"),
    )

    spec_id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)

    # Phase 1 fields
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    file: Mapped[str | None] = mapped_column(String, nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message: Mapped[str | None] = mapped_column(String, nullable=True)
    snippet: Mapped[str | None] = mapped_column(String, nullable=True)
    entrypoint: Mapped[str | None] = mapped_column(String, nullable=True)
    assertion_template: Mapped[str | None] = mapped_column(String, nullable=True)

    # JSONB fields from Phase 1
    trace: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    suspect_calls: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    pointer_vars: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    length_vars: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    bounds_hints: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    build_context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    phase1_status: Mapped[str] = mapped_column(String, default="emitted")
    phase2_status: Mapped[str] = mapped_column(String, default="queued", index=True)
    phase3_status: Mapped[str] = mapped_column(String, default="not_eligible", index=True)

    current_turn: Mapped[int] = mapped_column(Integer, default=0)
    turn_count_total: Mapped[int] = mapped_column(Integer, default=0)
    refine_count: Mapped[int] = mapped_column(Integer, default=0)

    phase2_outcome: Mapped[str | None] = mapped_column(String, nullable=True)
    phase2_error: Mapped[str | None] = mapped_column(String, nullable=True)
    phase3_verdict: Mapped[str | None] = mapped_column(String, nullable=True)
    phase3_error: Mapped[str | None] = mapped_column(String, nullable=True)

    # Lease fields
    worker_id: Mapped[str | None] = mapped_column(String, nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    intervention_pending: Mapped[bool] = mapped_column(default=False)
    artifacts_root: Mapped[str | None] = mapped_column(String, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    run: Mapped["Run"] = relationship(back_populates="specs")  # type: ignore[name-defined]
    turns: Mapped[list["Turn"]] = relationship(back_populates="spec", lazy="noload")  # type: ignore[name-defined]
    verdicts: Mapped[list["Verdict"]] = relationship(back_populates="spec", lazy="noload")  # type: ignore[name-defined]
    interventions: Mapped[list["Intervention"]] = relationship(back_populates="spec", lazy="noload")  # type: ignore[name-defined]


class Intervention(Base):
    """Ordered list of pending intervention payloads per spec."""

    __tablename__ = "interventions"

    intervention_id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    spec_id: Mapped[str] = mapped_column(ForeignKey("specs.spec_id"), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    submitted_by: Mapped[str | None] = mapped_column(String, nullable=True)
    applied: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    spec: Mapped["Spec"] = relationship(back_populates="interventions")
