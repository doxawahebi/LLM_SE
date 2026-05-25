"""Verdict ORM model."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.sql import func as sa_func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def _new_id() -> str:
    return str(uuid.uuid4())


class Verdict(Base):
    __tablename__ = "verdicts"
    __table_args__ = (Index("ix_verdicts_dedup_key", "dedup_key"),)

    verdict_id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    spec_id: Mapped[str] = mapped_column(ForeignKey("specs.spec_id"), nullable=False)
    verdict: Mapped[str] = mapped_column(String, nullable=False)  # confirmed | rejected
    cwe: Mapped[str | None] = mapped_column(String, nullable=True)
    asan_type: Mapped[str | None] = mapped_column(String, nullable=True)
    file: Mapped[str | None] = mapped_column(String, nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    func: Mapped[str | None] = mapped_column(String, nullable=True)
    inputs: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    asan_report_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    replay_driver_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    verified_bug_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    dedup_key: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=sa_func.now())

    spec: Mapped["Spec"] = relationship(back_populates="verdicts")  # type: ignore[name-defined]
