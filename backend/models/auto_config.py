"""AutoConfig ORM model — per-run Auto/Manual settings."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from database import Base

# Default auto-config: all functions enabled (auto=true)
DEFAULT_AUTO_CONFIG: dict = {
    "phase1.db_build": True,
    "phase1.query_execution": True,
    "phase1.sarif_parsing": True,
    "phase1.fact_enrichment": True,
    "phase1.spec_generation": True,
    "phase2.source_exploration": True,
    "phase2.spec_selection": True,
    "phase2.driver_synthesis": True,
    "phase2.stub_synthesis": True,
    "phase2.compile_diagnose": True,
    "phase2.klee_execution": True,
    "phase2.harness_refinement": True,
    "phase3.replay_driver_gen": True,
    "phase3.asan_compilation": True,
    "phase3.result_classification": True,
}


class AutoConfig(Base):
    __tablename__ = "auto_config"

    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.run_id"), primary_key=True)
    config: Mapped[dict] = mapped_column(JSONB, default=lambda: dict(DEFAULT_AUTO_CONFIG))
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
