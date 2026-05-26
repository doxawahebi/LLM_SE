"""AutoConfig ORM model — per-run Auto/Manual settings."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from database import Base

# Valid PipelineFunctionId values — flat snake_case, NO DOTS.
# Must match shared/contracts/sailor_models.py PipelineFunctionId enum exactly.
VALID_FUNCTION_IDS: frozenset[str] = frozenset([
    "phase1_db_build",
    "phase1_query_execution",
    "phase1_sarif_parsing",
    "phase1_fact_enrichment",
    "phase1_spec_generation",
    "phase2_spec_selection",
    "phase2_source_exploration",
    "phase2_driver_synthesis",
    "phase2_stub_synthesis",
    "phase2_compile_diagnose",
    "phase2_klee_execution",
    "phase3_replay_driver_generation",
    "phase3_asan_compilation",
    "phase3_result_classification",
])


class AutoConfig(Base):
    __tablename__ = "auto_config"

    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.run_id"), primary_key=True)
    # Stores only explicit overrides (flat snake_case keys). Missing key = auto=true.
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
