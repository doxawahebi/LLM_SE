"""Sailor — automated vulnerability discovery pipeline (SA + LLM + SE).

Public API::

    from sailor import (
        Phase1Config, Phase1Pipeline,
        Phase2Config, Phase2Pipeline,
        Phase3Config, Phase3Pipeline,
    )
    from sailor.models import VulnerabilitySpec, Phase1Result
"""

from sailor.phase1.pipeline import Phase1Config, Phase1Pipeline
from sailor.phase2.pipeline import Phase2Pipeline
from sailor.phase2.llm_orchestrator import Phase2Config
from sailor.phase3.pipeline import Phase3Config, Phase3Pipeline

__all__ = [
    "Phase1Config",
    "Phase1Pipeline",
    "Phase2Config",
    "Phase2Pipeline",
    "Phase3Config",
    "Phase3Pipeline",
]
