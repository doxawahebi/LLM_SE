"""Sailor — automated vulnerability discovery pipeline (SA + LLM + SE).

Public API::

    from sailor import Phase1Config, Phase1Pipeline
    from sailor.models import VulnerabilitySpec, Phase1Result
"""

from sailor.phase1.pipeline import Phase1Config, Phase1Pipeline

__all__ = ["Phase1Config", "Phase1Pipeline"]
