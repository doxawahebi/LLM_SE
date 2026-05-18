"""CodeQL CLI abstraction package for the SE-LLM-project pipeline."""

from .wrapper import CodeQLError, CodeQLRunner

__all__ = ["CodeQLError", "CodeQLRunner"]
