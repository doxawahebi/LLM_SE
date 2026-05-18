"""Pydantic v2 models for every data structure used in the SE-LLM pipeline.

All models use strict validation by default and are fully serialisable to/from
JSON via `model.model_dump()` / `Model.model_validate()`.

Typical import:
    from models.schemas import (
        BuildContext, FactPack, Location, Phase1Result,
        SARIFFinding, TraceStep, VulnerabilitySpec,
    )
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Low-level primitives
# ---------------------------------------------------------------------------


class Location(BaseModel):
    """Source-code location of a finding or trace event.

    Attributes:
        file: Relative or absolute path to the source file.
        line: 1-based line number.
        col_start: 1-based column where the token begins (inclusive).
        col_end: 1-based column where the token ends (inclusive).
    """

    model_config = ConfigDict(frozen=True)

    file: str = Field(..., min_length=1, description="Source file path.")
    line: int = Field(..., ge=1, description="1-based line number.")
    col_start: int = Field(..., ge=1, description="Inclusive start column (1-based).")
    col_end: int = Field(..., ge=1, description="Inclusive end column (1-based).")

    @model_validator(mode="after")
    def _col_end_ge_col_start(self) -> "Location":
        """Validate that col_end is at least col_start."""
        if self.col_end < self.col_start:
            raise ValueError(
                f"col_end ({self.col_end}) must be >= col_start ({self.col_start})"
            )
        return self


class TraceStep(BaseModel):
    """One step in a CodeQL data-flow trace.

    Attributes:
        file: Source file path for this step.
        line: 1-based line number.
        col: 1-based column number.
        label: Semantic role of this step in the taint flow.
    """

    model_config = ConfigDict(frozen=True)

    file: str = Field(..., min_length=1, description="Source file path.")
    line: int = Field(..., ge=1, description="1-based line number.")
    col: int = Field(..., ge=1, description="1-based column number.")
    label: Literal["source", "step", "sink"] = Field(
        ..., description="Taint-flow role of this step."
    )


# ---------------------------------------------------------------------------
# SARIF layer
# ---------------------------------------------------------------------------

#: Pattern used to normalise CWE identifiers from various rule_id formats.
#: Matches strings like "cpp/cwe-120/buffer-overflow", "CWE-79", etc.
_CWE_PATTERN: re.Pattern[str] = re.compile(r"(?i)cwe[-_](\d+)")


def _extract_cwe(rule_id: str) -> str:
    """Return the canonical CWE string (e.g. ``'CWE-120'``) from *rule_id*.

    Args:
        rule_id: Raw CodeQL rule identifier such as ``'cpp/cwe-120/buffer-overflow'``.

    Returns:
        Normalised string of the form ``'CWE-<number>'``, or ``'CWE-UNKNOWN'``
        when no CWE number can be extracted.
    """
    match = _CWE_PATTERN.search(rule_id)
    return f"CWE-{match.group(1)}" if match else "CWE-UNKNOWN"


class SARIFFinding(BaseModel):
    """Parsed representation of one SARIF result entry.

    The *finding_id* acts as a stable, human-readable primary key that uniquely
    identifies a result across pipeline runs.

    Attributes:
        finding_id: Composite key ``"<rule_id>:<file>:<line>:<col>"``.
        rule_id: Raw CodeQL rule identifier (e.g. ``'cpp/cwe-120/buffer-overflow'``).
        cwe: Normalised CWE string extracted from *rule_id* (e.g. ``'CWE-120'``).
        location: Primary code location of the finding.
        description: Human-readable message from the SARIF result.
        trace: Ordered list of taint-flow steps from source to sink.
        snippet: Raw source line at the finding location, truncated to 120 chars.
    """

    finding_id: str = Field(
        ...,
        min_length=1,
        description='Composite key "<rule_id>:<file>:<line>:<col>".',
    )
    rule_id: str = Field(..., min_length=1, description="CodeQL rule identifier.")
    cwe: str = Field(..., description="Normalised CWE string, e.g. 'CWE-120'.")
    location: Location
    description: str = Field(..., min_length=1)
    trace: list[TraceStep] = Field(default_factory=list)
    snippet: str = Field(
        ...,
        max_length=120,
        description="Source line at the finding location, max 120 characters.",
    )

    @field_validator("cwe")
    @classmethod
    def _validate_cwe_format(cls, v: str) -> str:
        """Validate that CWE is in the canonical ``'CWE-<number>'`` format."""
        if not re.fullmatch(r"CWE-(\d+|UNKNOWN)", v, re.IGNORECASE):
            raise ValueError(
                f"Invalid CWE format '{v}'. Expected 'CWE-<number>' or 'CWE-UNKNOWN'."
            )
        return v.upper()

    @model_validator(mode="before")
    @classmethod
    def _auto_derive_cwe(cls, data: dict) -> dict:
        """Derive *cwe* from *rule_id* when it is not explicitly supplied."""
        if isinstance(data, dict) and "cwe" not in data and "rule_id" in data:
            data["cwe"] = _extract_cwe(data["rule_id"])
        return data

    @model_validator(mode="before")
    @classmethod
    def _auto_derive_finding_id(cls, data: dict) -> dict:
        """Derive *finding_id* from its components when not explicitly supplied."""
        if isinstance(data, dict) and "finding_id" not in data:
            loc = data.get("location", {})
            if isinstance(loc, dict):
                file_ = loc.get("file", "")
                line_ = loc.get("line", 0)
                col_ = loc.get("col_start", 0)
            elif isinstance(loc, Location):
                file_, line_, col_ = loc.file, loc.line, loc.col_start
            else:
                file_, line_, col_ = "", 0, 0
            rule_id = data.get("rule_id", "")
            data["finding_id"] = f"{rule_id}:{file_}:{line_}:{col_}"
        return data

    @field_validator("snippet")
    @classmethod
    def _truncate_snippet(cls, v: str) -> str:
        """Silently truncate snippet to 120 characters."""
        return v[:120]


# ---------------------------------------------------------------------------
# Build context
# ---------------------------------------------------------------------------


class BuildContext(BaseModel):
    """Compiler flags extracted from a build system or compile_commands.json.

    Attributes:
        include_paths: List of ``-I<path>`` include directory flags.
        defines: List of ``-D<MACRO>`` preprocessor definition flags.
    """

    include_paths: list[str] = Field(
        default_factory=list,
        description="Compiler include paths (-I flags).",
    )
    defines: list[str] = Field(
        default_factory=list,
        description="Preprocessor macro definitions (-D flags).",
    )

    @field_validator("include_paths", "defines", mode="before")
    @classmethod
    def _deduplicate(cls, v: list[str]) -> list[str]:
        """Remove duplicate entries while preserving order."""
        seen: set[str] = set()
        unique: list[str] = []
        for item in v:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique


# ---------------------------------------------------------------------------
# Enriched fact pack
# ---------------------------------------------------------------------------


class FactPack(BaseModel):
    """Enriched data bundle produced by FactGenerator + FactEnricher.

    One ``FactPack`` is created for each ``SARIFFinding`` that passes the
    initial filter and survives the enrichment stage.

    Attributes:
        finding: The original, validated SARIF finding.
        suspect_calls: Names of potentially dangerous library/API calls
            discovered in the surrounding code slice.
        pointer_vars: Names of pointer-typed variables visible at the
            finding location.
        length_vars: Names of variables that appear to carry size/length
            semantics (e.g. ``n``, ``len``, ``size``, ``count``).
        bounds_hints: Free-form textual hints about buffer sizes or bounds
            constraints detected in the code.
        build_context: Compiler flags relevant to the translation unit that
            contains the finding.
    """

    finding: SARIFFinding
    suspect_calls: list[str] = Field(
        default_factory=list,
        description="Dangerous API call names near the finding.",
    )
    pointer_vars: list[str] = Field(
        default_factory=list,
        description="Pointer-typed variable names at the finding location.",
    )
    length_vars: list[str] = Field(
        default_factory=list,
        description="Variables carrying size/length semantics.",
    )
    bounds_hints: list[str] = Field(
        default_factory=list,
        description="Textual hints about buffer-size constraints.",
    )
    build_context: BuildContext = Field(
        default_factory=BuildContext,
        description="Compiler flags for the finding's translation unit.",
    )


# ---------------------------------------------------------------------------
# Vulnerability specification (output of Phase 1)
# ---------------------------------------------------------------------------


class VulnerabilitySpec(BaseModel):
    """Fully self-contained vulnerability specification passed to Phase 2.

    This model is the primary output of the Phase 1 pipeline and is designed
    to give a downstream symbolic-execution or LLM phase everything it needs
    without needing to re-read SARIF or source files.

    Attributes:
        rule_id: CodeQL rule identifier.
        cwe: Normalised CWE string.
        file: Path to the affected source file.
        line: 1-based line number of the primary finding.
        col: 1-based column of the primary finding.
        message: Human-readable vulnerability description.
        snippet: Source line at the finding location (max 120 chars).
        trace: Ordered taint-flow trace steps.
        suspect_calls: Dangerous API call names near the finding.
        pointer_vars: Pointer-typed variable names at the finding location.
        length_vars: Variables with size/length semantics.
        bounds_hints: Textual hints about buffer-size constraints.
        build_context: Compiler flags for the translation unit.
        entrypoint: Name of the function containing the finding, or the
            sentinel ``'LLM_INFER'`` when the name cannot be determined
            statically.
        assertion_template: A pre-filled KLEE/ASan assertion string that
            the downstream phase should use as a starting point.
    """

    rule_id: str = Field(..., min_length=1)
    cwe: str = Field(..., description="Normalised CWE string.")
    file: str = Field(..., min_length=1)
    line: int = Field(..., ge=1)
    col: int = Field(..., ge=1)
    message: str = Field(..., min_length=1)
    snippet: str = Field(..., max_length=120)
    trace: list[TraceStep] = Field(default_factory=list)
    suspect_calls: list[str] = Field(default_factory=list)
    pointer_vars: list[str] = Field(default_factory=list)
    length_vars: list[str] = Field(default_factory=list)
    bounds_hints: list[str] = Field(default_factory=list)
    build_context: BuildContext = Field(default_factory=BuildContext)
    entrypoint: str = Field(
        ...,
        min_length=1,
        description="Function name or 'LLM_INFER' if statically unknown.",
    )
    assertion_template: str = Field(
        ...,
        min_length=1,
        description="Pre-filled assertion/harness template string.",
    )

    @field_validator("snippet")
    @classmethod
    def _truncate_snippet(cls, v: str) -> str:
        """Silently truncate snippet to 120 characters."""
        return v[:120]

    @field_validator("entrypoint")
    @classmethod
    def _validate_entrypoint(cls, v: str) -> str:
        """Accept any non-empty string; 'LLM_INFER' is the sentinel value."""
        if not v.strip():
            raise ValueError("entrypoint must not be blank.")
        return v

    @classmethod
    def from_fact_pack(
        cls,
        pack: FactPack,
        entrypoint: str,
        assertion_template: str,
    ) -> "VulnerabilitySpec":
        """Construct a :class:`VulnerabilitySpec` from a :class:`FactPack`.

        Args:
            pack: The enriched fact pack to promote to a specification.
            entrypoint: Function name containing the finding, or ``'LLM_INFER'``.
            assertion_template: Pre-filled assertion/harness template string.

        Returns:
            A fully populated :class:`VulnerabilitySpec`.
        """
        f = pack.finding
        return cls(
            rule_id=f.rule_id,
            cwe=f.cwe,
            file=f.location.file,
            line=f.location.line,
            col=f.location.col_start,
            message=f.description,
            snippet=f.snippet,
            trace=list(f.trace),
            suspect_calls=list(pack.suspect_calls),
            pointer_vars=list(pack.pointer_vars),
            length_vars=list(pack.length_vars),
            bounds_hints=list(pack.bounds_hints),
            build_context=pack.build_context,
            entrypoint=entrypoint,
            assertion_template=assertion_template,
        )


# ---------------------------------------------------------------------------
# Phase 1 aggregate result
# ---------------------------------------------------------------------------


class Phase1Result(BaseModel):
    """Aggregate output of a complete Phase 1 pipeline run.

    Attributes:
        project: Short identifier for the analysed project (e.g. ``'libpng'``).
        project_root: Absolute path to the project's source root directory.
        total_findings: Number of raw SARIF findings before any filtering.
        after_filtering: Number of findings that survived all filters.
        reduction_rate: Fraction of findings discarded by filters
            ``(total_findings - after_filtering) / total_findings``.
            ``0.0`` when *total_findings* is zero.
        by_cwe: Mapping from CWE string to count of surviving specifications.
        specifications: Ordered list of :class:`VulnerabilitySpec` objects.
        timestamp: ISO 8601 UTC timestamp of when this result was produced.
    """

    project: str = Field(..., min_length=1)
    project_root: str = Field(..., min_length=1)
    total_findings: int = Field(..., ge=0)
    after_filtering: int = Field(..., ge=0)
    reduction_rate: float = Field(..., ge=0.0, le=1.0)
    by_cwe: dict[str, int] = Field(default_factory=dict)
    specifications: list[VulnerabilitySpec] = Field(default_factory=list)
    timestamp: str = Field(
        ...,
        min_length=1,
        description="ISO 8601 UTC timestamp, e.g. '2024-01-01T00:00:00Z'.",
    )

    @model_validator(mode="after")
    def _validate_counts(self) -> "Phase1Result":
        """Validate that after_filtering <= total_findings."""
        if self.after_filtering > self.total_findings:
            raise ValueError(
                f"after_filtering ({self.after_filtering}) cannot exceed "
                f"total_findings ({self.total_findings})."
            )
        if len(self.specifications) != self.after_filtering:
            raise ValueError(
                f"len(specifications) ({len(self.specifications)}) must equal "
                f"after_filtering ({self.after_filtering})."
            )
        return self

    @model_validator(mode="after")
    def _validate_reduction_rate(self) -> "Phase1Result":
        """Validate that reduction_rate is consistent with the counts."""
        if self.total_findings == 0:
            if self.reduction_rate != 0.0:
                raise ValueError(
                    "reduction_rate must be 0.0 when total_findings is 0."
                )
        else:
            expected = (self.total_findings - self.after_filtering) / self.total_findings
            if abs(self.reduction_rate - expected) > 1e-6:
                raise ValueError(
                    f"reduction_rate ({self.reduction_rate:.6f}) does not match "
                    f"computed value ({expected:.6f})."
                )
        return self

    @classmethod
    def build(
        cls,
        *,
        project: str,
        project_root: str,
        total_findings: int,
        specifications: list[VulnerabilitySpec],
        timestamp: str,
    ) -> "Phase1Result":
        """Factory that automatically computes derived fields.

        Prefer this constructor over the default ``__init__`` so that
        ``after_filtering``, ``reduction_rate``, and ``by_cwe`` are
        never computed by hand.

        Args:
            project: Short project identifier.
            project_root: Absolute path to the project source root.
            total_findings: Raw finding count before filtering.
            specifications: Surviving :class:`VulnerabilitySpec` objects.
            timestamp: ISO 8601 UTC timestamp string.

        Returns:
            A fully populated, validated :class:`Phase1Result`.
        """
        after = len(specifications)
        rate = 0.0 if total_findings == 0 else (total_findings - after) / total_findings
        by_cwe: dict[str, int] = {}
        for spec in specifications:
            by_cwe[spec.cwe] = by_cwe.get(spec.cwe, 0) + 1
        return cls(
            project=project,
            project_root=project_root,
            total_findings=total_findings,
            after_filtering=after,
            reduction_rate=round(rate, 6),
            by_cwe=by_cwe,
            specifications=specifications,
            timestamp=timestamp,
        )
