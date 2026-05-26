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
from enum import Enum
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

#: Override table for custom queries whose rule_id contains no CWE number.
_RULE_CWE_OVERRIDE: dict[str, str] = {
    # tcpdump: unguarded EXTRACT_*BITS → out-of-bounds read
    "cpp/bootp-missing-ndtcheck": "CWE-125",
}


def _extract_cwe(rule_id: str) -> str:
    """Return the canonical CWE string (e.g. ``'CWE-120'``) from *rule_id*.

    Args:
        rule_id: Raw CodeQL rule identifier such as ``'cpp/cwe-120/buffer-overflow'``.

    Returns:
        Normalised string of the form ``'CWE-<number>'``, or ``'CWE-UNKNOWN'``
        when no CWE number can be extracted.
    """
    if rule_id in _RULE_CWE_OVERRIDE:
        return _RULE_CWE_OVERRIDE[rule_id]
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


# ---------------------------------------------------------------------------
# Phase 2 enums and models
# ---------------------------------------------------------------------------


class SEOutcome(str, Enum):
    """Terminal outcome of one Phase 2 symbolic-execution run."""

    BUG_TRIGGERED = "bug_triggered"
    SITE_REACHED = "site_reached"
    NOT_REACHED = "not_reached"
    INCONCLUSIVE = "inconclusive"
    LIKELY_FP = "likely_false_positive"


class CompileErrorClass(str, Enum):
    """Classification of a clang compilation error."""

    INCOMPLETE_TYPE = "incomplete_type"
    CONFLICTING_PROTO = "conflicting_prototype"
    REDEFINITION = "redefinition"
    OTHER = "other"


class CompileDiagnostic(BaseModel):
    """Structured compilation error produced by CompileDiagnoser.

    Attributes:
        error_class: Coarse-grained error category.
        raw_error: Full compiler stderr text.
        suggested_fix: Orchestrator-augmented fix hint derived from error_class.
        relevant_source: Grepped prototype or header snippet (when available).
    """

    error_class: CompileErrorClass
    raw_error: str
    suggested_fix: str
    relevant_source: str | None = None


class SEDiagnostic(BaseModel):
    """Structured KLEE output produced by SEDiagnoser.

    Attributes:
        outcome: Classified outcome of the KLEE run.
        functions_entered: Functions where SPINE_PROBE fired.
        functions_missed: Call-chain functions where probe did not fire.
        ktest_paths: .ktest file paths (populated on BUG_TRIGGERED).
        raw_output: Full KLEE stdout + stderr.
    """

    outcome: SEOutcome
    functions_entered: list[str] = Field(default_factory=list)
    functions_missed: list[str] = Field(default_factory=list)
    ktest_paths: list[str] = Field(default_factory=list)
    raw_output: str = ""


class SymbolicInputKind(str, Enum):
    """How a struct field should be initialised in the KLEE driver."""

    SYMBOLIC_SCALAR = "symbolic_scalar"
    CONCRETE_POINTER = "concrete_pointer"
    SYMBOLIC_BUFFER = "symbolic_buffer"


class FieldClassification(BaseModel):
    """Classification of one struct field for driver synthesis.

    Attributes:
        field_name: C field name.
        field_type: C type string.
        kind: How the field should be made symbolic.
        reason: Rationale for this classification.
    """

    field_name: str
    field_type: str
    kind: SymbolicInputKind
    reason: str


class GuardCondition(BaseModel):
    """An early-exit guard that must be negated in the driver.

    Attributes:
        condition: Original guard expression, e.g. ``"plt_eh_frame == NULL"``.
        assume_stmt: klee_assume counterpart, e.g. ``"klee_assume(plt_eh_frame != NULL)"``.
        location: ``file:line`` where the guard appears.
    """

    condition: str
    assume_stmt: str
    location: str


class HarnessArtifacts(BaseModel):
    """All artefacts produced during harness synthesis.

    Attributes:
        driver_c: Full C source of the driver (contains ``main()``).
        slice_c: Full C source of the code slice and stubs.
        compile_cmd: clang command used to produce driver.bc / slice.bc.
        link_cmd: llvm-link command used to produce harness.bc.
        bitcode_path: Absolute path to the linked harness.bc (None until compiled).
    """

    driver_c: str
    slice_c: str
    compile_cmd: str
    link_cmd: str
    bitcode_path: str | None = None


class WitnessInput(BaseModel):
    """Concrete witness produced when a bug is triggered.

    Attributes:
        spec_id: ``finding_id`` from the originating :class:`VulnerabilitySpec`.
        ktest_paths: .ktest files produced by KLEE.
        outcome: Must be BUG_TRIGGERED for a true witness.
        harness: All harness artefacts used to produce this witness.
        turns_used: Number of LLM turns consumed.
        refine_count: Number of refinement iterations performed.
    """

    spec_id: str
    ktest_paths: list[str] = Field(default_factory=list)
    outcome: SEOutcome
    harness: HarnessArtifacts
    turns_used: int = Field(..., ge=0)
    refine_count: int = Field(..., ge=0)


class Phase2Result(BaseModel):
    """Per-specification result from Phase 2.

    Attributes:
        spec_id: ``finding_id`` of the originating :class:`VulnerabilitySpec`.
        outcome: Terminal outcome for this spec.
        witness: Populated only when outcome is BUG_TRIGGERED.
        turns_used: LLM turns consumed.
        timestamp: ISO 8601 UTC timestamp.
    """

    spec_id: str
    outcome: SEOutcome
    witness: WitnessInput | None = None
    turns_used: int = Field(..., ge=0)
    timestamp: str


# ---------------------------------------------------------------------------
# Phase 3 enums and models
# ---------------------------------------------------------------------------


class ValidationVerdict(str, Enum):
    """Terminal verdict for one Phase 3 concrete validation run."""

    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ERROR = "ERROR"


class ASanViolationType(str, Enum):
    """AddressSanitizer violation category."""

    HEAP_BUFFER_OVERFLOW = "heap-buffer-overflow"
    STACK_BUFFER_OVERFLOW = "stack-buffer-overflow"
    USE_AFTER_FREE = "heap-use-after-free"
    NULL_DEREFERENCE = "null-dereference"
    UNKNOWN = "unknown"


class ASanReport(BaseModel):
    """Parsed ASan crash report.

    Attributes:
        violation_type: Coarse error category.
        file: Source file where the violation occurred.
        line: Line number of the violation.
        func: Function name at the violation site.
        stack_trace: Full ASan stack trace text.
        is_in_project_source: True if ``file`` is inside the project root.
    """

    violation_type: ASanViolationType
    file: str
    line: int
    func: str
    stack_trace: str
    is_in_project_source: bool


class WitnessValue(BaseModel):
    """One symbolic variable's concrete witness value from a .ktest file.

    Attributes:
        name: Symbolic variable name, e.g. ``'copy_size'``.
        size_bytes: Width of the variable in bytes.
        data_hex: Hex representation of the witness bytes.
        data_interpreted: Human-readable integer (little-endian, ≤8 bytes)
            or hex string (>8 bytes).
    """

    name: str
    size_bytes: int
    data_hex: str
    data_interpreted: int | str


class ValidationResult(BaseModel):
    """Result of one Phase 3 concrete validation run.

    Attributes:
        spec_id: ``finding_id`` from the originating :class:`VulnerabilitySpec`.
        verdict: CONFIRMED, FALSE_POSITIVE, or ERROR.
        cwe: CWE string (may be refined from Phase 1 by Phase 3 ASan evidence).
        file: Source file of the violation (from ASanReport if CONFIRMED).
        line: Line number of the violation.
        func: Function name at the violation site.
        asan_type: ASan violation category (None on FALSE_POSITIVE/ERROR).
        asan_report: Parsed ASan report (None on FALSE_POSITIVE/ERROR).
        inputs: Concrete witness values from the .ktest file.
        replay_driver_path: Path to the generated replay_driver.c.
        asan_report_path: Path to the asan_output.txt file.
        verdict_path: Path to verified_bug.json (empty string if not CONFIRMED).
        timestamp: ISO 8601 UTC timestamp.
    """

    spec_id: str
    verdict: ValidationVerdict
    cwe: str
    file: str
    line: int
    func: str
    asan_type: ASanViolationType | None = None
    asan_report: ASanReport | None = None
    inputs: list[WitnessValue] = Field(default_factory=list)
    replay_driver_path: str = ""
    asan_report_path: str = ""
    verdict_path: str = ""
    timestamp: str


class Phase3Result(BaseModel):
    """Aggregate output of a complete Phase 3 validation run.

    Attributes:
        total_processed: Number of BUG_TRIGGERED specs processed.
        confirmed: Number of CONFIRMED validations.
        false_positives: Number of FALSE_POSITIVE validations.
        errors: Number of ERROR outcomes.
        results: All individual :class:`ValidationResult` objects.
        timestamp: ISO 8601 UTC timestamp.
    """

    total_processed: int
    confirmed: int
    false_positives: int
    errors: int
    results: list[ValidationResult] = Field(default_factory=list)
    timestamp: str


# ---------------------------------------------------------------------------
# Evaluation framework models
# ---------------------------------------------------------------------------


class BuildSystem(str, Enum):
    """Build system used by a CVE's project."""

    AUTOTOOLS = "autotools"
    CMAKE = "cmake"
    MAKE = "make"
    CUSTOM = "custom"


class CVERecord(BaseModel):
    """A single CVE entry in the evaluation dataset.

    Attributes:
        cve_id: CVE identifier, e.g. ``'CVE-2024-12345'``.
        cwe: CWE class, e.g. ``'CWE-122'``.
        description: Human-readable vulnerability description.
        project: Short project name, e.g. ``'binutils'``.
        project_url: Git clone URL.
        vulnerable_commit: Commit hash that introduced the bug.
        fixed_commit: Commit hash after the patch (may be empty string).
        vulnerable_file: Relative path to the affected source file.
        vulnerable_line: Ground-truth 1-based line number.
        vulnerable_func: Ground-truth function name.
        expected_asan_type: Expected ASan violation string, e.g. ``'heap-buffer-overflow'``.
        build_system: Build system used by the project.
        build_commands: Ordered list of shell commands to build the project.
        dependencies: APT package names required to build.
        docker_image: Docker base image, e.g. ``'ubuntu:22.04'``.
        env_vars: Build-time environment variables.
        extra_cflags: Extra compiler flags, e.g. ``'-O1 -g'``.
    """

    cve_id: str
    cwe: str
    description: str
    project: str
    project_url: str
    vulnerable_commit: str
    fixed_commit: str
    vulnerable_file: str
    vulnerable_line: int
    vulnerable_func: str
    expected_asan_type: str
    build_system: BuildSystem
    build_commands: list[str]
    dependencies: list[str]
    docker_image: str
    env_vars: dict[str, str]
    extra_cflags: str = ""


class PhaseStatus(str, Enum):
    """Lifecycle status of a pipeline phase within one evaluation run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class EvaluationVerdict(str, Enum):
    """Final verdict for one CVE evaluation run."""

    TRUE_POSITIVE = "true_positive"
    FALSE_NEGATIVE = "false_negative"
    FALSE_POSITIVE = "false_positive"
    PARTIAL = "partial"


class FailureReason(str, Enum):
    """Classified root cause of a failed evaluation."""

    # Phase 1 failures
    QUERY_MISSED = "query_missed"
    FILTERED_OUT = "filtered_out"
    BUILD_FAILED = "build_failed"
    STRUCTURAL_MISS = "structural_miss"
    # Phase 2 failures
    INCONCLUSIVE = "inconclusive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    HARNESS_COMPILE_ERROR = "harness_compile_error"
    SE_NOT_REACHED = "se_not_reached"
    # Phase 3 failures
    ASAN_NOT_CONFIRMED = "asan_not_confirmed"
    ASAN_WRONG_LOCATION = "asan_wrong_location"
    # Infrastructure failures
    DOCKER_ERROR = "docker_error"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class CVEEvaluationResult(BaseModel):
    """Full result of one evaluation run for a single CVE.

    Attributes:
        eval_id: UUID generated at run time.
        cve_id: The CVE being evaluated.
        run_number: 1-based run index (for repeated runs).
        phase1_status: Lifecycle status of Phase 1.
        phase2_status: Lifecycle status of Phase 2.
        phase3_status: Lifecycle status of Phase 3.
        phase1_result: Phase 1 aggregate result (None until completed).
        phase2_result: List of Phase 2 per-spec results (None until completed).
        phase3_result: Phase 3 aggregate result (None until completed).
        phase1_detected: True if Phase 1 found a spec at the ground-truth location.
        phase2_triggered: True if Phase 2 triggered a bug at the correct spec.
        phase3_confirmed: True if Phase 3 confirmed the bug via ASan.
        verdict: Final evaluation verdict.
        failure_reason: Classified failure cause (None on TRUE_POSITIVE).
        failure_detail: Free-form additional detail.
        phase1_duration_sec: Wall-clock seconds for Phase 1.
        phase2_duration_sec: Wall-clock seconds for Phase 2.
        phase3_duration_sec: Wall-clock seconds for Phase 3.
        phase2_turns_used: Total LLM turns consumed in Phase 2.
        total_duration_sec: Total wall-clock seconds for the run.
        llm_calls: Total LLM API calls made.
        estimated_tokens_used: Estimated total tokens consumed.
        estimated_cost_usd: Estimated USD cost of the run.
        timestamp_start: ISO 8601 UTC start time.
        timestamp_end: ISO 8601 UTC end time.
    """

    eval_id: str
    cve_id: str
    run_number: int

    phase1_status: PhaseStatus = PhaseStatus.PENDING
    phase2_status: PhaseStatus = PhaseStatus.PENDING
    phase3_status: PhaseStatus = PhaseStatus.PENDING

    phase1_result: Phase1Result | None = None
    phase2_result: list[Phase2Result] | None = None
    phase3_result: Phase3Result | None = None

    phase1_detected: bool = False
    phase2_triggered: bool = False
    phase3_confirmed: bool = False

    verdict: EvaluationVerdict | None = None
    failure_reason: FailureReason | None = None
    failure_detail: str = ""

    phase1_duration_sec: float = 0.0
    phase2_duration_sec: float = 0.0
    phase3_duration_sec: float = 0.0
    phase2_turns_used: int = 0
    total_duration_sec: float = 0.0

    llm_calls: int = 0
    estimated_tokens_used: int = 0
    estimated_cost_usd: float = 0.0

    timestamp_start: str = ""
    timestamp_end: str = ""
