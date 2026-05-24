# CLAUDE_evaluation.md — Sailor Evaluation Framework

> Claude Code reads this file during Session 5 — Evaluation Implementation.
> This document is referenced by CLAUDE.md Section 5, Session 5.
> All Absolute Rules defined in CLAUDE.md apply in full.

---

## Overview

This framework evaluates Sailor's end-to-end performance against known CVEs.
All pipeline results are persisted to a SQLite database to avoid redundant
LLM calls when re-running or extending the evaluation.

```
Design Constraints:
  - Token budget: ~$20 (minimize LLM calls via DB checkpointing)
  - Initial scale: 1 CVE
  - Must be extensible to N CVEs without structural changes

Key Principle:
  Every Phase result is saved to DB immediately after completion.
  Re-running the same CVE resumes from the last completed Phase,
  never re-invoking the LLM for already-completed work.
```

---

## Integration with Earlier Phases

Import from existing sailor modules — do not redefine.

```python
from sailor.models.schemas import (
    VulnerabilitySpec, Phase1Result,       # Phase 1
    WitnessInput, Phase2Result, SEOutcome, # Phase 2
    ValidationResult, Phase3Result,        # Phase 3
    ValidationVerdict,
)
from sailor.phase1.pipeline import Phase1Pipeline, Phase1Config
from sailor.phase2.pipeline import Phase2Pipeline, Phase2Config
from sailor.phase3.pipeline import Phase3Pipeline, Phase3Config
```

---

## Module Structure

```
sailor/evaluation/
├── __init__.py
├── pipeline.py          # EvaluationPipeline — top-level orchestrator
├── dataset.py           # CVERecord + CVEDataset
├── environment.py       # DockerEnvironment — build isolation
├── db.py                # EvaluationDB — SQLite persistence layer
├── metrics.py           # MetricsCalculator
└── report.py            # ReportGenerator
```

---

## Data Models (add to `sailor/models/schemas.py`)

```python
from enum import Enum
from pydantic import BaseModel

# ── CVE Dataset ──────────────────────────────────────────────────

class BuildSystem(str, Enum):
    AUTOTOOLS = "autotools"
    CMAKE     = "cmake"
    MAKE      = "make"
    CUSTOM    = "custom"

class CVERecord(BaseModel):
    # Identity
    cve_id: str                    # "CVE-2025-11494"
    cwe: str                       # "CWE-122"
    description: str

    # Project
    project: str                   # "binutils"
    project_url: str               # git clone URL
    vulnerable_commit: str         # commit hash with the bug
    fixed_commit: str              # commit hash after patch

    # Ground Truth
    vulnerable_file: str           # "bfd/elfxx-x86.c"
    vulnerable_line: int           # 2699
    vulnerable_func: str           # "_bfd_x86_elf_late_size_sections"
    expected_asan_type: str        # "heap-buffer-overflow"

    # Build
    build_system: BuildSystem
    build_commands: list[str]      # ordered build commands
    dependencies: list[str]        # apt package names
    docker_image: str              # e.g. "ubuntu:22.04"
    env_vars: dict[str, str]       # build-time environment variables
    extra_cflags: str = ""         # e.g. "-O1 -g"

# ── Evaluation Results ────────────────────────────────────────────

class PhaseStatus(str, Enum):
    PENDING    = "pending"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    SKIPPED    = "skipped"    # e.g. Phase 2 skipped if Phase 1 found nothing

class EvaluationVerdict(str, Enum):
    TRUE_POSITIVE  = "true_positive"   # CONFIRMED at correct location
    FALSE_NEGATIVE = "false_negative"  # missed entirely
    FALSE_POSITIVE = "false_positive"  # CONFIRMED at wrong location
    PARTIAL        = "partial"         # Phase 1 found but Phase 2/3 failed

class FailureReason(str, Enum):
    # Phase 1 failures
    QUERY_MISSED          = "query_missed"           # no query matched
    FILTERED_OUT          = "filtered_out"           # skip pattern removed it
    BUILD_FAILED          = "build_failed"           # CodeQL DB build error
    STRUCTURAL_MISS       = "structural_miss"        # macro/fnptr obfuscation

    # Phase 2 failures
    INCONCLUSIVE          = "inconclusive"           # T_max exhausted
    LIKELY_FALSE_POSITIVE = "likely_false_positive"  # R_max exceeded
    HARNESS_COMPILE_ERROR = "harness_compile_error"  # never compiled
    SE_NOT_REACHED        = "se_not_reached"         # ℓ never reached

    # Phase 3 failures
    ASAN_NOT_CONFIRMED    = "asan_not_confirmed"     # ASan didn't crash
    ASAN_WRONG_LOCATION   = "asan_wrong_location"    # crash in wrong file/func

    # Infrastructure failures
    DOCKER_ERROR          = "docker_error"
    TIMEOUT               = "timeout"
    UNKNOWN               = "unknown"

class CVEEvaluationResult(BaseModel):
    # Identity
    eval_id: str                   # UUID, generated at run time
    cve_id: str
    run_number: int                # 1-based, for repeated runs

    # Phase statuses
    phase1_status: PhaseStatus = PhaseStatus.PENDING
    phase2_status: PhaseStatus = PhaseStatus.PENDING
    phase3_status: PhaseStatus = PhaseStatus.PENDING

    # Phase outputs (None until completed)
    phase1_result: Phase1Result | None = None
    phase2_result: list[Phase2Result] | None = None
    phase3_result: Phase3Result | None = None

    # Ground truth matching
    phase1_detected: bool = False  # spec found at correct location
    phase2_triggered: bool = False # bug_triggered at correct spec
    phase3_confirmed: bool = False # ASan CONFIRMED

    # Final verdict
    verdict: EvaluationVerdict | None = None
    failure_reason: FailureReason | None = None
    failure_detail: str = ""

    # Performance
    phase1_duration_sec: float = 0.0
    phase2_duration_sec: float = 0.0
    phase3_duration_sec: float = 0.0
    phase2_turns_used: int = 0
    total_duration_sec: float = 0.0

    # Token usage (for budget tracking)
    llm_calls: int = 0
    estimated_tokens_used: int = 0
    estimated_cost_usd: float = 0.0

    timestamp_start: str = ""
    timestamp_end: str = ""
```

---

## FILE 1: `sailor/evaluation/db.py`

Implement class `EvaluationDB`.

All pipeline results are persisted here immediately after each Phase.
This prevents redundant LLM calls on re-run.

```python
import sqlite3
import json
from pathlib import Path
from sailor.models.schemas import CVEEvaluationResult, PhaseStatus

class EvaluationDB:
    """
    SQLite-based persistence layer for evaluation results.

    Schema:
      evaluations (
        eval_id         TEXT PRIMARY KEY,
        cve_id          TEXT NOT NULL,
        run_number      INTEGER NOT NULL,
        phase1_status   TEXT NOT NULL,
        phase2_status   TEXT NOT NULL,
        phase3_status   TEXT NOT NULL,
        phase1_result   TEXT,    -- JSON
        phase2_result   TEXT,    -- JSON
        phase3_result   TEXT,    -- JSON
        phase1_detected INTEGER,
        phase2_triggered INTEGER,
        phase3_confirmed INTEGER,
        verdict         TEXT,
        failure_reason  TEXT,
        failure_detail  TEXT,
        phase1_duration_sec REAL,
        phase2_duration_sec REAL,
        phase3_duration_sec REAL,
        phase2_turns_used   INTEGER,
        total_duration_sec  REAL,
        llm_calls           INTEGER,
        estimated_tokens_used INTEGER,
        estimated_cost_usd  REAL,
        timestamp_start TEXT,
        timestamp_end   TEXT
      )

      cve_records (
        cve_id          TEXT PRIMARY KEY,
        record_json     TEXT NOT NULL    -- full CVERecord JSON
      )
    """

    def __init__(self, db_path: Path): ...

    def init_schema(self) -> None:
        """Create tables if they don't exist."""

    def upsert_cve_record(self, record: CVERecord) -> None:
        """Insert or update a CVERecord."""

    def get_cve_record(self, cve_id: str) -> CVERecord | None:
        """Retrieve a CVERecord by cve_id."""

    def create_evaluation(self, result: CVEEvaluationResult) -> None:
        """Insert a new evaluation row."""

    def update_phase_status(
        self,
        eval_id: str,
        phase: int,                     # 1, 2, or 3
        status: PhaseStatus,
        result_json: str | None = None,
    ) -> None:
        """
        Update phase status and result atomically.
        Called immediately after each Phase completes or fails.
        This is the checkpoint that prevents redundant LLM calls.
        """

    def update_verdict(
        self,
        eval_id: str,
        verdict: EvaluationVerdict,
        failure_reason: FailureReason | None,
        failure_detail: str,
    ) -> None:
        """Set final verdict after Phase 3."""

    def update_metrics(
        self,
        eval_id: str,
        phase1_duration: float,
        phase2_duration: float,
        phase3_duration: float,
        phase2_turns: int,
        llm_calls: int,
        estimated_tokens: int,
        estimated_cost: float,
    ) -> None:
        """Update performance and cost metrics."""

    def get_evaluation(self, eval_id: str) -> CVEEvaluationResult | None:
        """Retrieve a full evaluation result."""

    def get_latest_evaluation(
        self, cve_id: str
    ) -> CVEEvaluationResult | None:
        """
        Get the most recent evaluation for a cve_id.
        Used to resume interrupted runs.
        """

    def get_resumable_phase(
        self, cve_id: str
    ) -> tuple[str, int] | None:
        """
        Check if a previous run exists that can be resumed.

        Returns (eval_id, next_phase) if resumable:
          next_phase = 2 if phase1 completed but phase2 pending
          next_phase = 3 if phase2 completed but phase3 pending
        Returns None if no resumable run exists.

        This is the key method for token budget preservation.
        If Phase 1 completed in a previous run, Phase 1 is NEVER
        re-executed — Phase 2 resumes from the saved Phase1Result.
        """

    def list_evaluations(
        self,
        cve_id: str | None = None,
    ) -> list[CVEEvaluationResult]:
        """List all evaluations, optionally filtered by cve_id."""

    def get_summary_stats(self) -> dict:
        """
        Aggregate statistics across all evaluations.
        Returns dict with:
          total_cves, total_runs,
          true_positives, false_negatives, false_positives, partials,
          avg_phase2_turns, avg_cost_usd, total_cost_usd,
          failure_reason_counts: dict[str, int]
        """
```

---

## FILE 2: `sailor/evaluation/dataset.py`

Implement class `CVEDataset`.

Manages the collection of CVE records used for evaluation.
Designed to start with 1 CVE and scale to N.

```python
class CVEDataset:
    """
    CVE dataset manager.

    Backed by EvaluationDB for persistence.
    Supports loading from JSON file for easy extension.
    """

    def __init__(self, db: EvaluationDB): ...

    def load_from_file(self, path: Path) -> int:
        """
        Load CVERecord list from a JSON file.
        Upserts each record into the DB.
        Returns number of records loaded.

        JSON format:
        [
          {
            "cve_id": "CVE-2025-11494",
            "cwe": "CWE-122",
            "project": "binutils",
            "project_url": "https://github.com/bminor/binutils-gdb",
            "vulnerable_commit": "b2bc71a",
            "fixed_commit": "a1b2c3d",
            "vulnerable_file": "bfd/elfxx-x86.c",
            "vulnerable_line": 2699,
            "vulnerable_func": "_bfd_x86_elf_late_size_sections",
            "expected_asan_type": "heap-buffer-overflow",
            "build_system": "autotools",
            "build_commands": [
              "./configure --disable-ld",
              "bear -- make -j4 all-bfd"
            ],
            "dependencies": ["build-essential", "bear", "libz-dev"],
            "docker_image": "ubuntu:22.04",
            "env_vars": {},
            "extra_cflags": "-O1 -g"
          }
        ]
        """

    def get(self, cve_id: str) -> CVERecord | None:
        """Retrieve a single CVERecord."""

    def list_all(self) -> list[CVERecord]:
        """Return all CVERecords in the dataset."""

    def add(self, record: CVERecord) -> None:
        """Add a single CVERecord programmatically."""


# ── Initial 1-CVE dataset (Binutils from the paper) ──────────────

INITIAL_DATASET: list[dict] = [
    {
        "cve_id": "CVE-2025-11494",
        "cwe": "CWE-122",
        "description": (
            "Heap buffer overflow in _bfd_x86_elf_late_size_sections "
            "in elfxx-x86.c in binutils via unchecked memcpy size."
        ),
        "project": "binutils",
        "project_url": "https://github.com/bminor/binutils-gdb.git",
        "vulnerable_commit": "b2bc71a",
        "fixed_commit": "",           # fill after identifying patch
        "vulnerable_file": "bfd/elfxx-x86.c",
        "vulnerable_line": 2699,
        "vulnerable_func": "_bfd_x86_elf_late_size_sections",
        "expected_asan_type": "heap-buffer-overflow",
        "build_system": "autotools",
        "build_commands": [
            "autoreconf -fi",
            "./configure --disable-ld --disable-gdb --disable-sim",
            "bear -- make -j4 all-bfd"
        ],
        "dependencies": [
            "build-essential", "bear", "autoconf", "automake",
            "libz-dev", "libtool", "texinfo"
        ],
        "docker_image": "ubuntu:22.04",
        "env_vars": {"CC": "clang", "CXX": "clang++"},
        "extra_cflags": "-O1 -g"
    }
]

SECONDARY_DATASET: list[dict] = [
    {
        "cve_id": "CVE-2023-1972"
    }
]
```

---

## FILE 3: `sailor/evaluation/environment.py`

Implement class `DockerEnvironment`.

Provides isolated, reproducible build environments per CVE.
Each CVE runs in its own Docker container.

```python
class DockerEnvironment:
    """
    Docker-based build isolation for CVE evaluation.

    Responsibilities:
      - Pull base image
      - Install dependencies
      - Clone project at vulnerable commit
      - Run build commands to produce compile_commands.json
      - Make project source available to Sailor pipeline
    """

    def __init__(
        self,
        record: CVERecord,
        workspace: Path,    # host path for volume mount
    ): ...

    def setup(self) -> Path:
        """
        Full environment setup sequence:
          1. Pull docker image
          2. Install dependencies (apt-get)
          3. Clone repository
          4. Checkout vulnerable_commit
          5. Run build_commands to generate compile_commands.json
          6. Return project_root path (on host via volume mount)

        Raises: EnvironmentSetupError on any failure.
        Logs each step with timing.
        """

    def get_project_root(self) -> Path:
        """Return the path to the checked-out project source."""

    def get_compile_commands_path(self) -> Path | None:
        """
        Return path to compile_commands.json if it was generated.
        Returns None if not found (Sailor falls back to build_command).
        """

    def teardown(self) -> None:
        """Remove Docker container. Keep workspace on host."""

    def _run_in_container(
        self, command: str, timeout: int = 600
    ) -> tuple[int, str, str]:
        """
        Execute a shell command inside the Docker container.
        Returns (exit_code, stdout, stderr).
        """

    def _generate_compile_commands(self) -> bool:
        """
        Attempt to generate compile_commands.json using bear.
        Falls back to cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
        if bear is unavailable.
        Returns True if successful.
        """
```

---

## FILE 4: `sailor/evaluation/metrics.py`

Implement class `MetricsCalculator`.

Computes evaluation metrics from DB results.
Designed for 1 CVE now, aggregates correctly for N CVEs later.

```python
class MetricsCalculator:
    def __init__(self, db: EvaluationDB): ...

    def compute(
        self,
        cve_ids: list[str] | None = None,  # None = all CVEs
    ) -> EvaluationMetrics:
        """
        Compute all metrics from DB.
        If cve_ids is None, aggregate over all CVEs.
        """

    def compute_for_cve(self, cve_id: str) -> CVEMetrics:
        """
        Per-CVE metrics across all runs.
        Includes success_rate for repeated runs (e.g. 2/3).
        """


class EvaluationMetrics(BaseModel):
    # Dataset
    total_cves: int
    total_runs: int

    # Core metrics
    true_positives: int
    false_negatives: int
    false_positives: int
    partials: int
    recall: float              # TP / (TP + FN)
    precision: float           # TP / (TP + FP)

    # Phase-level detection rates
    phase1_detection_rate: float   # % of CVEs found by CodeQL
    phase2_trigger_rate: float     # % of Phase1 hits → bug_triggered
    phase3_confirm_rate: float     # % of bug_triggered → CONFIRMED

    # Failure analysis
    failure_reason_counts: dict[str, int]
    # e.g. {"query_missed": 3, "inconclusive": 2, ...}

    # Performance
    avg_phase2_turns: float
    avg_total_duration_sec: float

    # Token / cost
    total_llm_calls: int
    total_estimated_tokens: int
    total_estimated_cost_usd: float
    avg_cost_per_cve_usd: float


class CVEMetrics(BaseModel):
    cve_id: str
    total_runs: int
    success_count: int              # runs ending in TRUE_POSITIVE
    success_rate: float             # success_count / total_runs
    best_verdict: EvaluationVerdict | None
    failure_reasons: list[str]      # across all failed runs
    avg_phase2_turns: float
    avg_cost_usd: float
```

---

## FILE 5: `sailor/evaluation/report.py`

Implement class `ReportGenerator`.

Generates human-readable evaluation reports from DB results.

```python
class ReportGenerator:
    def __init__(self, db: EvaluationDB, output_dir: Path): ...

    def generate(
        self,
        cve_ids: list[str] | None = None,
    ) -> Path:
        """
        Generate evaluation_report.md with:
          1. Summary table (per CVE: verdict, phase statuses, cost)
          2. Phase-level metrics
          3. Failure analysis breakdown
          4. Token / cost summary
          5. Per-CVE detail sections

        Returns path to written report file.
        """

    def generate_json(
        self,
        cve_ids: list[str] | None = None,
    ) -> Path:
        """
        Write evaluation_report.json with full EvaluationMetrics.
        Machine-readable for further analysis.
        """

    def _format_summary_table(
        self, results: list[CVEEvaluationResult]
    ) -> str:
        """
        Markdown table:
        | CVE ID | Phase1 | Phase2 | Phase3 | Verdict | Turns | Cost |
        |--------|--------|--------|--------|---------|-------|------|
        | CVE-.. | ✅     | ✅     | ✅     | TP      | 12    | $0.8 |
        """

    def _format_failure_analysis(
        self, results: list[CVEEvaluationResult]
    ) -> str:
        """
        Breakdown of failure reasons with fix suggestions:
          query_missed     → "Add custom query for this pattern"
          filtered_out     → "Review skip patterns in Phase 1"
          inconclusive     → "Increase T_max or improve harness rules"
          asan_not_confirmed → "Check Docker build environment"
        """
```

---

## FILE 6: `sailor/evaluation/pipeline.py`

Implement class `EvaluationPipeline`.

Top-level orchestrator. Connects all components and enforces
the checkpoint-resume logic that protects the token budget.

```python
@dataclass
class EvaluationConfig:
    db_path: Path                  # SQLite DB file path
    dataset_path: Path             # JSON file with CVERecord list
    workspace_dir: Path            # Docker volume mount base
    output_dir: Path               # Reports and artifacts

    # Sailor config (passed through to each Phase)
    llm_model: str = "claude-sonnet-4-5"
    klee_path: str = "klee"
    clang_path: str = "clang"

    # Evaluation config
    runs_per_cve: int = 1          # increase for reproducibility study
    phase_timeout_sec: int = 3600  # per phase, per CVE
    skip_docker: bool = False      # True for local dev without Docker

class EvaluationPipeline:
    def __init__(self, config: EvaluationConfig): ...

    def run(
        self,
        cve_ids: list[str] | None = None,  # None = run all in dataset
    ) -> EvaluationMetrics:
        """
        Main evaluation loop.

        For each CVE in dataset (filtered by cve_ids if given):
          For each run in range(runs_per_cve):

            # CHECKPOINT CHECK — never re-run completed phases
            resumable = db.get_resumable_phase(cve_id)
            if resumable:
              eval_id, next_phase = resumable
              resume from next_phase
            else:
              create new CVEEvaluationResult in DB

            # Run phases sequentially
            # Each phase result is saved to DB before next phase starts
            _run_phase1(eval_id, cve, env) if needed
            _run_phase2(eval_id, cve, env) if needed
            _run_phase3(eval_id, cve, env) if needed

            # Compute verdict
            _compute_verdict(eval_id, cve)

        # Generate report
        report_gen.generate()
        return metrics_calc.compute()
        """

    def _run_phase1(
        self,
        eval_id: str,
        record: CVERecord,
        env: DockerEnvironment,
    ) -> Phase1Result | None:
        """
        Run Phase1Pipeline.
        Save result to DB immediately via db.update_phase_status().
        Return None and record FAILED status on exception.
        """

    def _run_phase2(
        self,
        eval_id: str,
        record: CVERecord,
        phase1_result: Phase1Result,
    ) -> list[Phase2Result] | None:
        """
        Filter phase1_result.specifications to those matching
        ground truth location (file + func).
        Run Phase2Pipeline on filtered specs only.

        Token budget note:
          Only run Phase 2 on specs that match the ground truth location.
          Do NOT run Phase 2 on all 1,260 specs — that would exhaust
          the $20 token budget immediately.

        Save result to DB immediately.
        """

    def _run_phase3(
        self,
        eval_id: str,
        record: CVERecord,
        phase2_results: list[Phase2Result],
        phase1_result: Phase1Result,
    ) -> Phase3Result | None:
        """
        Run Phase3Pipeline on BUG_TRIGGERED results only.
        Save result to DB immediately.
        """

    def _compute_verdict(
        self,
        eval_id: str,
        record: CVERecord,
    ) -> EvaluationVerdict:
        """
        Load latest phase results from DB.
        Apply ground truth matching logic.
        Save verdict to DB.

        Matching logic:
          TRUE_POSITIVE:
            phase3_confirmed == True
            AND result location matches ground truth
            (file, func within tolerance)

          PARTIAL:
            phase1_detected == True
            AND (phase2_triggered OR phase3_confirmed) == False

          FALSE_NEGATIVE:
            phase1_detected == False

          FALSE_POSITIVE:
            phase3_confirmed == True
            AND result location does NOT match ground truth
        """

    def _match_ground_truth(
        self,
        result: ValidationResult,
        record: CVERecord,
        line_tolerance: int = 20,
    ) -> bool:
        """
        True if:
          record.vulnerable_file in result.file
          AND record.vulnerable_func in result.func
          AND abs(result.line - record.vulnerable_line) <= line_tolerance
        """
```

---

## Token Budget Management

Critical for the $20 constraint.

```
Estimated token costs per CVE (claude-sonnet-4-5):
  Phase 1: ~0 LLM calls (CodeQL only)
  Phase 2: T_max=60 turns × ~2,000 tokens/turn ≈ 120,000 tokens
           ≈ $0.36 per CVE (input) + $0.60 (output) ≈ ~$1/CVE
  Phase 3: ~0 LLM calls (ASan only)

$20 budget → ~20 CVEs at full T_max=60
           → or 1 CVE with T_max=60, run 3 times for reproducibility

Budget-saving rules enforced in EvaluationPipeline:
  1. Only run Phase 2 on specs matching ground truth location
     (not all 1,260 Phase 1 specs)
  2. DB checkpoint prevents re-running completed phases
  3. EvaluationConfig.runs_per_cve = 1 by default
  4. Phase 2 T_max can be reduced for budget runs:
     set T_max=20 for quick validation, T_max=60 for full run
```

---

## Output Files

```
output_dir/evaluation/
├── evaluation.db              # SQLite DB (all results)
├── evaluation_report.md       # Human-readable report
├── evaluation_report.json     # Machine-readable metrics
└── <cve_id>/
    ├── phase1_summary.json    # Phase 1 output
    ├── phase2_summary.json    # Phase 2 output
    ├── phase3_summary.json    # Phase 3 output
    └── verified_bug.json      # Final verdict (if CONFIRMED)
```

---

## Extending to N CVEs

To add more CVEs later, only two steps are needed:

```
Step 1: Add entries to the dataset JSON file
        No code changes required.

Step 2: Run EvaluationPipeline with the new cve_ids
        DB checkpointing ensures existing results are preserved.
        Only new CVEs are processed.

# Example: add 5 more CVEs
pipeline.run(cve_ids=["CVE-2024-0001", "CVE-2024-0002", ...])

# Example: re-run only failed CVEs
failed = [r.cve_id for r in db.list_evaluations()
          if r.verdict == EvaluationVerdict.FALSE_NEGATIVE]
pipeline.run(cve_ids=failed)
```

---

## Implementation Rules Specific to Evaluation

```
1. DB write happens IMMEDIATELY after each Phase completes.
   Never batch DB writes. Each phase result is a checkpoint.

2. Phase 2 must ONLY run on specs matching ground truth location.
   Running Phase 2 on all Phase 1 specs will exhaust the token budget.

3. EvaluationPipeline must check db.get_resumable_phase() before
   creating a new evaluation row. Never create duplicate runs
   for the same CVE unless runs_per_cve > 1.

4. DockerEnvironment.teardown() must be called in a finally block.
   Never leave containers running after pipeline completion or error.

5. All duration measurements use time.perf_counter(), not time.time().

6. estimated_cost_usd is calculated as:
     input_tokens  × (price_per_1M_input  / 1_000_000)
   + output_tokens × (price_per_1M_output / 1_000_000)
   Store as float, round to 4 decimal places in reports.
```

---

## Claude Code Task Prompt

```
Read CLAUDE.md, then read CLAUDE_evaluation.md, then implement
the evaluation framework.

Before writing any code:
1. Confirm Phases 1, 2, 3 are implemented:
   → Check sailor/phase1/pipeline.py exists
   → Check sailor/phase2/pipeline.py exists
   → Check sailor/phase3/pipeline.py exists
2. Verify Docker is available:
   → Run: docker --version
3. Verify SQLite is available (stdlib):
   → Run: python3 -c "import sqlite3; print(sqlite3.sqlite_version)"

Implement sailor/evaluation/ in this order:
  schemas.py additions (CVERecord, CVEEvaluationResult, etc.)
  → db.py               (implement schema + all methods)
  → dataset.py          (implement CVEDataset + INITIAL_DATASET)
  → environment.py      (implement DockerEnvironment)
  → metrics.py          (implement MetricsCalculator)
  → report.py           (implement ReportGenerator)
  → pipeline.py         (implement EvaluationPipeline)

After implementation, validate with:
  1. Initialize DB and load INITIAL_DATASET (1 CVE)
  2. Run EvaluationPipeline for CVE-2025-11494
  3. Confirm evaluation.db is created and populated
  4. Confirm evaluation_report.md is generated
  5. Interrupt mid-run, re-run, and verify DB checkpoint
     prevents Phase 1 from re-executing
```
