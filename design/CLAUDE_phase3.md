# Phase 3: Validation

> Claude Code reads this file during Session 4 — Phase 3 Implementation.
> This document is referenced by CLAUDE.md Section 5, Session 4.
> All Absolute Rules defined in CLAUDE.md apply in full.

---

## Overview

Phase 3 validates Phase 2 witness inputs against the unmodified project
source to eliminate false positives caused by unrealistic harness generation.

```
Input:  WitnessInput (.ktest files) from Phase 2
        where outcome == SEOutcome.BUG_TRIGGERED

Output: ValidationResult (CONFIRMED | FALSE_POSITIVE)
        + concrete replay driver
        + ASan crash report
        + verified_bug.json

Pipeline:
  [Replay Driver Generation]
    Transform symbolic driver → concrete driver
    Replace klee_make_symbolic → memcpy of witness bytes
    Remove all KLEE-specific calls
          ↓
  [ASan Compilation]
    Compile unmodified project source with -fsanitize=address → .a
    Compile replay driver and link against project .a
          ↓
  [Concrete Execution]
    Execute the linked reproducer binary
          ↓
  [Result Classification]
    Confirmed: ASan reports violation inside project source files
    False positive: no crash, or crash only in harness/stub code
          ↓
  [Output Generation]
    verified_bug.json + replay_driver.c + asan_report.txt
```

---

## Integration with Phase 1 and Phase 2

Phase 3 receives and references the following from earlier phases.
Do not redefine these — import from `sailor.models.schemas`.

```python
# From Phase 1 (sailor.models.schemas)
from sailor.models.schemas import VulnerabilitySpec, Location

# From Phase 2 (sailor.models.schemas)
from sailor.models.schemas import WitnessInput, HarnessArtifacts, SEOutcome
```

Phase 3 processes only specs where `outcome == SEOutcome.BUG_TRIGGERED`.
All other outcomes (INCONCLUSIVE, LIKELY_FP, SITE_REACHED) are skipped.

---

## Three-Phase Classification Hierarchy

Each phase characterizes the vulnerability at a different abstraction level.
Phase 3 ASan verdict is the ground truth — it runs unmodified code.

| Phase | Tool   | Classification Level | Example                    |
|-------|--------|---------------------|----------------------------|
| 1     | CodeQL | CWE pattern         | CWE-120 unchecked memcpy   |
| 2     | KLEE   | Memory error type   | .ptr.err, .free.err        |
| 3     | ASan   | Concrete violation  | heap-buffer-overflow       |

All three must be consistent in the final verified_bug.json.

---

## Module Structure

```
sailor/phase3/
├── pipeline.py              # Phase3Pipeline — top-level orchestrator
├── replay_driver_gen.py     # ReplayDriverGenerator
├── asan_compiler.py         # ASanCompiler
├── concrete_executor.py     # ConcreteExecutor
└── result_classifier.py     # ResultClassifier
```

---

## Data Models (add to `sailor/models/schemas.py`)

```python
from enum import Enum
from pydantic import BaseModel

class ValidationVerdict(str, Enum):
    CONFIRMED      = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ERROR          = "ERROR"          # execution failed unexpectedly

class ASanViolationType(str, Enum):
    HEAP_BUFFER_OVERFLOW  = "heap-buffer-overflow"
    STACK_BUFFER_OVERFLOW = "stack-buffer-overflow"
    USE_AFTER_FREE        = "heap-use-after-free"
    NULL_DEREFERENCE      = "null-dereference"
    UNKNOWN               = "unknown"

class ASanReport(BaseModel):
    violation_type: ASanViolationType
    file: str                    # source file where violation occurred
    line: int
    func: str                    # function name
    stack_trace: str             # full ASan stack trace text
    is_in_project_source: bool   # True if file is in project_root

class WitnessValue(BaseModel):
    name: str                    # symbolic variable name, e.g. "copy_size"
    size_bytes: int
    data_hex: str                # hex representation of witness bytes
    data_interpreted: int | str  # human-readable value

class ValidationResult(BaseModel):
    spec_id: str                 # finding_id from VulnerabilitySpec
    verdict: ValidationVerdict
    cwe: str                     # from VulnerabilitySpec
    file: str                    # from ASanReport
    line: int
    func: str
    asan_type: ASanViolationType | None
    asan_report: ASanReport | None
    inputs: list[WitnessValue]
    replay_driver_path: str
    asan_report_path: str
    verdict_path: str            # path to verified_bug.json
    timestamp: str               # ISO 8601

class Phase3Result(BaseModel):
    total_processed: int
    confirmed: int
    false_positives: int
    errors: int
    results: list[ValidationResult]
    timestamp: str
```

---

## FILE 1: `sailor/phase3/replay_driver_gen.py`

Implement class `ReplayDriverGenerator`.

Transforms the symbolic driver from Phase 2 into a concrete replay driver
by replacing all KLEE-specific calls with concrete witness values.

```python
class ReplayDriverGenerator:
    def __init__(
        self,
        witness: WitnessInput,
        output_dir: Path,
    ): ...

    def generate(self) -> Path:
        """
        Transform Phase 2 symbolic driver into concrete replay driver.

        Step 1: Load driver_c from witness.harness.driver_c
        Step 2: Parse .ktest file to extract witness values
                (one value per klee_make_symbolic call)
        Step 3: Apply all four transformations (see below)
        Step 4: Write to output_dir/replay_driver.c
        Return: path to replay_driver.c
        """

    def _parse_ktest(self, ktest_path: str) -> list[WitnessValue]:
        """
        Parse a .ktest binary file produced by KLEE.

        .ktest format:
          header: "KTEST" magic + version
          num_objects: uint32
          for each object:
            name_len: uint32
            name: bytes (symbolic variable name)
            data_len: uint32
            data: bytes (concrete witness bytes)

        Return list of WitnessValue with:
          name:             symbolic variable name
          size_bytes:       data_len
          data_hex:         hex string of data bytes
          data_interpreted: integer value (little-endian) if size <= 8,
                            else hex string
        """

    def _replace_klee_make_symbolic(
        self, source: str, witness_values: list[WitnessValue]
    ) -> str:
        """
        Replace each klee_make_symbolic call with memcpy of witness bytes.

        Pattern to match:
          klee_make_symbolic(&<var>, sizeof(<var>), "<name>");
          klee_make_symbolic(<buf>, <size>, "<name>");

        Replacement:
          memcpy(&<var>, "<witness_bytes_as_c_string>", sizeof(<var>));
          memcpy(<buf>, "<witness_bytes_as_c_string>", <size>);

        Example (copy_size = 17 = 0x11):
          BEFORE: klee_make_symbolic(&sz, sizeof(sz), "copy_size");
          AFTER:  memcpy(&sz, "\x11\x00\x00\x00\x00\x00\x00\x00",
                         sizeof(sz));
        """

    def _remove_klee_assume(self, source: str) -> str:
        """Remove all klee_assume(...); statements."""

    def _remove_klee_assert(self, source: str) -> str:
        """Remove all klee_assert(...); statements."""

    def _remove_klee_warning(self, source: str) -> str:
        """Remove all klee_warning_once(...); statements."""

    def _add_ktest_include(self, source: str) -> str:
        """
        Add required includes for memcpy:
          #include <string.h>
          #include <stdlib.h>
        Remove #include <klee/klee.h> if present.
        """
```

---

## FILE 2: `sailor/phase3/asan_compiler.py`

Implement class `ASanCompiler`.

Compiles the unmodified project source with AddressSanitizer and links
the replay driver against it.

```python
class ASanCompiler:
    def __init__(
        self,
        clang_path: str,
        project_root: Path,
        build_context: BuildContext,   # from VulnerabilitySpec
        output_dir: Path,
    ): ...

    def compile_project(self) -> Path:
        """
        Compile unmodified project source with ASan instrumentation.

        Command:
          clang -fsanitize=address -O1 -g \
                <include_paths from build_context> \
                <defines from build_context> \
                -c <project_source_files> \
                -o project_asan.a

        CRITICAL: Use the UNMODIFIED project source files.
        Never use the LLM-generated stub or slice files.

        Strategy for finding source files:
          1. Use compile_commands.json if available
          2. Otherwise: find <project_root> -name "*.c" -not -path "*/test*"

        Return: path to compiled project_asan.a
        Raise: ASanCompileError if compilation fails.
        """

    def compile_replay_driver(
        self, replay_driver_path: Path, project_archive: Path
    ) -> Path:
        """
        Compile replay driver and link against ASan-instrumented project.

        Command:
          clang -fsanitize=address -O1 -g \
                <replay_driver_path> \
                <project_archive> \
                -o reproducer

        Return: path to reproducer binary
        Raise: ASanCompileError if compilation fails.
        """

    def _get_source_files(self) -> list[Path]:
        """
        Collect project source files for compilation.
        Exclude: test/, bench/, example/, fuzz/, generated files.
        (Same skip patterns as Phase 1 filtering rules.)
        """
```

---

## FILE 3: `sailor/phase3/concrete_executor.py`

Implement class `ConcreteExecutor`.

Executes the reproducer binary and captures ASan output.

```python
class ConcreteExecutor:
    def __init__(
        self,
        timeout: int = 30,         # seconds per execution
        output_dir: Path = None,
    ): ...

    def execute(self, reproducer_path: Path) -> tuple[bool, str]:
        """
        Run the reproducer binary and capture output.

        Execute with:
          ASAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
          ./reproducer

        Capture both stdout and stderr.
        ASan reports appear on stderr.

        Return: (crashed: bool, combined_output: str)
          crashed=True  if exit code != 0 or "ERROR: AddressSanitizer" in stderr
          crashed=False if exits cleanly

        Raise: TimeoutError if execution exceeds timeout.
        Write combined output to output_dir/asan_output.txt
        """

    def _detect_crash(self, stdout: str, stderr: str, exit_code: int) -> bool:
        """
        Detect crash from:
          - exit_code != 0
          - "ERROR: AddressSanitizer" in stderr
          - "SUMMARY: AddressSanitizer" in stderr
          - "Segmentation fault" in stderr
        """
```

---

## FILE 4: `sailor/phase3/result_classifier.py`

Implement class `ResultClassifier`.

Parses ASan output and classifies the result as CONFIRMED or FALSE_POSITIVE.

```python
class ResultClassifier:
    def __init__(self, project_root: Path): ...

    def classify(
        self,
        crashed: bool,
        asan_output: str,
        spec: VulnerabilitySpec,
        witness_values: list[WitnessValue],
    ) -> ValidationResult:
        """
        Classify the execution result.

        CONFIRMED conditions (ALL must be true):
          1. crashed == True
          2. "ERROR: AddressSanitizer" present in asan_output
          3. ASan stack trace contains at least one frame
             pointing to a file inside project_root
             (not driver.c, stubs.c, or replay_driver.c)

        FALSE_POSITIVE conditions (ANY is true):
          1. crashed == False
          2. crash occurred only in harness files
             (driver.c, stubs.c, replay_driver.c)
          3. ASan output present but no project source in stack trace

        Build ValidationResult with:
          verdict:    CONFIRMED | FALSE_POSITIVE
          asan_report: parsed ASanReport (if crashed)
          inputs:     witness_values
        """

    def _parse_asan_report(self, asan_output: str) -> ASanReport | None:
        """
        Parse ASan stderr output into ASanReport.

        Extract:
          violation_type: from "ERROR: AddressSanitizer: <type>"
            Map to ASanViolationType enum:
              "heap-buffer-overflow"  → HEAP_BUFFER_OVERFLOW
              "stack-buffer-overflow" → STACK_BUFFER_OVERFLOW
              "heap-use-after-free"   → USE_AFTER_FREE
              "null-dereference"      → NULL_DEREFERENCE
              other                   → UNKNOWN

          file, line, func: from first stack frame in project source
            Pattern: "#N <func>(...) <file>:<line>"

          stack_trace: full text between
            "ERROR: AddressSanitizer:" and "SUMMARY:"

          is_in_project_source: True if file is under project_root
        """

    def _is_project_source(self, file_path: str) -> bool:
        """
        Return True if file_path is inside project_root.
        Return False for: driver.c, stubs.c, replay_driver.c,
                          /usr/*, /lib/*, memcpy.c (system files)
        """

    def _build_verified_bug_json(
        self,
        result: ValidationResult,
        spec: VulnerabilitySpec,
    ) -> dict:
        """
        Build the final verified_bug.json structure:
        {
          "verdict": "CONFIRMED",
          "cwe": "CWE-122",
          "file": "elfxx-x86.c",
          "line": 2286,
          "func": "_bfd_x86_elf_late_size_sections",
          "asan_type": "heap-buffer-overflow",
          "inputs": [
            {"copy_size": 17},
            {"dst_bytes": 16},
            {"src_bytes": 512}
          ]
        }

        CWE refinement:
          If Phase 1 CWE is CWE-120 and ASan reports heap-buffer-overflow
          → refine to CWE-122 (heap-based buffer overflow)
          If Phase 1 CWE is CWE-120 and ASan reports stack-buffer-overflow
          → refine to CWE-121 (stack-based buffer overflow)
          Otherwise → use Phase 1 CWE as-is
        """
```

---

## FILE 5: `sailor/phase3/pipeline.py`

Implement class `Phase3Pipeline`.

Top-level orchestrator for Phase 3. Processes all BUG_TRIGGERED results
from Phase 2 and produces final validation verdicts.

```python
@dataclass
class Phase3Config:
    project_name: str
    project_root: Path
    output_dir: Path
    clang_path: str = "clang"
    execution_timeout: int = 30      # seconds per reproducer run
    max_workers: int = 4

class Phase3Pipeline:
    def __init__(self, config: Phase3Config): ...

    def run(
        self,
        phase2_results: list[Phase2Result],
        specs: list[VulnerabilitySpec],
    ) -> Phase3Result:
        """
        Process all Phase 2 results where outcome == BUG_TRIGGERED.
        Skip all other outcomes silently (log count).

        For each qualifying result:
          1. Look up matching VulnerabilitySpec by spec_id
          2. Run ReplayDriverGenerator.generate()
          3. Run ASanCompiler.compile_project() + compile_replay_driver()
          4. Run ConcreteExecutor.execute()
          5. Run ResultClassifier.classify()
          6. Write output files

        Parallelize with ThreadPoolExecutor(max_workers).

        Write to output_dir/phase3/:
          <spec_id>/replay_driver.c
          <spec_id>/asan_output.txt
          <spec_id>/verified_bug.json  (only if CONFIRMED)
          phase3_results.json
          phase3_summary.json

        Summary format:
        {
          "project": "<project_name>",
          "total_processed": N,
          "confirmed": K,
          "false_positives": J,
          "errors": M,
          "confirmed_bugs": [
            {
              "spec_id": "...",
              "cwe": "CWE-122",
              "file": "elfxx-x86.c",
              "line": 2286,
              "asan_type": "heap-buffer-overflow"
            }
          ],
          "timestamp": "<ISO 8601>"
        }
        """

    def run_single(
        self,
        phase2_result: Phase2Result,
        spec: VulnerabilitySpec,
    ) -> ValidationResult:
        """Run Phase 3 for a single BUG_TRIGGERED result."""

    def _setup_output_dir(self, spec_id: str) -> Path:
        """Create output_dir/phase3/<spec_id>/ directory."""
```

---

## Full Pipeline Integration

Phase 3 completes the end-to-end Sailor pipeline:

```python
from sailor import (
    Phase1Pipeline, Phase1Config,
    Phase2Pipeline, Phase2Config,
    Phase3Pipeline, Phase3Config,
)
from sailor.models.schemas import SEOutcome

# Phase 1
p1_result = Phase1Pipeline(Phase1Config(...)).run()

# Phase 2
p2_results = Phase2Pipeline(Phase2Config(...)).run(
    p1_result.specifications
)

# Phase 3 — process only BUG_TRIGGERED results
p3_result = Phase3Pipeline(Phase3Config(
    project_name=p1_config.project_name,
    project_root=p1_config.project_root,
    output_dir=p1_config.output_dir / "phase3",
)).run(p2_results, p1_result.specifications)

# Final output
confirmed = [r for r in p3_result.results
             if r.verdict == ValidationVerdict.CONFIRMED]
```

---

## Implementation Rules Specific to Phase 3

```
1. NEVER use LLM-generated stub or slice files when compiling
   the project for ASan. Always use unmodified project source.
   This is the fundamental correctness guarantee of Phase 3.

2. CONFIRMED verdict requires the ASan stack trace to contain
   at least one frame inside project_root.
   A crash in driver.c or stubs.c alone is FALSE_POSITIVE.

3. .ktest parsing must handle binary format correctly.
   Use struct.unpack for all integer fields.
   Never assume text encoding for witness data bytes.

4. CWE refinement (CWE-120 → CWE-122/121) must be applied
   in ResultClassifier._build_verified_bug_json().
   The refined CWE is used in verified_bug.json, not the Phase 1 CWE.

5. All subprocess calls (clang, reproducer execution) go through
   ASanCompiler and ConcreteExecutor respectively.
   No raw subprocess.run() calls in pipeline.py or elsewhere.

6. Each spec_id gets its own subdirectory under output_dir/phase3/.
   Never mix output files from different specs.

7. verified_bug.json is written ONLY for CONFIRMED verdicts.
   FALSE_POSITIVE results write only asan_output.txt (for debugging).
```

---

## Claude Code Task Prompt

```
Read CLAUDE.md, then read CLAUDE_phase3.md, then implement Phase 3.

Before writing any code:
1. Confirm Phase 2 output is available:
   → Check output_dir/phase2/phase2_results.json exists
   → Confirm at least one result has outcome == "bug_triggered"
2. Verify clang and ASan are available:
   → Run: clang --version
   → Run: echo '#include <sanitizer/asan_interface.h>' | clang -x c -fsanitize=address -
3. Check .ktest parsing is feasible:
   → Locate one .ktest file from Phase 2 output
   → Verify it can be opened as binary

Then implement sailor/phase3/ in this order:
  schemas.py additions (ValidationResult, ASanReport, etc.)
  → replay_driver_gen.py
  → asan_compiler.py
  → concrete_executor.py
  → result_classifier.py
  → pipeline.py

Do not modify any Phase 1 or Phase 2 files.
Do not use stub or slice files when compiling project for ASan.

After implementation, validate with:
  Run Phase 3 on Phase 2 output.
  Confirm phase3_summary.json is written to output_dir/phase3/.
  If a CONFIRMED result exists, verify verified_bug.json structure
  matches the schema defined in CLAUDE_phase3.md.
```