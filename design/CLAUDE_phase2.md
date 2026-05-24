# Phase 2: LLM Orchestrated Symbolic Execution

### Overview

Phase 2 takes a `VulnerabilitySpec` from Phase 1 and determines whether
the vulnerability is actually reachable and triggerable by constructing
a harness `H` that KLEE (symbolic execution engine) can execute.

The pipeline is LLM-orchestrated: the LLM synthesizes the harness,
receives compiler and SE feedback, and iteratively refines `H` until
one of three terminal conditions is met.

```
Input:  VulnerabilitySpec  (from Phase 1)
Output: WitnessInput (.ktest) | inconclusive | likely_false_positive

Pipeline:
  [Source Exploration]   LLM reads signatures, structs, type definitions
          ↓
  [Driver Synthesis]     LLM writes main() that sets up symbolic state
          ↓
  [Stub Synthesis]       LLM writes self-contained code slice + stubs
          ↓
  [Assertion Instantiation] LLM encodes safety property into KLEE constraints
          ↓
  [Harness Refinement]   compile → KLEE → diagnose → fix loop
```

---

### Integration with Phase 1

Phase 2 receives the following models from Phase 1.
Do not redefine them — import from sailor.models.schemas.

Key models to import:
  - VulnerabilitySpec  (input to Phase 2)
  - BuildContext       (used by SourceExplorer)
  - TraceStep          (used by DriverSynthesizer)

Reference: sailor/models/schemas.py (implemented in Session 2)

---

### Module Structure

```
sailor/phase2/
├── pipeline.py              # Phase2Pipeline — top-level orchestrator
├── llm_orchestrator.py      # LLMOrchestrator — manages turn budget + history
├── source_explorer.py       # SourceExplorer — LLM tool calls for source reading
├── driver_synthesizer.py    # DriverSynthesizer — main() generation
├── stub_synthesizer.py      # StubSynthesizer — code slice + stub generation
├── assertion_instantiator.py # AssertionInstantiator — KLEE constraint encoding
├── harness_refiner.py       # HarnessRefiner — compile-execute-refine loop
├── compile_diagnoser.py     # CompileDiagnoser — clang error classification
└── se_diagnoser.py          # SEDiagnoser — KLEE output classification
```

---

### Data Models (add to `sailor/models/schemas.py`)

```python
from enum import Enum
from pydantic import BaseModel
from typing import Literal

class SEOutcome(str, Enum):
    BUG_TRIGGERED    = "bug_triggered"
    SITE_REACHED     = "site_reached"
    NOT_REACHED      = "not_reached"
    INCONCLUSIVE     = "inconclusive"
    LIKELY_FP        = "likely_false_positive"

class CompileErrorClass(str, Enum):
    INCOMPLETE_TYPE      = "incomplete_type"
    CONFLICTING_PROTO    = "conflicting_prototype"
    REDEFINITION         = "redefinition"
    OTHER                = "other"

class CompileDiagnostic(BaseModel):
    error_class: CompileErrorClass
    raw_error: str
    suggested_fix: str          # orchestrator-augmented fix hint
    relevant_source: str | None # grepped prototype or header snippet

class SEDiagnostic(BaseModel):
    outcome: SEOutcome
    functions_entered: list[str]   # parsed from klee_warning_once probes
    functions_missed: list[str]    # call chain functions not entered
    ktest_paths: list[str]         # populated on BUG_TRIGGERED
    raw_output: str

class SymbolicInputKind(str, Enum):
    SYMBOLIC_SCALAR = "symbolic_scalar"
    CONCRETE_POINTER = "concrete_pointer"
    SYMBOLIC_BUFFER = "symbolic_buffer"

class FieldClassification(BaseModel):
    field_name: str
    field_type: str
    kind: SymbolicInputKind
    reason: str                 # why this classification was chosen

class GuardCondition(BaseModel):
    condition: str              # e.g. "plt_eh_frame == NULL"
    assume_stmt: str            # e.g. "klee_assume(plt_eh_frame != NULL)"
    location: str               # file:line where guard appears

class HarnessArtifacts(BaseModel):
    driver_c: str               # full C source of driver (main())
    slice_c: str                # full C source of code slice + stubs
    compile_cmd: str            # clang command used
    link_cmd: str               # llvm-link command used
    bitcode_path: str | None

class WitnessInput(BaseModel):
    spec_id: str                # finding_id from VulnerabilitySpec
    ktest_paths: list[str]      # .ktest files produced by KLEE
    outcome: SEOutcome
    harness: HarnessArtifacts
    turns_used: int
    refine_count: int

class Phase2Result(BaseModel):
    spec_id: str
    outcome: SEOutcome
    witness: WitnessInput | None
    turns_used: int
    timestamp: str
```

---

### LLM Provider Strategy

```
Default:  Gemini Flash  (used unless ANTHROPIC_API_OPTION is explicitly set)
Override: Claude        (used only when ANTHROPIC_API_OPTION=true)

Rationale:
  Running Claude on every spec exhausts token budget rapidly.
  Gemini Flash is the default to preserve tokens.
  Claude is an explicit opt-in for higher-quality runs.

Environment variables:
  ANTHROPIC_API_OPTION   "true" → use Claude
                         anything else (including unset) → use Gemini Flash
  ANTHROPIC_API_KEY      required when ANTHROPIC_API_OPTION=true
  GEMINI_API_KEY         required when ANTHROPIC_API_OPTION is not "true"

Rate limit handling (Gemini Flash only):
  HTTP 429 (RESOURCE_EXHAUSTED) from Gemini API:
    → sleep 60 seconds exactly
    → retry the same request once
    → if retry also returns 429: raise LLMRateLimitError
      caller marks spec as inconclusive; turn counter is NOT incremented
```

### LLM Client Factory (`sailor/phase2/llm_client.py`)

Implement class `LLMClientFactory` and `LLMClient`.
All LLM API calls in Phase 2 go through `LLMClient.chat()`.
No direct SDK calls anywhere else in phase2/.

```python
import os
import time
import logging
from dataclasses import dataclass

log = logging.getLogger("sailor.phase2.llm_client")


class LLMRateLimitError(Exception):
    """Raised when Gemini 429 persists after one 60-second retry."""


@dataclass
class LLMClient:
    """
    Unified LLM client that routes to Gemini Flash or Claude
    based on the ANTHROPIC_API_OPTION environment variable.

    Usage:
        client = LLMClientFactory.from_env()
        response = client.chat(messages, system_prompt)
    """
    provider: str     # "gemini" | "anthropic"
    model: str
    api_key: str

    # Gemini rate-limit retry config
    _rate_limit_wait: int = 60   # seconds
    _rate_limit_retries: int = 1  # retry once, then raise

    def chat(
        self,
        messages: list[dict],
        system_prompt: str = "",
        max_tokens: int = 8192,
    ) -> str:
        """
        Send a chat request to the configured LLM provider.
        Returns the assistant message text.

        Gemini Flash:
          - Uses google-generativeai SDK
          - On 429: sleep 60s, retry once, then raise LLMRateLimitError

        Claude:
          - Uses anthropic SDK
          - No special rate-limit handling (Anthropic has its own retry logic)
        """
        if self.provider == "gemini":
            return self._call_gemini(messages, system_prompt, max_tokens)
        elif self.provider == "anthropic":
            return self._call_anthropic(messages, system_prompt, max_tokens)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    def _call_gemini(
        self,
        messages: list[dict],
        system_prompt: str,
        max_tokens: int,
    ) -> str:
        """
        Call Gemini Flash via google-generativeai SDK.

        Rate-limit retry logic:
          attempt = 0
          while attempt <= self._rate_limit_retries:
              try:
                  response = model.generate_content(...)
                  return response.text
              except google.api_core.exceptions.ResourceExhausted:
                  if attempt == self._rate_limit_retries:
                      raise LLMRateLimitError(
                          "Gemini 429 persisted after 60s retry"
                      )
                  log.warning("Gemini rate limit hit — sleeping 60s")
                  time.sleep(self._rate_limit_wait)
                  attempt += 1

        Message format conversion (OpenAI-style → Gemini Content):
          role "user"      → role="user"
          role "assistant" → role="model"
          system_prompt    → passed as system_instruction to GenerativeModel
        """

    def _call_anthropic(
        self,
        messages: list[dict],
        system_prompt: str,
        max_tokens: int,
    ) -> str:
        """
        Call Claude via anthropic SDK.

        Uses anthropic.Anthropic(api_key=self.api_key).messages.create()
        No special rate-limit handling — anthropic SDK handles retries.
        """


class LLMClientFactory:
    """
    Reads ANTHROPIC_API_OPTION from environment and returns the
    appropriate LLMClient. Called once at Phase2Config construction.
    """

    @staticmethod
    def from_env() -> LLMClient:
        """
        Resolution logic:

          use_claude = os.environ.get("ANTHROPIC_API_OPTION", "").lower() == "true"

          if use_claude:
              api_key = os.environ.get("ANTHROPIC_API_KEY", "")
              if not api_key:
                  raise EnvironmentError(
                      "ANTHROPIC_API_KEY must be set when "
                      "ANTHROPIC_API_OPTION=true"
                  )
              return LLMClient(
                  provider="anthropic",
                  model="claude-sonnet-4-5",
                  api_key=api_key,
              )
          else:
              api_key = os.environ.get("GEMINI_API_KEY", "")
              if not api_key:
                  raise EnvironmentError(
                      "GEMINI_API_KEY must be set when "
                      "ANTHROPIC_API_OPTION is not 'true'"
                  )
              return LLMClient(
                  provider="gemini",
                  model="gemini-2.0-flash",
                  api_key=api_key,
              )
        """
```

### Turn Budget Configuration

```python
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class Phase2Config:
    # Inherited from Phase1Config
    project_name: str
    project_root: Path
    output_dir: Path

    # LLM client — resolved from environment at construction time.
    # Default uses Gemini Flash unless ANTHROPIC_API_OPTION=true.
    # Never set provider/model/key directly; always use LLMClientFactory.
    llm: LLMClient = field(
        default_factory=LLMClientFactory.from_env
    )

    # KLEE settings
    klee_path: str = "klee"
    clang_path: str = "clang"
    llvm_link_path: str = "llvm-link"
    klee_timeout: int = 300               # seconds per run (paper: T_klee=300)
    klee_depth_limit: int = 1000

    # Turn budgets (from paper)
    T_explore: int = 8     # source exploration turns
    T_author: int = 12     # harness authoring turns (T_explore < t < T_author)
    T_max: int = 60        # total turn budget
    R_max: int = 15        # max refinement turns after site_reached
```

---

### FILE 1: `sailor/phase2/llm_orchestrator.py`

Implement class `LLMOrchestrator`.

This class manages the entire Algorithm 1 loop from the paper.
It owns the turn counter, conversation history, and phase transitions.

```python
class LLMOrchestrator:
    def __init__(self, config: Phase2Config, spec: VulnerabilitySpec): ...

    def run(self) -> Phase2Result:
        """
        Execute Algorithm 1 in full.

        t = 0, refine_count = 0
        while t < T_max:
            action = self._call_llm(history)

            if t < T_explore:
                # Source exploration phase
                result = self.source_explorer.execute(action)
                history.append(result)

            elif t < T_author:
                # Harness authoring phase
                result = self.harness_writer.execute(action)
                history.append(result)

            else:
                # Harness refinement phase
                compile_result = self.compile_diagnoser.run(harness)
                if compile_result.failed:
                    history.append(compile_result.diagnostic)
                    t += 1
                    continue

                se_result = self.se_diagnoser.run(bitcode)

                if se_result.outcome == BUG_TRIGGERED:
                    return Phase2Result(outcome=BUG_TRIGGERED, ...)

                if se_result.outcome == SITE_REACHED:
                    refine_count += 1
                    if refine_count > R_max:
                        return Phase2Result(outcome=LIKELY_FP, ...)
                    history.append(se_result.diagnostic)

                t += 1

        return Phase2Result(outcome=INCONCLUSIVE, ...)
        """

    def _call_llm(self, history: list[dict]) -> dict:
        """
        Call the LLM via self.llm_client.chat().
        All provider routing (Gemini vs Claude) is handled by LLMClient.

        On LLMRateLimitError (Gemini 429 after retry):
          - Do NOT increment turn counter t
          - Log the rate limit event
          - Re-raise so the caller (run()) can catch and handle:
              the spec is marked inconclusive without consuming a turn

        Never call Gemini or Anthropic SDK directly here.
        """

    def _build_system_prompt(self) -> str:
        """
        Construct the system prompt containing:
        - VulnerabilitySpec (verbatim from Phase 1)
        - Driver rules with GOOD/BAD examples
        - Code slice rules with GOOD/BAD examples
        - Assertion instantiation rules per CWE
        - Available tool definitions
        """
```

---

### FILE 2: `sailor/phase2/source_explorer.py`

Implement class `SourceExplorer`.

The LLM issues tool calls during `t < T_explore` to read project source.
This class executes those tool calls and returns structured results.

```python
class SourceExplorer:
    def __init__(self, project_root: Path): ...

    def get_function_signature(self, function_name: str) -> str:
        """
        Search project source for the function signature.
        Use: grep -rn "function_name" --include="*.h" --include="*.c"
        Return the signature line + surrounding context (±5 lines).
        """

    def get_struct_definition(self, struct_name: str) -> str:
        """
        Search for struct definition including all fields.
        Handle typedef struct patterns.
        Return full struct body.
        """

    def get_type_declaration(self, type_name: str) -> str:
        """
        Search for typedef, enum, or macro definition.
        Return declaration with file:line location.
        """

    def get_call_chain(
        self, entry: str, target: str
    ) -> list[str]:
        """
        Return ordered list of functions from entry to target
        using ctags or grep-based call graph approximation.
        """

    def get_file_slice(
        self, file: str, start_line: int, end_line: int
    ) -> str:
        """Return lines [start_line, end_line] from file."""

    def identify_guards(
        self, call_chain: list[str]
    ) -> list[GuardCondition]:
        """
        Scan call chain functions for early-exit conditions:
          if (ptr == NULL) return;
          if (!condition) return false;
        Return list of GuardCondition with assume_stmt populated.
        """

    def classify_fields(
        self,
        spec: VulnerabilitySpec,
        struct_name: str,
    ) -> list[FieldClassification]:
        """
        Partition struct fields into three categories:
          SYMBOLIC_SCALAR:  appears in assertion_template operands
          CONCRETE_POINTER: pointer fields (must not be NULL)
          SYMBOLIC_BUFFER:  heap regions whose contents are symbolic

        Base classification on:
          - assertion_template from VulnerabilitySpec
          - guard conditions identified
          - fields referenced along e → ℓ path
        """
```

---

### FILE 3: `sailor/phase2/driver_synthesizer.py`

Implement class `DriverSynthesizer`.

Generates the `main()` function (driver) that sets up the initial
symbolic state for KLEE.

```python
class DriverSynthesizer:
    def __init__(
        self,
        spec: VulnerabilitySpec,
        field_classifications: list[FieldClassification],
        guard_conditions: list[GuardCondition],
    ): ...

    def build_prompt(self) -> str:
        """
        Build the driver synthesis prompt following Figure 3a structure:

        SPEC section (verbatim from VulnerabilitySpec):
          l: <file>:<line>
          e: <entry function>
          d: <vulnerability description>
          guards: <comma-separated guard conditions>
          assert: <assertion_template>

        DRIVER RULES section with GOOD/BAD examples:
          Entry:    call e with allocated parameters
          Symbolic: overapproximate; make fields symbolic
            GOOD: klee_make_symbolic(&ctx, sizeof(ctx), "ctx");
            BAD:  ctx->state = 7;  // hardcoded
          Guards:   for each guard c, add klee_assume(!c)
            GOOD: klee_assume(ptr != NULL);
          Pointers: real allocs, never NULL
            GOOD: p = calloc(1, sizeof(*p));
          Buffers:  alloc + make contents symbolic
            GOOD: buf = malloc(N); klee_make_symbolic(buf, N, "buf");
        """

    def synthesize(self, llm_response: str) -> str:
        """
        Parse LLM response and extract the generated driver C code.
        Validate that:
          - main() is present
          - klee_make_symbolic calls match SYMBOLIC fields
          - calloc/malloc calls present for CONCRETE_POINTER fields
          - klee_assume(!c) present for each GuardCondition
          - entry function e is called
        Returns driver C source as string.
        """

    def add_vulnerability_condition(
        self, driver_c: str, spec: VulnerabilitySpec
    ) -> str:
        """
        Add klee_assume constraints that VIOLATE the safety property.

        Per assertion_template:
          CWE-120/787: n <= min(len(dst), len(src))
            → klee_assume(n > len(dst))
            → klee_assume(n <= len(src))

          CWE-416: no use of p after free(p)
            → ensure free(p) is called before dereference
            → free() stub must call real free()

          CWE-476: p != NULL before *p
            → klee_assume(p == NULL)

          CWE-190: arithmetic within type range
            → klee_assume(a + b > TYPE_MAX)

        Returns updated driver C source with constraints added.
        """
```

---

### FILE 4: `sailor/phase2/stub_synthesizer.py`

Implement class `StubSynthesizer`.

Generates the self-contained code slice C file containing only the
call chain from `e` to `ℓ`, with all external dependencies stubbed.

```python
class StubSynthesizer:
    def __init__(
        self,
        spec: VulnerabilitySpec,
        source_explorer: SourceExplorer,
        call_chain: list[str],
    ): ...

    def build_prompt(self) -> str:
        """
        Build the stub synthesis prompt following Figure 4a structure:

        SPEC section:
          target:   <vulnerable statement at ℓ>
          entry:    <entry function e>
          on-path:  <statements on the path from e to ℓ>
          off-path: <branches and callees NOT on the path>

        CODE SLICE RULES with GOOD/BAD examples:
          Entry:    keep signature + call to vul_func ONLY
            GOOD: int e(Type *ctx) { vul_func(ctx); return 0; }

          Branches: off-path if → if(0), loop → if(1)

          Functions: off-path callees → symbolic stubs
            BAD:  int f(...) { return -300; }
            GOOD: int f(...) {
                    int r;
                    klee_make_symbolic(&r, sizeof(r), "r");
                    return r; }

          Types:    keep only fields accessed by sliced code

          Probes:   add klee_warning_once("SPINE_PROBE:<func>:ENTRY")
                    at entry of each function in slice

          Exception: CWE-416 free() stub MUST call real free()
        """

    def synthesize(self, llm_response: str) -> str:
        """
        Parse and extract the generated code slice C source.
        Validate that all four stub granularities are applied:
          1. Function-level: off-path callees replaced with stubs
          2. Branch-level:   off-path if → if(0), switch case → break
          3. Loop-level:     enclosing loops → if(1)
          4. Type-level:     structs redefined with only accessed fields
        Returns slice C source as string.
        """

    def inject_reachability_assertion(self, slice_c: str) -> str:
        """
        Insert klee_assert(0 && "SAILOR_SINK_REACHED") immediately
        after the vulnerable statement at ℓ in the code slice.
        This fires only if ℓ executes without a memory error,
        confirming reachability (site_reached outcome).
        """

    def _apply_function_level_stubs(
        self, functions: list[str], call_chain: list[str]
    ) -> list[str]:
        """
        For each function NOT in call_chain:
          - Replace body with klee_make_symbolic return if return value
            influences path to ℓ
          - Otherwise return hardcoded default (0, NULL, false)
          - EXCEPTION: for CWE-416, free() must call real __real_free()
        """

    def _apply_branch_level_stubs(self, source: str) -> str:
        """
        Replace off-path if blocks with if(0) { }.
        Replace off-path switch cases with break.
        Identify off-path by checking if the block contains ℓ.
        """

    def _apply_loop_level_stubs(self, source: str) -> str:
        """
        Convert while/for/do-while loops that ENCLOSE ℓ to if(1).
        This bounds KLEE's path count to a single pass.
        """

    def _apply_type_level_stubs(
        self, source: str, accessed_fields: list[str]
    ) -> str:
        """
        Redefine project structs to include only fields in accessed_fields.
        This avoids transitive type dependencies and enables
        standalone compilation without project headers.
        """
```

---

### FILE 5: `sailor/phase2/compile_diagnoser.py`

Implement class `CompileDiagnoser`.

Compiles the harness to LLVM bitcode and classifies any errors.

```python
class CompileDiagnoser:
    def __init__(
        self,
        clang_path: str,
        llvm_link_path: str,
        project_root: Path,
        output_dir: Path,
    ): ...

    def compile(
        self, driver_c: str, slice_c: str
    ) -> tuple[bool, CompileDiagnostic | None]:
        """
        Step 1: Write driver_c and slice_c to output_dir/harness/
        Step 2: Compile each with:
                  clang -O0 -g -emit-llvm -c <file> -o <file>.bc
                  Include project headers from build_context.include_paths
        Step 3: Link with:
                  llvm-link driver.bc slice.bc -o harness.bc
        Step 4: Return (True, None) on success
                Return (False, CompileDiagnostic) on failure

        CompileDiagnostic includes:
          - error_class (one of four classes)
          - raw_error (compiler stderr)
          - suggested_fix (augmented by _classify_error)
          - relevant_source (grepped from project if applicable)
        """

    def _classify_error(
        self, stderr: str
    ) -> CompileDiagnostic:
        """
        Pattern-match stderr into one of four error classes:

        incomplete_type:
          Pattern: "incomplete type", "has no member named", "unknown type"
          Fix: search project headers for the missing struct/field
               grep -rn "<type_name>" --include="*.h" <project_root>

        conflicting_prototype:
          Pattern: "conflicting types for", "redeclared as different kind"
          Fix: grep for real prototype and provide it to LLM
               grep -rn "<func_name>" --include="*.h" <project_root>

        redefinition:
          Pattern: "redefinition of", "previously defined"
          Fix: suggest adding #ifndef guard or removing duplicate

        other:
          Pattern: anything else
          Fix: return raw error with file:line context
        """
```

---

### FILE 6: `sailor/phase2/se_diagnoser.py`

Implement class `SEDiagnoser`.

Runs KLEE on the compiled bitcode and classifies the outcome.

```python
class SEDiagnoser:
    def __init__(
        self,
        klee_path: str,
        timeout: int,
        depth_limit: int,
        output_dir: Path,
    ): ...

    def run(self, bitcode_path: str) -> SEDiagnostic:
        """
        Execute KLEE with dual-strategy search:
          klee --search=random-path --search=dfs
               --max-time=<timeout>
               --max-depth=<depth_limit>
               --emit-all-errors
               <bitcode_path>

        Parse KLEE output and classify into SEOutcome:
          BUG_TRIGGERED: KLEE reports memory error at ℓ
                         .ktest files present in klee-out/
          SITE_REACHED:  klee_assert(0) fires (SAILOR_SINK_REACHED)
                         no memory error
          NOT_REACHED:   neither assert nor memory error
                         ℓ was never executed
        """

    def _parse_outcome(
        self, stdout: str, stderr: str, klee_out_dir: Path
    ) -> SEOutcome:
        """
        BUG_TRIGGERED detection:
          - stderr contains "memory error" or "KLEE: ERROR"
          - .ktest files exist in klee_out_dir/

        SITE_REACHED detection:
          - stderr contains "SAILOR_SINK_REACHED"
          - no memory error reported

        NOT_REACHED detection:
          - neither of the above
        """

    def _parse_coverage_probes(self, stderr: str) -> tuple[list[str], list[str]]:
        """
        Parse klee_warning_once("SPINE_PROBE:<func>:ENTRY") messages
        from KLEE stderr.

        Returns:
          functions_entered: list of function names where probe fired
          functions_missed:  call chain functions where probe did NOT fire
        """

    def _collect_ktest_paths(self, klee_out_dir: Path) -> list[str]:
        """Collect all .ktest file paths from klee-out/ directory."""
```

---

### FILE 7: `sailor/phase2/harness_refiner.py`

Implement class `HarnessRefiner`.

Manages the compile-execute-refine feedback loop (Algorithm 1, else branch).

```python
class HarnessRefiner:
    def __init__(
        self,
        config: Phase2Config,
        spec: VulnerabilitySpec,
        compile_diagnoser: CompileDiagnoser,
        se_diagnoser: SEDiagnoser,
    ): ...

    def refine(
        self,
        harness: HarnessArtifacts,
        history: list[dict],
        t: int,
        refine_count: int,
    ) -> tuple[HarnessArtifacts, SEDiagnostic, int, int]:
        """
        Execute one iteration of the compile-execute-refine loop.

        1. Compile harness → on failure:
             build augmented CompileDiagnostic
             append to history
             return (harness, None, t+1, refine_count)

        2. Run KLEE → classify outcome:
             BUG_TRIGGERED:
               return (harness, se_diag, t+1, refine_count)
               (caller terminates loop)

             SITE_REACHED:
               refine_count += 1
               if refine_count > R_max: signal LIKELY_FP
               build feedback: "ℓ reached but no bug —
                                tighten klee_assume constraints"
               append to history

             NOT_REACHED:
               build feedback with coverage probe analysis:
                 "Entered: <functions_entered>
                  Missed:  <functions_missed>
                  Fix driver guards or stub return values"
               append to history

        3. Return updated state for next iteration
        """

    def _build_compile_feedback(
        self, diag: CompileDiagnostic
    ) -> dict:
        """Format compile diagnostic as LLM history entry."""

    def _build_se_feedback(
        self, diag: SEDiagnostic
    ) -> dict:
        """
        Format SE diagnostic as LLM history entry.

        For NOT_REACHED: include probe analysis showing
          which functions were/weren't entered.
        For SITE_REACHED: include suggestion to tighten
          klee_assume constraints in driver.
        """
```

---

### FILE 8: `sailor/phase2/pipeline.py`

Implement class `Phase2Pipeline`.

Top-level entry point for Phase 2. Processes a list of VulnerabilitySpecs,
runs them in parallel, and writes results.

```python
@dataclass
class Phase2Config:
    # (defined above — include here)
    ...

class Phase2Pipeline:
    def __init__(self, config: Phase2Config): ...

    def run(
        self,
        specs: list[VulnerabilitySpec],
        max_workers: int = 4,
    ) -> list[Phase2Result]:
        """
        Process all specs using ThreadPoolExecutor.
        Each spec is independent — run in parallel.

        For each spec:
          orchestrator = LLMOrchestrator(config, spec)
          result = orchestrator.run()

        Write results to output_dir/phase2_results.json
        Write summary to output_dir/phase2_summary.json

        Summary format:
        {
          "total": N,
          "bug_triggered": K,
          "site_reached": J,
          "not_reached": M,
          "inconclusive": P,
          "likely_false_positive": Q,
          "by_cwe": { "CWE-120": ..., "CWE-416": ... },
          "timestamp": "<ISO 8601>"
        }
        """

    def run_single(self, spec: VulnerabilitySpec) -> Phase2Result:
        """Run Phase 2 for a single VulnerabilitySpec."""
```

---

### Integration Contract

Phase 2 must integrate cleanly with Phase 1 output:

```python
# In existing pipeline entry point:
from sailor import Phase1Pipeline, Phase2Pipeline, Phase1Config, Phase2Config

# Phase 1
p1_config = Phase1Config(...)
p1_result = Phase1Pipeline(p1_config).run()

# Phase 2
p2_config = Phase2Config(
    project_name=p1_config.project_name,
    project_root=p1_config.project_root,
    output_dir=p1_config.output_dir / "phase2",
    # llm is resolved automatically from environment:
    #   ANTHROPIC_API_OPTION=true  → Claude (claude-sonnet-4-5)
    #   default (unset/false)      → Gemini Flash (gemini-2.0-flash)
    klee_path="/usr/local/bin/klee",
)
p2_results = Phase2Pipeline(p2_config).run(p1_result.specifications)

# Pass bug_triggered results to Phase 3
witnesses = [r.witness for r in p2_results
             if r.outcome == SEOutcome.BUG_TRIGGERED]
```

Phase 2 must NOT:
- Import anything from the existing project (one-way dependency only)
- Assume KLEE is pre-warmed or that bitcode persists between runs
- Call sys.exit() — always raise specific exceptions
- Hardcode LLM model name — receive via Phase2Config

---

### Implementation Rules Specific to Phase 2

```
1. LLM prompt construction is the responsibility of each synthesizer class.
   LLMOrchestrator only manages turns and history — it does NOT build prompts.

2. All LLM calls go through LLMOrchestrator._call_llm() → LLMClient.chat().
   No direct Gemini or Anthropic SDK calls anywhere else in phase2/.
   LLMClient is the single point of provider routing and rate-limit handling.

3. Provider selection is read from environment ONCE at Phase2Config construction
   via LLMClientFactory.from_env(). Never re-read env vars inside a turn loop.

4. LLMRateLimitError from Gemini must NOT consume a turn (t is not incremented).
   The spec is marked inconclusive and logged. Turn budget is preserved.

5. All subprocess calls to clang, llvm-link, klee go through
   CompileDiagnoser and SEDiagnoser respectively.
   No raw subprocess.run("klee ...") calls elsewhere.

6. The four stub granularities (function/branch/loop/type) must all be
   implemented in StubSynthesizer. None may be skipped.

7. CWE-416 exception (free() must call real free()) must be enforced
   in StubSynthesizer._apply_function_level_stubs().

8. klee_warning_once coverage probes must be injected into every
   function in the code slice. SEDiagnoser._parse_coverage_probes()
   depends on their presence for NOT_REACHED diagnosis.

9. Turn budget (T_explore, T_author, T_max, R_max) must be strictly
   enforced by LLMOrchestrator. Never exceed budget silently.
```

---

### Claude Code Task Prompt

```
Read CLAUDE.md, then implement Phase 2 of the Sailor pipeline.

Before writing any code:
1. Confirm Phase 1 is complete and Phase1Result can be loaded
   from output_dir/specifications.json
2. Check that klee, clang, and llvm-link are available
   (run: which klee && klee --version)
3. Confirm required environment variables are set:
   - If ANTHROPIC_API_OPTION=true: verify ANTHROPIC_API_KEY is set
   - Otherwise: verify GEMINI_API_KEY is set
   Install required SDKs if missing:
     pip install google-generativeai   (for Gemini Flash)
     pip install anthropic              (for Claude)

Then implement sailor/phase2/ in this order:
  schemas.py additions (WitnessInput, SEOutcome, etc.)
  → llm_client.py        (LLMClient + LLMClientFactory — implement FIRST)
  → source_explorer.py
  → driver_synthesizer.py
  → stub_synthesizer.py
  → compile_diagnoser.py
  → se_diagnoser.py
  → harness_refiner.py
  → llm_orchestrator.py  (use self.llm_client.chat(), not SDK directly)
  → pipeline.py

After implementation, validate with:
  # Test Gemini Flash (default):
  unset ANTHROPIC_API_OPTION
  Run Phase 2 on one VulnerabilitySpec from Phase 1 output.
  Confirm phase2_summary.json is written to output_dir/phase2/.

  # Test Claude override:
  ANTHROPIC_API_OPTION=true Run Phase 2 on the same spec.
  Confirm the same outputs are produced.

  # Test Gemini rate-limit path (mock):
  Verify LLMRateLimitError is raised after one 60s retry.
  Verify the spec is marked inconclusive without incrementing t.

Do not modify any existing Phase 1 files.
Do not modify the existing SE engine directly — wrap it.
```
