# sailor — Vulnerability Discovery Pipeline Package

`sailor` is the core Python package implementing the three-phase automated
vulnerability discovery pipeline: Static Analysis → LLM Symbolic Execution
→ Concrete Validation.

---

## Package Structure

```
sailor/
├── infra/               Infrastructure: Docker lifecycle + Celery tasks
│   ├── docker_runner.py     DockerRunner — all Phase execution
│   ├── celery_tasks.py      Phase 1/2/3 Celery task definitions
│   └── celery_config.py     Broker + backend configuration
│
├── codeql/              CodeQL integration
│   ├── queries.py           34 memory-safety query definitions + .ql sources
│   └── wrapper.py           CodeQLRunner (called inside runner container)
│
├── models/              Data contracts
│   └── schemas.py           All Pydantic v2 models (single source of truth)
│
├── phase1/              Static Analysis phase
│   ├── fact_generation.py   FactGenerator — invokes CodeQLRunner, parses SARIF
│   ├── fact_enrichment.py   FactEnricher — 5 regex extractors
│   ├── spec_generation.py   SpecificationGenerator — emits VulnerabilitySpec JSON
│   └── pipeline.py          Phase1Pipeline (entry point)
│
├── phase2/              LLM-Orchestrated Symbolic Execution
│   ├── source_explorer.py   SourceExplorer — LLM tool calls for source reading
│   ├── driver_synthesizer.py  DriverSynthesizer — generates driver.c
│   ├── stub_synthesizer.py    StubSynthesizer — 4 granularities
│   ├── compile_diagnoser.py   CompileDiagnoser → runner.compile_harness()
│   ├── se_diagnoser.py        SEDiagnoser → runner.run_klee()
│   ├── harness_refiner.py     HarnessRefiner — LLM-driven repair loop
│   ├── llm_orchestrator.py    LLMOrchestrator — Algorithm 1 from paper
│   ├── mock_llm_client.py     MockLLMClient (E2E tests only)
│   └── pipeline.py            Phase2Pipeline (entry point)
│
├── phase3/              Concrete Validation
│   ├── replay_driver_gen.py   ReplayDriverGenerator — klee_make_symbolic → memcpy
│   ├── asan_compiler.py       ASanCompiler → runner.build_asan_archive()
│   ├── concrete_executor.py   ConcreteExecutor → runner.run_asan_replay()
│   ├── result_classifier.py   ResultClassifier — confirms ASan frame in source
│   └── pipeline.py            Phase3Pipeline (entry point)
│
└── evaluation/          Batch CVE evaluation framework
    ├── dataset.py           CVERecord + CVEDataset
    ├── db.py                EvaluationDB (SQLite)
    ├── metrics.py           MetricsCalculator
    ├── report.py            ReportGenerator
    └── pipeline.py          EvaluationPipeline
```

---

## Execution Model

**All heavy tool invocations run inside Docker containers — never on the host.**

```
HOST (Python process)                 DOCKER (runner container)
─────────────────────────────────     ─────────────────────────
DockerRunner.start()           ──►   container starts
DockerRunner.setup_target()    ──►   git clone + build
DockerRunner.run_phase1()      ──►   codeql database create
                                      codeql analyze
DockerRunner.compile_harness() ──►   clang -emit-llvm + llvm-link
DockerRunner.run_klee()        ──►   klee --posix-runtime ...
DockerRunner.build_asan_archive() ►  clang -fsanitize=address
DockerRunner.run_asan_replay() ──►   ./replay_driver
DockerRunner.stop()            ──►   container removed (always)
```

The `DockerRunner` must always be used inside a `try/finally` block:

```python
runner = DockerRunner(cve_id="CVE-2025-11494", config=RunnerConfig())
try:
    runner.start()
    runner.setup_target(repo_url=..., build_command=...)
    sarif = runner.run_phase1(query_suite=...)
    # ... phases 2 and 3
finally:
    runner.stop()   # ALWAYS — containers must not be left running
```

---

## Phase 1: Static Analysis

```
Input:  C/C++ project (git URL or source directory)
Output: List[VulnerabilitySpec]  (JSON, one per candidate site)

Stages:
  FactGenerator        Runs 34 CodeQL memory-safety queries inside runner container.
                       Parses SARIF output into raw CodeQLFact objects.

  FactEnricher         Applies 5 regex extractors to each fact's code snippet:
                         - pointer variables
                         - length variables
                         - suspect function calls
                         - bounds hints
                         - build context (include paths, defines)

  SpecificationGenerator
                       Filters out test/bench/fuzz/main functions and paths.
                       Produces one VulnerabilitySpec JSON per remaining site.
                       Attaches assertion template based on CWE class.
```

**VulnerabilitySpec (Phase 1 → Phase 2 interface):**
```json
{
  "rule_id":            "local/cpp/cwe-120-overflow",
  "file":               "bfd/elfxx-x86.c",
  "line":               2699,
  "message":            "CWE-120: Buffer Overflow via memcpy (unchecked length).",
  "snippet":            "memcpy(htab->..->contents, ..eh_frame_plt, ..->size);",
  "suspect_calls":      ["memcpy"],
  "pointer_vars":       ["contents", "eh_frame_plt"],
  "length_vars":        ["size"],
  "build_context":      {"include_paths": ["-Ibfd"], "defines": []},
  "entrypoint":         "LLM_INFER",
  "assertion_template": "n <= min(len(dst), len(src))"
}
```

**Independent execution:**
```python
from sailor.phase1.pipeline import Phase1Pipeline

pipeline = Phase1Pipeline(cve_id="my-cve", runner=runner)
specs: list[VulnerabilitySpec] = pipeline.run()
pipeline.save_json("/data/output/my-cve/specs.json")
```

---

## Phase 2: LLM-Orchestrated Symbolic Execution

```
Input:  VulnerabilitySpec
Output: one of:
          bug_triggered          →  .ktest witness files  →  Phase 3
          inconclusive           →  T_max (60) turns exhausted
          likely_false_positive  →  site reached, no bug, R_max (15) hit
```

**Algorithm 1 — LLMOrchestrator:**

```
1. SourceExplorer  (up to T_explore=8 turns)
   LLM reads source files via tool calls to build:
     - call chain from entrypoint to vulnerability site
     - struct field layouts
     - guard conditions (assumes / negations)

2. DriverSynthesizer + StubSynthesizer
   LLM generates:
     driver.c   — main(), klee_make_symbolic(), klee_assume guards
     slice.c    — self-contained call chain with stubs:
                    fn-level:     off-path callees → symbolic-return stubs
                    branch-level: off-path if blocks → if(0)
                    loop-level:   loops enclosing site → if(1)
                    type-level:   project structs → fields accessed only

3. Refinement loop  (up to T_max=60 total turns, R_max=15 after site reached)
   repeat:
     compile_diagnoser  →  clang + llvm-link inside runner
         if error: LLM repairs compile error
     se_diagnoser       →  klee inside runner (T_klee=300s per run)
         if bug_triggered: return .ktest files
         if site_reached:  R_max countdown starts
         if warnings:      LLM adjusts assumptions
   until T_max or outcome determined
```

**Independent execution:**
```python
from sailor.phase2.pipeline import Phase2Pipeline

pipeline = Phase2Pipeline.from_spec_json("specs.json", runner=runner)
result = pipeline.run()   # returns Phase2Result
```

---

## Phase 3: Concrete Validation

```
Input:  Phase2Result (containing .ktest witness file paths)
Output: VerifiedBug  (confirmed) or Phase3Result with verdict=REJECTED
```

**Steps:**

```
ReplayDriverGenerator
    Reads driver.c and slice.c from Phase 2.
    Rewrites every klee_make_symbolic(ptr, n, name) call to:
      memcpy(ptr, witness_bytes[name], n)
    Produces replay_driver.c that feeds concrete witness inputs.

ASanCompiler
    Compiles unmodified project source with -fsanitize=address → libproject.a
    Links replay_driver.c against libproject.a → replay_driver binary
    All compilation runs inside runner container.

ConcreteExecutor
    Executes replay_driver inside runner container.
    Captures stdout + stderr (ASan report).

ResultClassifier
    Confirms if at least one ASan stack frame maps to a file inside
    the project's own source tree.
    Frames in driver.c, stubs.c, or system libraries → not confirmed.
    Narrows CWE: "heap-buffer-overflow" → CWE-122, "stack-buffer-overflow" → CWE-121.
```

**Output — verified_bug.json:**
```json
{
  "verdict":   "CONFIRMED",
  "cwe":       "CWE-122",
  "file":      "bfd/elfxx-x86.c",
  "line":      2286,
  "func":      "_bfd_x86_elf_late_size_sections",
  "asan_type": "heap-buffer-overflow",
  "inputs":    [{"copy_size": 17}, {"dst_bytes": 16}]
}
```

**Independent execution:**
```python
from sailor.phase3.pipeline import Phase3Pipeline

pipeline = Phase3Pipeline.from_phase2_result("phase2_result.json", runner=runner)
result = pipeline.run()
```

---

## LLM Provider

Phase 2 uses an LLM for source exploration and harness synthesis. The provider is resolved at runtime from environment variables — never hardcoded:

```python
from sailor.phase2.llm_orchestrator import LLMClientFactory

client = LLMClientFactory.from_env()
# ANTHROPIC_API_OPTION unset / "false"  →  Gemini Flash (gemini-2.0-flash)
# ANTHROPIC_API_OPTION=true             →  Claude (claude-sonnet-4-5)
```

---

## Data Models

All data contracts are Pydantic v2 `BaseModel` in `sailor/models/schemas.py`. No plain `dict`, `dataclass`, or `namedtuple` is used as a data contract between phases.

Key models:
- `VulnerabilitySpec` — Phase 1 output / Phase 2 input
- `Phase1Result` — list of specs + metadata
- `HarnessH` — driver + slice + stubs + assertions
- `Phase2Result` — outcome, ktest paths, turn log
- `Phase3Result` / `VerifiedBug` — ASan verdict + concrete inputs

---

## CodeQL Queries

34 memory-safety queries are defined in `sailor/codeql/queries.py`, covering:

| CWE | Class |
|-----|-------|
| CWE-120, 121, 122 | Buffer overflow (generic, stack, heap) |
| CWE-125, 787 | Out-of-bounds read/write |
| CWE-415, 416 | Double-free, use-after-free |
| CWE-476 | Null pointer dereference |
| CWE-190 | Integer overflow |
| CWE-562 | Return of local variable address |
| CWE-674 | Uncontrolled recursion |
| CWE-823 | Out-of-range pointer offset |

Custom queries are written to a shared volume via `CodeQLQuerySuite.write_custom_queries()` and run inside the runner container through `CodeQLRunner` — no raw `subprocess` CodeQL calls anywhere else.

---

## Testing

```bash
# Unit tests (test_phase/)
pytest test_phase/ -v

# E2E tests (tests/) — requires runner image
docker build -f docker/Dockerfile.runner -t sailor-runner:latest .
pytest tests/e2e_self_test.py -v
```

E2E workspaces in `tests/e2e_workspace/`:

| Directory | CWE | Vulnerability |
|-----------|-----|---------------|
| `cwe_122/` | CWE-122 | Heap buffer overflow (required) |
| `cwe_121/` | CWE-121 | Stack buffer overflow (required) |
| `cwe_416/` | CWE-416 | Use-after-free (required) |
| `cwe_476/` | CWE-476 | Null pointer dereference (required) |

Each workspace contains `target.c`, `Makefile`, `expected.json`, and pre-generated fixtures (`spec.json`, `witness.ktest`, `mock_llm_turns/`) for deterministic testing without a live LLM.

---

## Coding Conventions

| Rule | Detail |
|------|--------|
| Language | Python 3.11+ |
| Type hints | Mandatory on all function signatures |
| Docstrings | Google style on all public classes and methods |
| Logging | `logging` module; logger name `"sailor.<module>"` |
| Imports | `sailor/` never imports from `core/`, `frontend/`, `main.py` |
| Exceptions | Never `sys.exit()` — always raise specific exceptions |
| Paper alignment | If code contradicts `paper/`, code is wrong — add `# Paper §X.X: <reason>` |


## Reference

Shafiuzzaman, M., Desai, A., Guo, W., & Bultan, T. (2026). Guiding Symbolic Execution with Static Analysis and LLMs for Vulnerability Discovery. arXiv preprint arXiv:2604.06506.
