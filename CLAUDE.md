# CLAUDE.md — Sailor Project Guide

> Claude Code reads this file before every session.
> This file is the single source of truth for project structure,
> rules, and session execution order.

---

## 1. Project Overview

Sailor is an automated vulnerability discovery pipeline that composes
Static Analysis (SA) + LLM + Symbolic Execution (SE).

```
Paper reference files (read when needed, not always):
  paper/paper_overview.md      ← §1~2: system design rationale
  paper/paper_phase1.md        ← §3: Fact Generation/Enrichment/Spec
  paper/paper_phase2.md        ← §4: Driver/Stub/Assertion/Refinement
  paper/paper_phase3.md        ← §5: Concrete Validation

Spec files (product requirements — what to build):
  spec/backend_spec.md              ← API contract, domain model, state machines
  spec/frontend_spec.md             ← UI requirements, routes, component contracts
  spec/e2e_test_spec.md             ← E2E test contracts, workspace layout,
                                       expected.json schema, mock LLM policy
  spec/interactive_control_spec.md  ← User registration, Auto/Manual mode,
                                       per-function interrupts, phase downloads

Design files (implementation decisions — how to build):
  design/CLAUDE_Sessions_prompt.md       ← session definitions + standard last step
  design/CLAUDE_sync_design_from_spec.md ← one-shot: sync all design files to spec
  design/CLAUDE_backend.md              ← FastAPI + Celery implementation guide
  design/CLAUDE_frontend.md             ← React + Vite implementation guide
  design/CLAUDE_phase2.md               ← Phase 2 implementation guide
  design/CLAUDE_phase3.md               ← Phase 3 implementation guide
  design/CLAUDE_evaluation.md           ← Evaluation framework guide
  design/CLAUDE_infra.md                ← Docker + Celery infrastructure guide
  design/CLAUDE_e2e_test.md             ← E2E test implementation guide
  design/cve/CLAUDE_cve_2025_11494.md   ← Primary CVE test (binutils)
  design/cve/CLAUDE_cve_2023_1972.md    ← Secondary CVE test
  design/cve/CLAUDE_cve_2017_13028.md   ← tcpdump CVE test
  design/cve/CLAUDE_tcpdump_pipeline_test.md  ← tcpdump pipeline validation
```

---

## 2. Execution Model

```
LOCAL MACHINE (Claude Code territory):
  sailor/ Python package code
  Docker CLI (build images, manage containers)
  Celery task dispatch
  DB reads / result collection

DOCKER CONTAINER (all Phase execution):
  git clone target source      ← NEVER on local
  apt install dependencies     ← NEVER on local
  make / cmake / configure     ← NEVER on local
  codeql database create       ← NEVER on local (Phase 1)
  codeql analyze               ← NEVER on local (Phase 1)
  clang -emit-llvm + klee      ← NEVER on local (Phase 2)
  clang -fsanitize=address     ← NEVER on local (Phase 3)

CELERY (orchestration):
  run_phase1_task()  ← dispatches Phase 1 to runner container
  run_phase2_task()  ← dispatches Phase 2 to runner container
  run_phase3_task()  ← dispatches Phase 3 to runner container
```

---

## 3. Actual Project Structure

```
.
├── CLAUDE.md                        ← THIS FILE
├── paper/                           ← Paper reference chunks (read-only)
│   ├── paper_overview.md
│   ├── paper_phase1.md
│   ├── paper_phase2.md
│   └── paper_phase3.md
│
├── sailor/                          ← MAIN PACKAGE (authoritative)
│   ├── infra/                       ← Docker + Celery integration (NEW)
│   │   ├── docker_runner.py         ← DockerRunner (all Phase execution)
│   │   ├── celery_tasks.py          ← Phase 1/2/3 Celery task definitions
│   │   └── celery_config.py         ← broker + backend config
│   ├── codeql/
│   │   ├── queries.py               ← 34 query definitions + .ql sources
│   │   └── wrapper.py               ← CodeQLRunner (used inside container)
│   ├── models/
│   │   └── schemas.py               ← ALL Pydantic v2 data models
│   ├── phase1/
│   │   ├── fact_generation.py       ← FactGenerator
│   │   ├── fact_enrichment.py       ← FactEnricher (5 regex extractors)
│   │   ├── spec_generation.py       ← SpecificationGenerator
│   │   └── pipeline.py              ← Phase1Pipeline
│   ├── phase2/
│   │   ├── source_explorer.py       ← SourceExplorer (LLM tool calls)
│   │   ├── driver_synthesizer.py    ← DriverSynthesizer
│   │   ├── stub_synthesizer.py      ← StubSynthesizer (4 granularities)
│   │   ├── compile_diagnoser.py     ← CompileDiagnoser → runner.compile_harness()
│   │   ├── se_diagnoser.py          ← SEDiagnoser → runner.run_klee()
│   │   ├── harness_refiner.py       ← HarnessRefiner
│   │   ├── llm_orchestrator.py      ← LLMOrchestrator (Algorithm 1)
│   │   ├── mock_llm_client.py       ← MockLLMClient (E2E test only)
│   │   └── pipeline.py              ← Phase2Pipeline
│   ├── phase3/
│   │   ├── replay_driver_gen.py     ← ReplayDriverGenerator
│   │   ├── asan_compiler.py         ← ASanCompiler → runner.build_asan_archive()
│   │   ├── concrete_executor.py     ← ConcreteExecutor → runner.run_asan_replay()
│   │   ├── result_classifier.py     ← ResultClassifier
│   │   └── pipeline.py              ← Phase3Pipeline
│   └── evaluation/
│       ├── dataset.py               ← CVERecord + CVEDataset
│       ├── db.py                    ← EvaluationDB (SQLite)
│       ├── environment.py           ← REPLACED by sailor/infra/docker_runner.py
│       ├── metrics.py               ← MetricsCalculator
│       ├── report.py                ← ReportGenerator
│       └── pipeline.py              ← EvaluationPipeline
│
├── docker/                          ← Docker images (NEW)
│   ├── Dockerfile.runner            ← Phase execution image (codeql+klee+clang)
│   ├── Dockerfile.worker            ← Celery worker image
│   └── docker-compose.yml           ← services: redis, postgres, worker, api
│
├── phases/                          ← LEGACY — do not use
├── codeql/                          ← LEGACY — do not use
├── models/                          ← LEGACY — do not use
├── core/                            ← LEGACY — do not use
│
├── test_phase/                      ← Unit tests
│   ├── test_phase1.py
│   ├── test_phase2.py
│   └── test_phase3.py
│
├── tests/                           ← End-to-end tests
│   ├── e2e_self_test.py             ← E2E test runner (rewritten)
│   ├── conftest.py                  ← pytest fixtures (workspace, docker_runner)
│   ├── generate_fixtures.py         ← one-time fixture generation script
│   └── e2e_workspace/               ← minimal C vulnerability targets
│       ├── cwe_122/                 ← heap buffer overflow (required)
│       │   ├── target.c
│       │   ├── Makefile
│       │   ├── expected.json
│       │   ├── README.md
│       │   └── fixtures/
│       │       ├── spec.json
│       │       ├── witness.ktest
│       │       ├── verified_bug.json
│       │       └── mock_llm_turns/
│       ├── cwe_121/                 ← stack buffer overflow (required)
│       ├── cwe_416/                 ← use-after-free (required)
│       └── cwe_476/                 ← null dereference (required)
│
├── frontend/                        ← React web UI
└── main.py
```

---

## 4. Absolute Rules — Never Violate

```
1. sailor/ is the authoritative codebase.
   phases/, codeql/ (root), models/ (root), core/ are LEGACY.
   Never add new code to legacy directories.
   Never import from legacy directories in sailor/ code.

2. ALL Phase execution runs inside Docker containers via DockerRunner.exec().
   NEVER run codeql / klee / clang / make / git clone on the local machine.
   Local machine only: Python logic, Docker CLI calls, DB reads/writes.

3. DockerRunner.stop() MUST be called in a finally block.
   Containers must never be left running after task completion or failure.

4. All Celery tasks are defined in sailor/infra/celery_tasks.py.
   Do NOT use core/celery_app.py or core/workflow.py — LEGACY.

5. All CodeQL CLI calls (inside container) go through CodeQLRunner
   (sailor/codeql/wrapper.py). No raw subprocess codeql calls elsewhere.

6. All data models are Pydantic v2 BaseModel in sailor/models/schemas.py.
   No plain dict, dataclass, or namedtuple as data contracts.

7. Never call sys.exit(). Always raise specific exceptions.

8. Each Phase pipeline is independently executable.
   Phase1Pipeline.run() serializes to JSON.
   Phase2Pipeline loads that JSON and runs without Phase 1.

9. sailor/ does not import from core/, frontend/, or main.py.
   Dependency: core/ → sailor/ (one-way only).

10. When implementation conflicts with paper:
    paper is ground truth → fix the implementation.
    Add comment: # Paper §X.X: <reason>

12. LLM provider selection is controlled by ANTHROPIC_API_OPTION.
    Default (unset or any value other than "true"): Gemini Flash.
    This applies unconditionally — even in production runs.

      ANTHROPIC_API_OPTION unset / "false"  →  Gemini Flash (gemini-2.0-flash)
      ANTHROPIC_API_OPTION=true             →  Claude (claude-sonnet-4-5)

    Never hardcode a provider or model anywhere in the codebase.
    Always resolve via LLMClientFactory.from_env() at runtime.
    If GEMINI_API_KEY is missing and ANTHROPIC_API_OPTION is not "true":
      raise EnvironmentError at startup — do NOT silently fall back to Claude.

13. If you're writing about SSE wire format, you're either editing sse_contract.md or you're doing it wrong.

11. [SYNC_CHECK: ON]

    Spec files and sailor/ code must stay in sync, but neither
    automatically overrides the other. All conflicts require human
    judgment before any file is modified.

    When SYNC_CHECK is OFF: skip all conflict classification and
    drift reporting. Proceed with implementation without checking
    CLAUDE_*.md files for consistency.

    When SYNC_CHECK is ON (current):

    Ground truth hierarchy (highest to lowest):
      1. paper/paper_phase*.md   — paper algorithm; never changes
      2. CLAUDE_*.md             — design decisions; changes only intentionally
      3. sailor/ code            — implementation; may contain bugs

    When sailor/ code conflicts with a CLAUDE_*.md spec file,
    classify the conflict before acting:

      Case A — code is wrong (implementation bug):
        Symptom: CLAUDE_*.md matches paper/, but sailor/ code does not.
        Action:  Fix the code. Do NOT update the spec file.

      Case B — spec is outdated (intentional design change):
        Symptom: code change was deliberate and does not contradict paper/.
        Action:  Update the CLAUDE_*.md file to match the code.
                 Do NOT revert the code.

      Case C — conflict is unclear, or both may be wrong:
        Symptom: cannot determine Case A vs B without human input.
        Action:  Touch NEITHER file.
                 Add a [?] item to CLAUDE_feedback.md and stop.
                 Wait for explicit human decision before proceeding.

    Classification rule:
      If code contradicts paper/         → always Case A (code is wrong).
      If code extends paper/ with a new
        design decision not covered
        by the paper                     → likely Case B (verify with human).
      If unsure which case applies       → always Case C.

    Never resolve a conflict by assuming the code is correct.
    When in doubt, do nothing and report.

    To toggle: change [SYNC_CHECK: ON] to [SYNC_CHECK: OFF] above.
```

---

## 5. Code Style

```
Language:    Python 3.11+
Type hints:  mandatory on all function signatures
Docstrings:  Google style on all public classes and methods
Logging:     logging module, name = "sailor.<module>"
Tests:       test_phase/ for unit, tests/ for e2e
Dependencies: pydantic>=2.0 + stdlib only inside sailor/
              (celery, docker-sdk allowed in sailor/infra/ only)
```

---

## 6. Session Execution Order

Session definitions, step-by-step instructions, and the Standard Last
Step are in **design/CLAUDE_Sessions_prompt.md**.

When executing any session:
  1. Read this CLAUDE.md in full first.
  2. Read design/CLAUDE_Sessions_prompt.md in full.
  3. Find the requested session by name and execute its steps.

When spec/ files change and design/ files need to catch up:
  → "Read CLAUDE.md, then execute design/CLAUDE_sync_design_from_spec.md"
  → This updates CLAUDE_backend.md, CLAUDE_frontend.md, and
    CLAUDE_Sessions_prompt.md in one pass to match all spec/ files.
  → Run this before Session 9 or 10 if spec/ was recently changed.

Available sessions:
  Session 0  — Infrastructure Setup
  Session 1  — Project Analysis, Sync Check & Cleanup
  Session 2  — Phase 1: Test & Refine
  Session 3  — Phase 2: Test & Refine
  Session 4  — Phase 3: Test & Refine
  Session 5  — Evaluation Framework: Test & Refine
  Session 6  — tcpdump Pipeline Validation
  Session 7  — Secondary CVE Test (CVE-2023-1972)
  Session 8  — E2E Test Implementation
  Session 9  — Backend Implementation (FastAPI + Celery)
  Session 10 — Frontend Implementation (React + Vite)

Every session ends with the Standard Last Step defined in
design/CLAUDE_Sessions_prompt.md. Never skip it.

---

## 7. How to Use Paper Files

```
Read paper/paper_phaseN.md ONLY for the phase you are working on.

Session 2 → paper/paper_phase1.md only
Session 3 → paper/paper_phase2.md only
Session 4 → paper/paper_phase3.md only
Sessions 5-7 → paper files only if a specific discrepancy is found

Paper always overrides implementation choices.
```

---

## 8. Known Issues

```
Claude Code appends discovered issues here during sessions.
Format: [Session N] <file>:<func> — <description> — <status>

[x] [Session 3] source_explorer.py:_negate_guard — lstrip("!") before startswith("!") check caused double negation for !expr — FIXED
[x] [Session 3] source_explorer.py:_parse_struct_fields — regex missed "char *name;" syntax (pointer adjacent to name) — FIXED
[x] [Session 3] harness_refiner.py:refine — functions_missed always [] because SEDiagnoser doesn't know call chain — FIXED (pass call_chain kwarg)
[x] [Session 3] llm_orchestrator.py:Phase2Config — docstring said "Gemini model" but implementation uses Anthropic Claude SDK — FIXED
[x] [Session 0] sailor/infra/ created — DockerRunner, celery_tasks, celery_config; Phase 2/3 components delegate to runner — FIXED
[x] [Session 0] sailor/codeql/wrapper.py missing — phase1 imported from deleted legacy codeql/wrapper.py — FIXED (created sailor/codeql/wrapper.py)
[x] [Session 0] docker/Dockerfile.runner — used wrong klee/klee paths; klee base OS needed for solver deps — FIXED (use klee/klee as base image)
[x] [Session 0] docker/Dockerfile.worker — copied non-existent core/ dir — FIXED (removed core/ COPY)
[x] [Session 8] compile_diagnoser.py:_compile_harness — missing /tmp/klee_src/include in container include_paths → klee/klee.h not found — FIXED
[x] [Session 8] concrete_executor.py:execute — used key "output" instead of "asan_output" from run_asan_replay() return dict — FIXED
[x] [Session 8] docker_runner.py:compile_harness — wrote harness files to Docker-root-owned volume path → Permission denied — FIXED (use docker cp from temp dir)
[x] [Session 8] docker_runner.py:run_asan_replay — same root-owned write issue for replay_driver.c — FIXED (use docker cp)
[x] [Session 8] tests/e2e_workspace/cwe_122/target.c — static vulnerable() cannot be linked from replay driver; combined main() causes duplicate symbol — FIXED (remove static, split main into main.c)
```
