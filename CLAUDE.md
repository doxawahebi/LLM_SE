# CLAUDE.md — Sailor Implementation Guide

> Claude Code must read this file before starting any task.
> This document contains the paper-based specification, design decisions,
> and implementation rules for integrating Sailor into this project.

---

## 1. Project Goal

Sailor is an automated vulnerability discovery pipeline that composes
**Static Analysis (SA) + LLM + Symbolic Execution (SE)** to answer
three questions no single technique can resolve alone:

| Question | Answered By | Method |
|----------|-------------|--------|
| **Where** does the vulnerability reside? | SA | CodeQL pattern matching |
| **How** does execution reach it? | LLM | Harness + stub synthesis |
| **Whether** it is reachable? | SE | Path constraint solving |

```
[Phase 1] Static Analysis
  CodeQL → 34 memory-safety queries → VulnerabilitySpec list
          ↓
[Phase 2] LLM + Symbolic Execution
  LLM synthesizes harness → SE derives path constraints → witness input
          ↓
[Phase 3] Validation
  Concrete replay confirms vulnerability
```

The goal of this project is to implement Sailor Phase 1/2/3 and
integrate them into the existing SE + LLM orchestration codebase.

---

## 2. Existing Project Structure

> ⚠️ PLACEHOLDER — Claude Code: run `tree -L 3` at project root,
> analyze imports, then fill in this section before any implementation.
> Do not modify any existing files until this section is complete.


---

## 3. Sailor Implementation Specification

### 3.1 Module Structure



---

### 3.2 Phase 1: Static Analysis

Detailed implementation specifications are in CLAUDE_phase1.md.

---

### 3.3 Phase 2: LLM + Symbolic Execution

Detailed implementation specifications are in CLAUDE_phase2.md.


---

### 3.4 Phase 3: Validation

Detailed implementation specifications are in CLAUDE_phase3.md.

---

## 4. Implementation Rules

### Absolute Rules — Never Violate

```
1. All CodeQL CLI calls MUST go through CodeQLRunner.
   Direct subprocess calls to `codeql` anywhere else are forbidden.

2. All data models MUST be defined as Pydantic v2 BaseModel subclasses.
   Do not use plain dict, dataclass, or namedtuple as data contracts.

3. Never modify existing SE engine files directly.
   Always extend via inheritance or wrapper classes.

4. Never call sys.exit(). Always raise specific, descriptive exceptions.

5. Each Phase pipeline must be independently executable.
   Phase1Pipeline.run() serializes output to JSON.
   Phase2Pipeline can load that JSON and run without Phase 1.

6. Never break the integration contract:
   sailor/ must not import anything from the existing project.
   Dependency direction: existing project → sailor (one-way only).
```

### Code Style

```
Language     : Python 3.11+
Type hints   : mandatory on every function signature
Docstrings   : Google style on all classes and public methods
Parallelism  : concurrent.futures.ThreadPoolExecutor
Logging      : logging module, logger name = "sailor.<module_name>"
Dependencies : pydantic>=2.0 + Python stdlib only
               (subprocess, re, json, pathlib, logging,
                concurrent.futures, dataclasses, typing)
```

---

## 5. Task Execution Order

Each session is triggered independently by the user.
Claude Code must:
- Apply ALL rules defined in this CLAUDE.md
- Execute ONLY the session specified in the prompt
- Read the spec file referenced in that session

---

### Session 1 — Project Analysis & Cleanup

Step 0. Read CLAUDE.md in full. (Always first.)

Step 1. Analyze existing project structure.
        → Run: tree -L 3
        → Run: import analysis to detect dead code and duplicates
        → Fill in Section 2 [TODO] placeholders
        → Output a cleanup report. Do NOT touch any files yet.
        → Wait for confirmation before proceeding.

Step 2. Clean up duplicates and dead code.
        → Create a git commit before making any changes.
        → Execute the cleanup.

---

### Session 2 — Phase 1 Implementation

Step 0. Read CLAUDE.md in full. (Always first.)

Step 1. Read CLAUDE_phase1.md in full.

Step 2. Implement sailor/phase1/ in this order:
        schemas.py
        → wrapper.py
        → queries.py  (all 21 custom .ql source strings included)
        → fact_generation.py
        → fact_enrichment.py
        → spec_generation.py
        → pipeline.py

Step 3. Integrate Phase 1 with existing codebase.
        → Wire Phase1Pipeline into the existing entry point.
        → Extend (never modify) existing components.

Step 4. Validate Phase 1 end-to-end.
        → Run Phase 1 against a sample C/C++ project.
        → Confirm phase1_summary.json is produced correctly.

---

### Session 3 — Phase 2 Implementation

Step 0. Read CLAUDE.md in full. (Always first.)

Step 1. Read CLAUDE_phase2.md in full.

Step 2. Confirm Phase 1 output is available.
        → Check output_dir/specifications.json exists.
        → Verify klee, clang, llvm-link are available.

Step 3. Implement sailor/phase2/ in this order:
        schemas.py additions
        → source_explorer.py
        → driver_synthesizer.py
        → stub_synthesizer.py
        → compile_diagnoser.py
        → se_diagnoser.py
        → harness_refiner.py
        → llm_orchestrator.py
        → pipeline.py

Step 4. Integrate Phase 2 with existing codebase.
        → Wire Phase2Pipeline to receive Phase1Result.
        → Extend (never modify) existing LLM/SE components.

Step 5. Validate Phase 2 end-to-end.
        → Run Phase 2 on one VulnerabilitySpec from Phase 1 output.
        → Confirm phase2_summary.json is written correctly.
        → Verify at least one outcome is produced:
          bug_triggered | site_reached | not_reached

---

### Session 4 — Phase 3 Implementation

Step 0. Read CLAUDE.md in full. (Always first.)

Step 1. Read CLAUDE_phase3.md in full.

Step 2. Confirm Phase 2 output is available.
        → Check output_dir/phase2/phase2_results.json exists.
        → Confirm at least one result has outcome == "bug_triggered".

Step 3. Verify ASan toolchain is available.
        → Run: clang --version
        → Run: echo '#include <sanitizer/asan_interface.h>' | clang -x c -fsanitize=address -
        → Locate one .ktest file from Phase 2 output to confirm binary parsing is feasible.

Step 4. Implement sailor/phase3/ in this order:
        schemas.py additions (ValidationResult, ASanReport, etc.)
        → replay_driver_gen.py
        → asan_compiler.py
        → concrete_executor.py
        → result_classifier.py
        → pipeline.py

Step 5. Integrate Phase 3 with existing codebase.
        → Wire Phase3Pipeline to receive Phase2Result list.
        → Do not modify any Phase 1 or Phase 2 files.

Step 6. Validate Phase 3 end-to-end.
        → Run Phase 3 on Phase 2 output.
        → Confirm phase3_summary.json is written to output_dir/phase3/.
        → If a CONFIRMED result exists, verify verified_bug.json
          matches the schema defined in CLAUDE_phase3.md.


---

### Session 5 — Evaluation Framework Implementation

Step 0. Read CLAUDE.md in full. (Always first.)

Step 1. Read CLAUDE_evaluation.md in full.

Step 2. Confirm Phases 1, 2, 3 are implemented.
        → Check sailor/phase1/pipeline.py exists.
        → Check sailor/phase2/pipeline.py exists.
        → Check sailor/phase3/pipeline.py exists.

Step 3. Verify infrastructure is available.
        → Run: docker --version
        → Run: python3 -c "import sqlite3; print(sqlite3.sqlite_version)"
        → Run: python3 -c "from sailor.phase1.pipeline import Phase1Pipeline; print('OK')"

Step 4. Implement sailor/evaluation/ in this order:
        schemas.py additions (CVERecord, CVEEvaluationResult, etc.)
        → db.py
        → dataset.py
        → environment.py
        → metrics.py
        → report.py
        → pipeline.py

Step 5. Integrate evaluation framework with existing codebase.
        → Wire EvaluationPipeline to call Phase1Pipeline, Phase2Pipeline, Phase3Pipeline.
        → Do not modify any Phase 1, 2, or 3 files.

Step 6. Validate evaluation framework end-to-end.
        → Initialize DB and load INITIAL_DATASET (1 CVE).
        → Run EvaluationPipeline for the single CVE.
        → Confirm evaluation.db is created and populated.
        → Confirm evaluation_report.md is generated in output_dir/evaluation/.
        → Interrupt mid-run, re-run, and verify DB checkpoint
          prevents already-completed phases from re-executing.
        → Only use CVE-2025-11494 for this session's test.

---

## Session 6 — Primary Pipeline Test (CVE-2025-11494)

Step 0. Read CLAUDE.md in full. (Always first.)

Step 1. Read CLAUDE_cve_2025_11494.md in full.

Step 2. Execute the Claude Code Task Prompt defined in CLAUDE_cve_2025_11494.md.

---

## 6. Reference Paper

- **Title**: "Guiding Symbolic Execution with Static Analysis and LLMs
  for Vulnerability Discovery"
- **System**: Sailor
- **Core Insight**: SA answers *where*, LLM answers *how*,
  SE answers *whether* — composing all three resolves what no
  single technique can handle alone.
- **Validated On**: GNU Binutils (1.84M lines)
  — discovered zero-day CWE-122 heap-based buffer overflow
  at `elfxx-x86.c:2699` (`memcpy` with unchecked `size` argument)

## 7. Phase Implementation Specs

Detailed implementation specifications are in separate files.
Claude Code: read the relevant file when implementing each phase.

| Phase | Spec File | Status |
|-------|-----------|--------|
| Phase 1 | CLAUDE_phase1.md | ✅ Ready |
| Phase 2 | CLAUDE_phase2.md | ✅ Ready |
| Phase 3 | CLAUDE_phase3.md | ✅ Ready |
