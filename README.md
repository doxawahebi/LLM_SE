# SE-LLM-Project

An automated vulnerability discovery pipeline that composes Static Analysis (SA), Large Language Models (LLM), and Symbolic Execution (SE) to find and confirm memory-safety bugs in C/C++ projects.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [AI Tool Utilization Strategy](#3-ai-tool-utilization-strategy)
4. [Execution Method](#4-execution-method)

---

## 1. Project Overview

This project is a pipeline that automates the full lifecycle of vulnerability discovery — from static pattern detection through concrete crash confirmation — without requiring manual harness authoring or expert symbolic-execution knowledge.

**Three-phase approach:**

| Phase | Engine | Input | Output |
|-------|--------|-------|--------|
| Phase 1 | CodeQL (34 memory-safety queries) | C/C++ project source | `VulnerabilitySpec` JSON per candidate site |
| Phase 2 | LLM + KLEE | `VulnerabilitySpec` | `.ktest` witness inputs (or inconclusive) |
| Phase 3 | AddressSanitizer | `.ktest` witness | `verified_bug.json` (confirmed crash) |

**Key design properties:**
- Each phase is independently executable — Phase 2 requires only the JSON output of Phase 1.
- All heavy tool invocations (CodeQL, KLEE, clang, make, git clone) run exclusively inside ephemeral Docker containers. The host machine only runs Python orchestration logic.
- Phase 2 specs are independent of each other and can be processed in parallel.

---

## 2. System Architecture

### 2.1 Sailor Pipeline (Internal)

```
Input: C/C++ project source (zip or git URL)
                        │
                        ▼
┌────────────────────────────────────────────────────────────────┐
│  PHASE 1 — Static Analysis                                     │
│                                                                │
│   FactGenerator        ──────► CodeQL (34 queries, in Docker) │
│        │  raw SARIF findings                                   │
│        ▼                                                       │
│   FactEnricher         ──────► 5 regex extractors             │
│        │  pointer_vars, length_vars, suspect_calls, ...       │
│        ▼                                                       │
│   SpecificationGenerator ────► VulnerabilitySpec (JSON)       │
│        │  one spec per candidate site                          │
│        │  filtered: test/bench/fuzz/main excluded              │
└────────┼───────────────────────────────────────────────────────┘
         │   List<VulnerabilitySpec>   (independent, parallelizable)
         ▼
┌────────────────────────────────────────────────────────────────┐
│  PHASE 2 — LLM-Orchestrated Symbolic Execution (per spec)     │
│                                                                │
│   SourceExplorer    ──► LLM tool calls  (T_explore ≤ 8)      │
│        │  call chain, struct layouts, guards                   │
│        ▼                                                       │
│   DriverSynthesizer ──► LLM generates driver.c + slice.c     │
│   StubSynthesizer   ──► 4 granularities (fn/branch/loop/type)│
│        │                                                       │
│   ╔══════════════════════════════════════╗                    │
│   ║  Refinement Loop (T_max ≤ 60 turns) ║                    │
│   ║                                      ║                    │
│   ║  compile_diagnoser ──► clang (Docker)║                    │
│   ║        │  compiler diagnostics        ║                    │
│   ║        ▼                              ║                    │
│   ║  se_diagnoser      ──► KLEE (Docker) ║                    │
│   ║        │  .ktest / KLEE warnings      ║                    │
│   ║        ▼                              ║                    │
│   ║  HarnessRefiner    ──► LLM refines   ║                    │
│   ╚══════════════════════════════════════╝                    │
│        │                                                       │
│        ├─ bug_triggered  ──────────────────────► Phase 3      │
│        ├─ inconclusive   (T_max exhausted)                    │
│        └─ likely_false_positive (R_max ≤ 15 hit)             │
└────────────────────────────────────────────────────────────────┘
         │   .ktest witness inputs
         ▼
┌────────────────────────────────────────────────────────────────┐
│  PHASE 3 — Concrete Validation                                 │
│                                                                │
│   ReplayDriverGenerator ──► rewrites klee_make_symbolic →     │
│                              memcpy of witness bytes           │
│   ASanCompiler          ──► clang -fsanitize=address (Docker) │
│   ConcreteExecutor      ──► runs replay binary (Docker)       │
│   ResultClassifier      ──► at least one ASan frame in source │
│                                                                │
│   Output: verified_bug.json  (verdict, CWE, file, line, func) │
└────────────────────────────────────────────────────────────────┘
```

### 2.2 Overall System Design (Client → Server → Worker)

```
                     ┌─────────────────────────────────────────┐
                     │          CLIENT (Browser)               │
                     │   React + Vite   :3000                  │
                     │                                         │
                     │  Upload zip ──► Dashboard ──► Spec view │
                     │  Real-time SSE progress stream          │
                     └───────────────┬─────────────────────────┘
                                     │ HTTP REST
                                     │ GET /runs  POST /runs/:id/start
                                     │ SSE /runs/:id/stream
                                     ▼
                     ┌─────────────────────────────────────────┐
                     │          API SERVICE (FastAPI)          │
                     │              :8000                      │
                     │                                         │
                     │  Validates requests                     │
                     │  Mutates State Store (Postgres)         │
                     │  Enqueues tasks → Celery (via Redis)    │
                     │  Fans out SSE events to connected UIs   │
                     └───────────────┬─────────────────────────┘
                                     │ Celery task dispatch
                                     │ (Redis broker)
                                     ▼
                     ┌─────────────────────────────────────────┐
                     │       CELERY WORKER                     │
                     │  (sailor package + backend tasks)       │
                     │                                         │
                     │  run_phase1_task() ──────────────┐      │
                     │  run_phase2_task() ──────────────┤      │
                     │  run_phase3_task() ──────────────┘      │
                     │              │ docker exec               │
                     │              ▼                          │
                     │  ┌───────────────────────────────────┐  │
                     │  │  RUNNER (ephemeral, per-spec)     │  │
                     │  │  ubuntu + CodeQL + KLEE + clang   │  │
                     │  │                                   │  │
                     │  │  Phase 1: codeql database create  │  │
                     │  │           codeql analyze          │  │
                     │  │  Phase 2: clang -emit-llvm        │  │
                     │  │           llvm-link + klee        │  │
                     │  │  Phase 3: clang -fsanitize=address│  │
                     │  │           ./replay_driver         │  │
                     │  │                                   │  │
                     │  │  Auto-removed on task completion  │  │
                     │  └───────────────────────────────────┘  │
                     └───────────────┬─────────────────────────┘
                                     │ reads / writes
                        ┌────────────┼────────────┐
                        ▼            ▼            ▼
                  ┌──────────┐ ┌──────────┐ ┌──────────┐
                  │  Redis   │ │ Postgres │ │  MinIO   │
                  │  :6379   │ │  :5432   │ │  :9000   │
                  │  broker  │ │  state   │ │artifacts │
                  │  events  │ │  store   │ │  store   │
                  └──────────┘ └──────────┘ └──────────┘
```

**Data flow summary:**

1. User uploads a project zip through the React UI.
2. FastAPI records the run in Postgres and enqueues a Phase 1 task to Redis.
3. Celery worker picks up the task; `DockerRunner` starts an ephemeral runner container.
4. Runner executes CodeQL inside the container and writes SARIF + specs to shared volumes.
5. Worker reads specs, enqueues one Phase 2 task per spec.
6. Each Phase 2 task enters the LLM refinement loop; progress events flow through Redis to SSE consumers.
7. Specs that produce a `.ktest` witness proceed to Phase 3 (ASan replay inside runner).
8. Final `verified_bug.json` is stored in MinIO; Postgres verdict is updated; UI reflects confirmed bugs.

---

## 3. AI Tool Utilization Strategy

This project was developed using **Claude Code** (Anthropic) as the primary AI engineering assistant. The development followed a structured, spec-first workflow with AI assistance at every layer.

### 3.1 Development Workflow

```
1. Write spec files (spec/)
        │
        │  Human authors formal product requirements:
        │  - API contracts, domain models, state machines (backend_spec.md)
        │  - UI routes, component contracts (frontend_spec.md)
        │  - E2E test contracts, workspace layout (e2e_test_spec.md)
        │  - Interactive control, per-function interrupts (interactive_control_spec.md)
        │
        ▼
2. AI reads spec → writes design files (design/)
        │
        │  Claude Code reads each spec file in full, then produces
        │  detailed implementation guides in design/CLAUDE_*.md:
        │
        │  spec/backend_spec.md     → design/CLAUDE_backend.md
        │  spec/frontend_spec.md    → design/CLAUDE_frontend.md
        │  spec/e2e_test_spec.md    → design/CLAUDE_e2e_test.md
        │  paper/paper_phase*.md    → design/CLAUDE_phase*.md
        │                             design/CLAUDE_infra.md
        │
        │  Design files contain: class signatures, method contracts,
        │  data flow, error handling strategy, Dockerfile specs,
        │  and cross-file consistency rules.
        │
        ▼
3. AI implements from design files (sailor/, backend/, frontend/, docker/)
        │
        │  Claude Code reads the relevant CLAUDE_*.md design file,
        │  then writes the actual implementation into the codebase.
        │  Implementation must match the design; conflicts are flagged.
        │
```

### 3.2 Prompting Log

All interactions with Claude Code followed **session-based prompting** defined in `design/CLAUDE_Sessions_prompt.md`. Each session has a fixed trigger phrase and numbered steps.

| Session | Trigger phrase | Scope |
|---------|---------------|-------|
| Session 0 | `Read CLAUDE.md and execute Session 0.` | Infrastructure: Docker, Celery, Redis, Postgres |
| Session 1 | `Read CLAUDE.md and execute Session 1.` | Sync check, cleanup, spec drift repair |
| Session 2 | `Read CLAUDE.md and execute Session 2.` | Phase 1: FactGenerator, FactEnricher, SpecGenerator |
| Session 3 | `Read CLAUDE.md and execute Session 3.` | Phase 2: SourceExplorer, LLMOrchestrator, HarnessRefiner |
| Session 4 | `Read CLAUDE.md and execute Session 4.` | Phase 3: ReplayDriver, ASanCompiler, ResultClassifier |
| Session 5 | `Read CLAUDE.md and execute Session 5.` | Evaluation framework: CVEDataset, EvaluationDB, metrics |
| Session 6 | `Read CLAUDE.md and execute Session 6.` | tcpdump pipeline validation (CVE-2017-13028) |
| Session 7 | `Read CLAUDE.md and execute Session 7.` | Secondary CVE test (CVE-2023-1972) |
| Session 8 | `Read CLAUDE.md and execute Session 8.` | E2E test suite: CWE-121/122/416/476 workspaces |
| Session 9 | `Read CLAUDE.md and execute Session 9.` | Backend: FastAPI routes, Celery tasks, SSE |
| Session 10 | `Read CLAUDE.md and execute Session 10.` | Frontend: React + Vite, real-time dashboard |

**Sync session** (run before Session 9 or 10 whenever spec files change):

```
Read CLAUDE.md, then execute design/CLAUDE_sync_design_from_spec.md
```

This one-shot command updates all `CLAUDE_*.md` design files to match current `spec/` files, ensuring the AI implements from up-to-date requirements.

### 3.3 Ground Truth Hierarchy

The AI enforces a strict hierarchy when implementation conflicts with specifications:

```
paper/paper_phase*.md    (highest — research algorithm, never changes)
       ↓
design/CLAUDE_*.md       (design decisions — change only intentionally)
       ↓
sailor/ code             (implementation — may contain bugs)
```

When a conflict is found, it is classified before any file is modified:
- **Case A** (code is wrong): fix the code, leave the spec.
- **Case B** (spec is outdated): update the spec, leave the code.
- **Case C** (unclear): touch neither; add a `[?]` item to `CLAUDE_feedback.md` and wait for human decision.

### 3.4 LLM Provider Selection

The LLM used for Phase 2 harness synthesis is resolved at runtime via environment variable:

```
ANTHROPIC_API_OPTION unset / "false"  →  Gemini Flash (gemini-2.0-flash)  [default]
ANTHROPIC_API_OPTION=true             →  Claude (claude-sonnet-4-5)
```

This is enforced by `LLMClientFactory.from_env()` — no provider or model is ever hardcoded.

---

## 4. Execution Method

### 4.1 Prerequisites

- Docker 24+ with Compose v2 (`docker compose` subcommand)
- 16 GB RAM recommended (KLEE is memory-intensive)
- API key for either Gemini (`GEMINI_API_KEY`) or Anthropic (`ANTHROPIC_API_KEY`)

### 4.2 Environment Setup

```bash
cp .env.example .env
# Edit .env and fill in:
#   DB_PASSWORD        — Postgres password
#   JWT_SECRET         — random secret for session tokens
#   MINIO_ROOT_USER    — MinIO admin user
#   MINIO_ROOT_PASSWORD — MinIO admin password
#   GEMINI_API_KEY     — required unless ANTHROPIC_API_OPTION=true
#   ANTHROPIC_API_KEY  — required if ANTHROPIC_API_OPTION=true
```

### 4.3 Build and Start All Services

```bash
docker compose up -d
```

This starts:
- `frontend`  — React UI at http://localhost:3000
- `backend`   — FastAPI at http://localhost:8000
- `worker`    — Celery worker (processes pipeline tasks)
- `redis`     — Message broker + event bus
- `postgres`  — State store
- `minio`     — Artifact store at http://localhost:9001

### 4.4 Run the Pipeline via UI

1. Open http://localhost:3000
2. Click **New Run**, upload a `.zip` of a C/C++ project.
3. Optionally configure CodeQL query suite, Phase 2 budgets, parallelism.
4. Click **Start** — watch specs flow through Phase 1 → 2 → 3 in real time.
5. Download `verified_bug.json` from any confirmed finding.

### 4.5 Run via API

```bash
# Create and start a run
curl -X POST http://localhost:8000/runs \
  -F "name=my-project" \
  -F "zip=@/path/to/project.zip"

# Stream progress (SSE)
curl http://localhost:8000/runs/{run_id}/stream

# List results
curl http://localhost:8000/runs/{run_id}/specs
```

### 4.6 Run E2E Tests

The E2E test suite validates the full pipeline against four synthetic CWE workspaces (heap overflow, stack overflow, use-after-free, null dereference):

```bash
# Requires runner image to be built first
docker build -f docker/Dockerfile.runner -t sailor-runner:latest .

# Run E2E tests with mock LLM (no API key needed)
pytest tests/e2e_self_test.py -v
```

### 4.7 Run Unit Tests

```bash
pytest test_phase/ -v
```

### 4.8 Run Sailor Pipeline Directly (without web UI)

Each phase pipeline is independently executable from Python:

```bash
# Phase 1 only
python -c "
from sailor.phase1.pipeline import Phase1Pipeline
result = Phase1Pipeline(cve_id='my-cve', runner=runner).run()
"

# Phase 2 using Phase 1 output JSON
python -c "
from sailor.phase2.pipeline import Phase2Pipeline
Phase2Pipeline.from_spec_json('spec.json', runner=runner).run()
"
```

### 4.9 Stop All Services

```bash
docker compose down
# To also remove volumes (deletes all data):
docker compose down -v
```

---

## Project Structure

```
.
├── spec/                 Product requirements (what to build)
├── design/               Implementation guides (how to build)
├── paper/                Research paper reference (algorithm ground truth)
├── sailor/               Main Python package (pipeline implementation)
│   ├── infra/            DockerRunner + Celery tasks + config
│   ├── codeql/           CodeQLRunner + 34 query definitions
│   ├── models/           Pydantic v2 data models (single source of truth)
│   ├── phase1/           Fact generation, enrichment, spec generation
│   ├── phase2/           LLM orchestration, harness synthesis, SE
│   └── phase3/           ASan replay, result classification
├── backend/              FastAPI application
├── frontend/             React + Vite UI
├── docker/               Dockerfile.runner + Dockerfile.worker
├── docker-compose.yml    Single entry point for all services
├── test_phase/           Unit tests
└── tests/                E2E tests + CWE workspaces
```

See [sailor/README.md](sailor/README.md) for the Sailor package internals.

## Reference
---
Shafiuzzaman, M., Desai, A., Guo, W., & Bultan, T. (2026). Guiding Symbolic Execution with Static Analysis and LLMs for Vulnerability Discovery. arXiv preprint arXiv:2604.06506.