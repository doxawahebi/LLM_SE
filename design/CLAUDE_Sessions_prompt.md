# CLAUDE_Sessions_prompt.md — Session Definitions

> This file is referenced by CLAUDE.md Section 6.
> Claude Code reads this file automatically when executing any session.
> All Absolute Rules defined in CLAUDE.md apply in full.

---

## Standard Last Step (apply to EVERY session without exception)

After completing all session-specific steps, always run this last:

```
Check CLAUDE.md Rule 11:
  If [SYNC_CHECK: OFF] → skip feedback entry. Done.
  If [SYNC_CHECK: ON]  → append a feedback entry to CLAUDE_feedback.md:

  ## [Session N] <ISO 8601 timestamp>

  ### Files modified in sailor/
  - <file>: <what changed> (e.g. Phase2Config: added llm: LLMClient field)

  ### Spec files that need update
  - [ ] [B] CLAUDE_phase2.md: Phase2Config.llm_model → now llm: LLMClient
  - [?]     CLAUDE_phase1.md: FactEnricher window ±10 vs spec ±20 — unclear

  ### Spec files verified accurate
  - [ok] CLAUDE_phase3.md: ResultClassifier — matches code and paper

  ### Code that needs fix (Case A)
  - [ ] sailor/phase2/llm_orchestrator.py: off-by-one in turn budget
        paper §4 says t < T_max; code exits at T_max - 1

Do NOT modify any CLAUDE_*.md spec files here.
Spec file updates happen only in Session 1 Step 3.
Code fixes from [A] items happen only in Session 1 Step 4.
```

---

## Session 0 — Infrastructure Setup

**Trigger:** `Read CLAUDE.md and execute Session 0.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Read design/CLAUDE_infra.md in full.
        Read design/CLAUDE_backend.md Project Structure section.
        Read design/CLAUDE_frontend.md Dockerfile section.

Step 2. Create .env from .env.example.
        → cp .env.example .env
        → Fill in: DB_PASSWORD, JWT_SECRET, MINIO_ROOT_USER,
                   MINIO_ROOT_PASSWORD, GEMINI_API_KEY
        → Verify ANTHROPIC_API_OPTION=false (Gemini is default per Rule 12)
        → Do NOT commit .env — it is gitignored.

Step 3. Create docker-compose.yml at project root.
        → Use the full spec from design/CLAUDE_infra.md.
        → Services: frontend, backend, worker, redis, postgres, minio,
                    minio-init.
        → All services on sailor_net bridge network.
        → All healthchecks defined.

Step 4. Create frontend/Dockerfile.
        → Multi-stage: development → build → production (nginx)
        → nginx.conf: API proxy to backend:8000 + SPA fallback
        → Use spec from design/CLAUDE_frontend.md Dockerfile section.

Step 5. Create backend/Dockerfile.
        → python:3.11-slim base
        → CMD: alembic upgrade head && uvicorn main:app
        → Use spec from design/CLAUDE_backend.md Dockerfile section.

Step 6. Create docker/Dockerfile.worker and docker/Dockerfile.runner.
        → Dockerfile.worker: python:3.11-slim + sailor package + Celery
        → Dockerfile.runner: ubuntu:22.04 + codeql + klee + clang
        → Use specs from design/CLAUDE_infra.md.

Step 7. Create sailor/infra/ package.
        → sailor/infra/__init__.py
        → sailor/infra/docker_runner.py   (DockerRunner class)
        → sailor/infra/celery_tasks.py    (Phase 1/2/3 task definitions)
        → sailor/infra/celery_config.py   (broker/backend from env vars)

Step 8. Update Phase pipelines to use DockerRunner.
        → Phase2Config: add docker_runner parameter
        → Phase3Config: add docker_runner parameter
        → CompileDiagnoser: delegate to runner.compile_harness()
        → SEDiagnoser: delegate to runner.run_klee()
        → ASanCompiler: delegate to runner.build_asan_archive()
        → ConcreteExecutor: delegate to runner.run_asan_replay()

Step 9. Build sailor-runner image (required by worker at runtime).
        → docker build -f docker/Dockerfile.runner -t sailor-runner:latest .
        → docker run --rm sailor-runner:latest codeql --version
        → docker run --rm sailor-runner:latest klee --version
        → docker run --rm sailor-runner:latest clang --version

Step 10. Start the full system with a single command.
         → docker compose up -d
         → Wait for all healthchecks to pass:
             docker compose ps
             (all services must show "healthy" or "running")

Step 11. Verify each service.
         → Frontend:  curl http://localhost:3000
                      (must return HTML, not connection refused)
         → Backend:   curl http://localhost:8000/api/health
                      (must return {"status": "ok"})
         → DB:        docker compose exec postgres psql -U sailor -c "\dt"
                      (must list all tables after alembic migrate)
         → MinIO:     curl http://localhost:9001
                      (console accessible)
         → Worker:    docker compose logs worker | grep "ready"
                      (Celery worker must report ready)
         → API proxy: curl http://localhost:3000/api/health
                      (must proxy to backend — same response as above)

Step 12. Run unit tests — confirm no local codeql/klee/clang calls.
         → python3 -m pytest test_phase/ -v -k 'not e2e'

Step 13. Run Standard Last Step.
```

---

## Session 1 — Project Analysis, Sync Check & Cleanup

**Trigger:** `Read CLAUDE.md and execute Session 1.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Analyze project structure.
        → Verify tree matches CLAUDE.md Section 3.
        → Find any imports from legacy dirs into sailor/.
        → Find any local subprocess calls to codeql/klee/clang/make.
        → Find dead code (unreferenced files).
        → Output report only. Do NOT touch files yet.

Step 2. Sync Check — detect drift between spec files and actual code.

        Check CLAUDE.md Rule 11 first:
          If [SYNC_CHECK: OFF] → skip this step entirely, proceed to Step 3.
          If [SYNC_CHECK: ON]  → continue below.

        For each CLAUDE_*.md file, extract all of the following
        that appear as code blocks and compare against sailor/:
          - class names and their __init__ signatures
          - dataclass / @dataclass field names and types
          - public method signatures (name, parameters, return type)
          - config field names referenced in example code

        For each conflict found, classify it before reporting.
        Compare the conflicting item against paper/paper_phase*.md.

          If code contradicts paper/                 → Case A (code is wrong)
          If spec contradicts paper/ but code matches → Case B (spec outdated)
          If paper/ does not cover the item           → Case C (needs human judgment)

        Output a drift report in this format:
          [A] CLAUDE_phase2.md: LLMOrchestrator turn budget
              spec has: T_max enforced in while loop
              code has: loop exits at T_max - 1 (off-by-one)
              paper says: t < T_max
              action: fix code — do NOT update spec

          [B] CLAUDE_phase2.md: Phase2Config.llm_model field
              spec has: llm_model: str = "claude-opus-4-5"
              code has: llm: LLMClient (intentional redesign)
              paper: does not specify LLM config structure
              action: update spec file to match code

          [?] CLAUDE_phase1.md: FactEnricher.bounds_hints window
              spec has: ±20 lines around ℓ
              code has: ±10 lines around ℓ
              paper says: "around ℓ" (no exact number)
              action: cannot determine — needs human decision

          [ok] CLAUDE_phase3.md: ResultClassifier — matches code and paper

        Do NOT modify any file yet. Wait for confirmation.

Step 3. After confirmation: act on drift report decisions.
        → Case A items: fix sailor/ code, leave spec unchanged.
        → Case B items: update CLAUDE_*.md to match code.
        → Case C items: add to CLAUDE_feedback.md as [?] and skip.
        → git commit spec-only changes:
          "docs: sync CLAUDE_*.md with current implementation"
        → git commit code fixes separately:
          "fix: correct implementation to match paper §X.X"

Step 4. After confirmation: clean up code issues from Step 1.
        → git commit before changes.
        → Fix legacy imports.
        → Replace local subprocess codeql/klee calls with DockerRunner.
        → Do NOT delete legacy files (may be referenced externally).

Step 5. Run Standard Last Step.
```

---

## Session 2 — Phase 1: Test & Refine

**Trigger:** `Read CLAUDE.md and execute Session 2.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Read paper/paper_phase1.md in full.

Step 2. Read sailor/phase1/ all source files.

Step 3. Compare implementation against paper.
        Check each item:
          □ FactGenerator._parse_sarif(): handles inter-proc + local traces
          □ FactGenerator: standard (13) + custom (21) queries covered
          □ FactEnricher: all 5 extractors implemented
          □ SpecificationGenerator: ASSERTION_TEMPLATES has all 8 CWEs
          □ SpecificationFilter: FILE_SKIP + FUNCTION_SKIP patterns complete
          □ Entry point BFS: non-static caller traversal correct
          □ Phase1Pipeline: prebuilt_sarif injection supported
            (for tcpdump test — skips CodeQL DB rebuild)
          □ Outputs: findings.json, fact_packs.json,
            specifications.json, phase1_summary.json

Step 4. Run unit tests.
        → python3 -m pytest test_phase/test_phase1.py -v

Step 5. Run e2e Phase 1 test.
        → pytest tests/e2e_self_test.py -m e2e_phase1 -v
        → All 4 workspaces (cwe_122, cwe_121, cwe_416, cwe_476) must PASS.
        → If any workspace missing: implement per design/CLAUDE_e2e_test.md.

Step 6. Fix discrepancies. Add missing tests.

Step 7. Run Standard Last Step.
```

---

## Session 3 — Phase 2: Test & Refine

**Trigger:** `Read CLAUDE.md and execute Session 3.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Read paper/paper_phase2.md in full.

Step 2. Read sailor/phase2/ all source files.

Step 3. Compare implementation against paper.
        Check each item:
          □ LLMOrchestrator: Algorithm 1
            T_explore=8, T_author=12, T_max=60, R_max=15, T_klee=300s
          □ LLMOrchestrator: 3 phases (exploration→authoring→refinement)
          □ LLMOrchestrator: termination conditions correct
          □ LLMClient: ANTHROPIC_API_OPTION=true → Claude,
                       default (unset) → Gemini Flash
          □ LLMClient: Gemini 429 → sleep 60s → retry once → LLMRateLimitError
          □ LLMRateLimitError: does NOT increment turn counter t
          □ StubSynthesizer: 4 granularities (func/branch/loop/type)
          □ CWE-416 exception: free() stub calls real free()
          □ Coverage probes: klee_warning_once at every function entry
          □ CompileDiagnoser: delegates to runner.compile_harness()
            4 error classes + suggested fix
          □ SEDiagnoser: delegates to runner.run_klee()
            dual-strategy, 300s timeout, depth=1000
            3 outcomes: not_reached/site_reached/bug_triggered

Step 4. Check CLAUDE_phase2.md LLM provider section.
        → Verify llm_client.py matches LLM Provider Strategy spec.

Step 5. Run unit tests.
        → python3 -m pytest test_phase/test_phase2.py -v

Step 6. Run e2e Phase 2 test (mock LLM — no API key required).
        → E2E_MOCK_LLM=true pytest tests/e2e_self_test.py -m e2e_phase2 -v
        → All 4 workspaces must PASS.
        → If fixtures/mock_llm_turns/ missing: run fixture generation first.
            E2E_MOCK_LLM=record python tests/generate_fixtures.py

Step 7. Fix discrepancies. Add missing tests.

Step 8. Run Standard Last Step.
```

---

## Session 4 — Phase 3: Test & Refine

**Trigger:** `Read CLAUDE.md and execute Session 4.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Read paper/paper_phase3.md in full.

Step 2. Read sailor/phase3/ all source files.

Step 3. Compare implementation against paper.
        Check each item:
          □ ReplayDriverGenerator: removes klee_assume/assert/warning_once
          □ ReplayDriverGenerator: preserves regular assignments
            (e.g., ndo->ndo_vflag = 3 must NOT be removed)
          □ ASanCompiler: delegates to runner.build_asan_archive()
            UNMODIFIED project source only — never stubs
          □ ConcreteExecutor: delegates to runner.run_asan_replay()
          □ ResultClassifier: CONFIRMED only if crash in project source
          □ ResultClassifier: full CWE refinement table
            heap-overflow→CWE-122, stack-overflow→CWE-121,
            heap-use-after-free→CWE-416, double-free→CWE-415
          □ .ktest parsing: ktest-tool CLI or KTest_fromFile (not custom parser)
          □ verified_bug.json: correct schema

Step 4. Run unit tests.
        → python3 -m pytest test_phase/test_phase3.py -v

Step 5. Run e2e Phase 3 test.
        → pytest tests/e2e_self_test.py -m e2e_phase3 -v
        → All 4 workspaces must PASS.
        → Requires fixtures/witness.ktest to exist per workspace.
        → If missing: run Session 3 Step 6 (Phase 2 fixture generation) first.

Step 6. Fix discrepancies. Add missing tests.

Step 7. Run Standard Last Step.
```

---

## Session 5 — Evaluation Framework: Test & Refine

**Trigger:** `Read CLAUDE.md and execute Session 5.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Read design/CLAUDE_evaluation.md in full.

Step 2. Read sailor/evaluation/ all source files.

Step 3. Check each item:
          □ INITIAL_DATASET: contains CVE-2025-11494
          □ EvaluationPipeline: dispatches Phase tasks via Celery
            (not calling Phase pipelines directly)
          □ EvaluationDB: get_resumable_phase() skips completed phases
          □ EvaluationPipeline._run_phase2(): SpecMatcher filters specs
          □ SpecMatcher: 4 levels (strict→file_func→file_only→fuzzy)
          □ DockerEnvironment (environment.py): marked as deprecated,
            replaced by sailor/infra/docker_runner.py

Step 4. Run evaluation for CVE-2025-11494.
        → Read design/cve/design/cve/CLAUDE_cve_2025_11494.md for ground truth.
        → EvaluationPipeline(config).run(cve_ids=["CVE-2025-11494"])
        → Phases run inside Docker via Celery tasks.
        → Success: verified_bug.json with verdict=CONFIRMED

Step 5. Run Standard Last Step.
```

---

## Session 6 — tcpdump Pipeline Validation

**Trigger:** `Read CLAUDE.md and execute Session 6.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Read design/cve/CLAUDE_tcpdump_pipeline_test.md in full.

Step 2. Verify pre-built artifacts.
        → .tcmdump_sast/bootp_sa.sarif exists
        → .tcmdump_sast/myqueries/ exists
        → .tcmdump_sast/tcpdump-db/ exists

Step 3. Run pipeline using sailor/ package.
        → Phase1Pipeline with prebuilt_sarif_path=bootp_sa.sarif
        → Phase2/3 dispatch via Celery tasks (runner container)
        → PoC file generation from confirmed result

Step 4. On failure: fix sailor/ code, re-run.
        → Apply fixes from design/cve/CLAUDE_tcpdump_pipeline_test.md

Step 5. Success: verified_bug.json + poc/ with poc.pcap

Step 6. Run Standard Last Step.
```

---

## Session 7 — Secondary CVE Test (CVE-2023-1972)

**Trigger:** `Read CLAUDE.md and execute Session 7.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Confirm CVE-2025-11494 verdict = "true_positive" in DB.
        If not: fix Session 5 first. Do NOT proceed.

Step 2. Read design/cve/CLAUDE_cve_2023_1972.md in full.

Step 3. Run EvaluationPipeline for CVE-2023-1972.
        → Tests bfd/elf.c path (different from bfd/elfxx-x86.c)
        → Documents failure_reason differences if pipeline fails.

Step 4. Run Standard Last Step.
```

---

## Session 8 — E2E Test Implementation

**Trigger:** `Read CLAUDE.md and execute Session 8.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Read spec/e2e_test_spec.md in full.
        Read design/CLAUDE_e2e_test.md in full.

Step 2. Check prerequisites.
        → Confirm Session 0 completed: docker compose ps
          All services must be healthy (frontend, backend, worker, redis,
          postgres, minio).
        → Confirm sailor-runner image exists:
            docker image inspect sailor-runner:latest
        → Confirm runner has required tools:
            docker run --rm sailor-runner:latest clang --version
            docker run --rm sailor-runner:latest klee --version

Step 3. Implement workspace files (design/CLAUDE_e2e_test.md Phase A).
        Order: cwe_122 → cwe_121 → cwe_416 → cwe_476.
        For each workspace:
          → target.c  (exact template from spec/e2e_test_spec.md §5)
          → Makefile
          → expected.json (schema from spec/e2e_test_spec.md §6)
          → README.md
        Verify each: clang -O1 -g target.c -o target && ./target

Step 4. Extend DockerRunner (design/CLAUDE_e2e_test.md Phase C).
        → Add copy_local_source() to sailor/infra/docker_runner.py
        → Add local_source_path param to setup_target()
        → Unit test: docker cp round-trip for cwe_122/target.c

Step 5. Implement MockLLMClient (design/CLAUDE_e2e_test.md Phase B3).
        → Create sailor/phase2/mock_llm_client.py
        → Unit test: playback, record, hash mismatch → MockLLMError

Step 6. Implement test runner (design/CLAUDE_e2e_test.md Phase B1+B2).
        → tests/conftest.py
        → tests/e2e_self_test.py
        → tests/generate_fixtures.py

Step 7. Run Phase 1 e2e tests (no LLM required).
        → pytest tests/e2e_self_test.py -m e2e_phase1 -v
        → All 4 workspaces must PASS.
        → Fixtures spec.json written to each workspace/fixtures/.

Step 8. Generate mock LLM fixtures for Phase 2 (real LLM, run once).
        → Requires: GEMINI_API_KEY or ANTHROPIC_API_KEY set.
        → E2E_MOCK_LLM=record python tests/generate_fixtures.py
        → Commit generated fixtures/mock_llm_turns/ directories.

Step 9. Run Phase 2 e2e tests (mock LLM).
        → E2E_MOCK_LLM=true pytest tests/e2e_self_test.py -m e2e_phase2 -v
        → All 4 workspaces must PASS.

Step 10. Run Phase 3 e2e tests.
         → pytest tests/e2e_self_test.py -m e2e_phase3 -v
         → All 4 workspaces must PASS.

Step 11. Run full pipeline on cwe_122 (real LLM validation).
         → pytest tests/e2e_self_test.py -m e2e_full -k cwe_122 -v
         → Must PASS within 120 seconds.

Step 12. Verify all items in design/CLAUDE_e2e_test.md Validation Checklist.

Step 13. Run Standard Last Step.
```

---

## Session 9 — Backend Implementation (FastAPI + Celery)

**Trigger:** `Read CLAUDE.md and execute Session 9.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Read spec/backend_spec.md in full.
        Read design/CLAUDE_backend.md in full.
        Read spec/interactive_control_spec.md §5 (Backend API Additions)
        and §6 (Interrupt State Persistence).

Step 2. Verify prerequisites.
        → Session 0 must be complete: docker compose ps
          (postgres, redis, minio must be healthy)
        → If not: run Session 0 first.

Step 3. Implement Phase A — Foundation.

  A1. Project setup.
      → backend/requirements.txt with all dependencies
      → backend/config.py: Settings reading from env vars
      → backend/database.py: async SQLAlchemy engine + session
      → backend/celery_app.py: Celery app + queue config
      → backend/Dockerfile (spec: design/CLAUDE_backend.md)

  A2. Database models (backend/models/).
      → Implement ALL models per spec/backend_spec.md §2.1
        and design/CLAUDE_backend.md Gap 2.
      → Include: interrupt_points table (spec/interactive_control_spec.md §6)
      → Include: auto_config table (spec/interactive_control_spec.md §5.1)
      → Generate Alembic initial migration.
      → Verify: docker compose exec backend alembic upgrade head
                docker compose exec postgres psql -U sailor -c "\dt"
                (all tables must exist, including interrupt_points, auto_config)

  A3. Pydantic schemas (backend/schemas/).
      → Request/response schemas for all entities.
      → Discriminated union for Intervention (§6).
      → EventMessage schema (§5.3).

  A4. Artifact store (backend/services/artifact_service.py).
      → ArtifactStore ABC + MinIOArtifactStore.
      → Presigned URL generation (300s TTL).
      → Verify: docker compose exec backend python -c
          "from services.artifact_service import MinIOArtifactStore; print('OK')"

  A5. Auth (backend/api/auth.py + services/auth_service.py + middleware/auth.py).
      → POST /api/auth/login → JWT access + refresh tokens.
      → POST /api/auth/refresh, POST /api/auth/logout.
      → POST /api/auth/register (public; first registered user gets admin role).
      → get_current_user() dependency + require_role() decorator.
      → Verify: first registration returns role="admin", second returns role="viewer".

Step 4. Implement Phase B — Core API.

  B1. Run operations (backend/api/runs.py + services/run_service.py).
      → POST /api/runs, GET /api/runs, GET /api/runs/:id.
      → POST /api/runs/:id/pause|resume|cancel|clone.
      → State transitions per spec §3.1 — enforce via UPDATE WHERE.

  B2. Spec operations (backend/api/specs.py + services/spec_service.py).
      → GET /api/runs/:id/specs (cursor-paginated, all filter params).
      → GET /api/runs/:id/specs/:id/turns (summary only).
      → GET /api/runs/:id/specs/:id/turns/:id (with payload).
      → POST requeue, skip, bulk-requeue, bulk-skip.

  B3. Intervention (backend/api/specs.py §6).
      → POST /api/runs/:id/specs/:id/intervene.
      → EditHarness: optimistic concurrency via base_version (→ 409).

  B4. Artifacts (backend/api/artifacts.py).
      → GET /api/runs/:id/specs/:id/artifacts → tree.
      → GET /api/runs/:id/specs/:id/artifacts/*path → presigned URL redirect.
      → POST artifacts.tar.gz → enqueue export_task → 202 + job_id.

  B5. Results, logs, workers.
      → GET /api/runs/:id/results, /logs, /workers, /workers/:id.
      → GET /api/runs/:id/results/compare?other=:id.

  B6. Auto/Manual config (backend/api/auto_config.py).
      → GET  /api/runs/:id/auto-config
      → PATCH /api/runs/:id/auto-config  (operator role)

  B7. Interrupt panel endpoints (backend/api/interrupts.py).
      → GET  /api/runs/:id/interrupts
      → GET  /api/runs/:id/interrupts/:interrupt_id
      → POST /api/runs/:id/interrupts/:interrupt_id/resume  (intervener role)
      → POST /api/runs/:id/interrupts/:interrupt_id/skip    (intervener role)

  B8. File validation (backend/api/validate.py + services/validation_service.py).
      → POST /api/validate/file (public, stateless)
      → ValidatorService with all file type validators per design/CLAUDE_backend.md B8.
      → CSourceValidator runs clang --syntax-only inside DockerRunner.

  B9. User management (extend backend/api/auth.py).
      → POST /api/auth/register (already in A5 — verify it's wired to router here)
      → GET  /api/users, POST /api/users/:id/role, DELETE /api/users/:id  [admin]

  B10. Phase-level download endpoints (backend/api/phase_downloads.py).
       → All endpoints per design/CLAUDE_backend.md B10.
       → All responses: HTTP 302 presigned redirect (300s TTL).

Step 5. Implement Phase C — SSE.

  C1. Event service (backend/services/event_service.py).
      → Publish events to Redis Pub/Sub per spec §8.
      → RunCountersUpdated throttled to ≤ 1/second per run.

  C2. Push service (backend/services/push_service.py).
      → Per-connection asyncio queue (drop at 1MB).
      → 250ms flush loop with coalescing.
      → 60-second replay buffer in Redis LRANGE.

  C3. SSE endpoint (backend/api/events.py).
      → GET /api/events?topics=...&token=<jwt>
      → Last-Event-ID reconnect + resync_required on gap.

Step 6. Implement Phase D — Celery Tasks.

  D1. phase1_task (backend/tasks/phase1.py).
  D2. phase2_task (backend/tasks/phase2.py).
      → Gemini Flash by default (ANTHROPIC_API_OPTION=false).
      → Lease heartbeat every 30s.
      → Control-flag check at every turn boundary.
      → Interrupt check at every function boundary per design/CLAUDE_backend.md:
          check auto_config[function_name]; if false → write interrupt_points row,
          publish SSE event interrupt_created, poll until resumed or skipped.
      → Apply same interrupt pattern to phase1_task and phase3_task.
  D3. phase3_task (backend/tasks/phase3.py).
  D4. export_task (backend/tasks/exports.py).

Step 7. Implement Phase E — Middleware, Health, Metrics.
        → Idempotency middleware (Idempotency-Key header → Redis cache).
        → Tracing middleware (trace_id propagation to Celery).
        → GET /api/health, GET /api/metrics (Prometheus).

Step 8. Run tests.
        → pytest backend/tests/ -v
        → mypy backend/ --strict
        → Verify FastAPI /docs shows all expected endpoints including
            /api/runs/:id/auto-config, /api/runs/:id/interrupts/*,
            /api/validate/file, /api/auth/register, phase download endpoints.
        → pytest backend/tests/test_interrupts.py
            Test: interrupt created → waiting, resume with modified file, skip.
            Test: file validation rejects PDF-as-SARIF (returns severity="error").
            Test: first-user registration gets admin role.
        → pytest backend/tests/test_phase_downloads.py
            Test: presigned redirect for each phase artifact type.

Step 9. Verify full stack in Docker.
        → docker compose up -d --build backend worker
        → curl http://localhost:8000/api/health  →  {"status": "ok"}
        → curl http://localhost:8000/docs        →  OpenAPI UI

Step 10. Run Standard Last Step.
```

---

## Session 10 — Frontend Implementation (React + Vite)

**Trigger:** `Read CLAUDE.md and execute Session 10.`

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Read spec/frontend_spec.md in full.
        Read design/CLAUDE_frontend.md in full.
        Read spec/interactive_control_spec.md in full.
        (interactive_control_spec.md overrides frontend_spec.md
         for features described in its §2, §3, §4.)

Step 2. Verify prerequisites.
        → Session 9 must be complete: curl http://localhost:8000/api/health
        → Backend OpenAPI schema available at http://localhost:8000/openapi.json
        → If not: run Session 9 first.

Step 3. Implement Phase A — Foundation.

  A1. Project setup.
      → Vite + React + TypeScript template inside frontend/
      → Install: zustand, @tanstack/react-query, @tanstack/virtual,
                 @uiw/react-codemirror, react-router-dom, tailwindcss,
                 axios, recharts, nuqs, shadcn/ui,
                 zxcvbn, @codemirror/lang-c, react-dropzone
      → Configure Tailwind + shadcn/ui init.
      → frontend/Dockerfile (spec: design/CLAUDE_frontend.md).
      → frontend/nginx.conf (API proxy + SPA fallback).
      → Configure routes: include /register, /settings/users.

  A2. Implement frontend/src/lib/types.ts in full.
      → All TypeScript interfaces from design/CLAUDE_frontend.md.
      → No placeholder types — every field must match backend schema.
      → Verify against backend OpenAPI: http://localhost:8000/openapi.json

  A3. Implement frontend/src/api/client.ts.
      → axios instance, VITE_API_URL base, Bearer token injection.
      → 401 → redirect to login, error normalization.

  A4. Implement hooks/useSSE.ts.
      → EventSource with ?token= auth param.
      → Reconnect: exponential backoff (1s, 2s, 4s, max 30s).
      → Last-Event-ID reconnect + resync_required handling.
      → JSON Merge Patch (RFC 7386) applied to Zustand stores.

  A5. Implement hooks/useSpecStore.ts + hooks/useRunStore.ts.
      → useSpecStore: Map<spec_id, Spec> + applyDiff().
      → useRunStore: Run + applyDiff() + control actions.

Step 4. Implement Phase B — Core Views.

  B1. Dashboard (/).
      → RunTile with progress bars.
      → Subscribes to runs.all SSE topic.

  B2. New Run (/runs/new).
      → All form inputs from spec §1.
      → Zip upload with drag-and-drop.

  B3. Run Detail header (/runs/:run_id).
      → Live phase progress bars.
      → Pause/Resume/Cancel/Re-run controls.

  B4. Spec Table (core of §3b).
      → TanStack Virtual — 30K rows at 60fps. Non-negotiable.
      → All columns, filter bar, URL-encoded filters via nuqs.
      → Saved filter presets, right-click context menu.
      → Subscribes to runs.:id.specs SSE topic.

  B5. Charts Strip (§3c).
      → Phase 2 outcomes stacked area (Recharts).
      → Turn distribution histogram.

Step 5. Implement Phase C — Spec Detail.

  C1. Spec Header (§4a): JSON collapsible + phase chips.
  C2. Timeline (§4b): lazy-load payloads on click. Never fetch all on mount.
  C3. Artifact Tree (§4c): file tree + CodeMirror read-only viewer.
  C4. Intervention Panel (§4d): modes A/B/C + confirmation modal.
      → Warn: "Editing will consume 1 of your remaining N turns."

  C5. Interrupt system (spec §3, design/CLAUDE_frontend.md C5).
      → InterruptPanel.tsx (base) + all 15 function-specific variants.
      → InterruptFileRow.tsx + FileValidationBanner.tsx.
      → Interrupt notification: SSE "interrupt_created" → toast → navigate.
      → PipelineControlsSidebar.tsx with AutoCheckbox per pipeline function.

Step 6. Implement Phase D — Supporting Views.

  D1. Worker View (/runs/:id/workers) — §5.
  D2. Logs View (/runs/:id/logs) — §6.
      → Virtualized. Never render >500 lines in DOM simultaneously.
  D3. Results Browser (Results tab) — §7.
  D4. Settings (/settings) — §8.
      → LLM API keys: write-only input, last-4 display only.

  D5. Phase-end downloads (spec §4, design/CLAUDE_frontend.md D5).
      → PhaseDownloadButton.tsx + PhaseDownloadGroup.tsx.
      → EvidencePackageButton.tsx.
      → Download buttons on timeline event cards (Phase 1/2/3 completion).
      → "Download all Phase N" in Artifacts pane.

Step 7. Implement Phase E — Auth, Error Handling, Polish.

  E1. Login page + JWT token management + Registration.
      → Role-based rendering (hide intervention controls for viewer).
      → /register page: form + zxcvbn password meter + first-user admin banner.
      → /settings/users page: admin-only, role management table.
  E2. Error handling per spec §9.
      → Red badge on spec row, persistent banner for systemic errors.
  E3. Skeleton UI, empty states, stale indicator (SSE disconnected).

Step 8. Build verification.
        → npm run build      (must succeed, zero TypeScript errors)
        → npm run lint       (zero ESLint errors)

Step 9. Verify full stack in Docker.
        → docker compose up -d --build frontend
        → curl http://localhost:3000           →  HTML (not connection refused)
        → curl http://localhost:3000/api/health →  {"status": "ok"} (proxy works)
        → Open browser: http://localhost:3000
          Login page must render. Dashboard must load after login.

Step 10. Run Standard Last Step.
```
