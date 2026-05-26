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
        Read spec/sse_contract.md in full.
        Read spec/interactive_control_spec.md §4 (Auto/Manual Mode +
        Interrupt System) and §5 (Phase-End Download).
        Read shared/contracts/README.md (conflict resolution log).

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
      → For every column that mirrors a shared contract type, use
        the exact field names from shared/contracts/sailor_models.py.
        Critical examples:
          interrupt_points.function_name  → PipelineFunctionId enum value
                                            e.g. "phase2_klee_execution"
                                            (snake_case, NO DOTS)
          interrupt_points.status         → "waiting"|"resumed"|"skipped"
          interrupt_points.scope          → "run"|"spec"
          auto_config.config JSONB        → keys are PipelineFunctionId values,
                                            values are boolean; flat map,
                                            NO nested objects, NO dotted keys
          runs.status                     → RunStatus enum (lowercase)
          runs.counters JSONB             → RunCounters field names verbatim
                                            (e.g. specs_total, NOT total_specs)
          runs.config JSONB               → RunConfig field names verbatim
                                            (e.g. phase2_t_klee_seconds,
                                            NOT T_klee or phase2.t_klee_seconds)
          specs.phase2_status             → Phase2Status enum (includes "errored")
          specs.phase3_status             → Phase3Status enum (includes
                                            "not_eligible"; "skipped" does not exist)
          verdicts.verdict                → VerdictValue ("confirmed"|"rejected",
                                            lowercase always)
      → Remove the `phase` integer column from interrupt_points;
        it is derivable from the function_name prefix (phase1_*, phase2_*, phase3_*).
      → Include auto_config table (interactive_control_spec.md §4.4).
      → Generate Alembic initial migration.
      → Verify: docker compose exec backend alembic upgrade head
                docker compose exec postgres psql -U sailor -c "\dt"
                (all tables must exist, including interrupt_points, auto_config)

  A3. Shared contract models — DO NOT create backend/schemas/ for wire types.
      → Run: ./scripts/regen_contracts.sh
        Confirms shared/contracts/sailor_models.py is current.
      → In backend/pyproject.toml (or requirements), ensure the repo root is
        on PYTHONPATH so `from shared.contracts.sailor_models import ...` works.
      → Create backend/schemas/internal.py for backend-internal types only
        (DB-internal shapes, Celery task argument/result types, audit diffs).
        Any type that appears in an HTTP request or response body MUST come from
        shared.contracts.sailor_models, not from backend/schemas/.
      → Verify: python -c "from shared.contracts.sailor_models import Run, Spec,
          SSEMessageRunStatusChanged, InterruptPoint, AutoConfigPatch; print('OK')"

  A4. Artifact store (backend/services/artifact_service.py).
      → ArtifactStore ABC + MinIOArtifactStore.
      → Presigned URL generation (300s TTL).
      → Verify: docker compose exec backend python -c
          "from services.artifact_service import MinIOArtifactStore; print('OK')"

  A5. Auth (backend/api/auth.py + services/auth_service.py + middleware/auth.py).
      → POST /api/auth/login → JWT access + refresh tokens.
      → POST /api/auth/refresh, POST /api/auth/logout.
      → POST /api/auth/register (public; first registered user gets admin role;
        uses RegisterRequest / RegisterResponse from shared.contracts.sailor_models).
      → get_current_user() dependency + require_role() decorator.
      → Verify: first registration returns role="admin", second returns role="viewer".

  A6. Idempotency + tracing middleware (do this before any API handler).
      → middleware/idempotency.py: read Idempotency-Key header; cache
        (user_id + endpoint + key) → response in Redis 24h TTL;
        on hit return cached response without calling the handler.
      → middleware/tracing.py: generate trace_id (UUID4) per request;
        attach to request.state; propagate to Celery task headers;
        include in all LogLine events and ApiError responses.

Step 4. Implement Phase B — Core API.

  B1. Run operations (backend/api/runs.py + services/run_service.py).
      → POST /api/runs, GET /api/runs, GET /api/runs/:id.
      → Response model: Run (from shared.contracts.sailor_models).
      → POST /api/runs/:id/pause|resume|cancel|clone.
      → DELETE /api/runs/:id (soft delete → status="archived").
      → State transitions per spec §3.1 — enforce via UPDATE WHERE.

  B2. Spec operations (backend/api/specs.py + services/spec_service.py).
      → GET /api/runs/:id/specs (cursor-paginated, all filter params).
        Response: PaginatedSpecs (from shared.contracts.sailor_models).
      → GET /api/runs/:id/specs/:spec_id/turns — returns Turn[] (summary only,
        no inline payload). Response uses Turn schema from shared.contracts.
      → GET /api/runs/:id/specs/:spec_id/turns/:turn_id — returns TurnDetail
        (Turn + inlined TurnPayload). This is the ONLY endpoint that returns
        inline payload. Never inline payload in the list endpoint.
      → POST requeue, skip, bulk-requeue, bulk-skip.
      → POST /api/runs/:id/specs/:spec_id/manual-harness
        Body: { enabled: bool }. Response: ManualHarnessMode.

  B3. Intervention (backend/api/specs.py §6).
      → POST /api/runs/:id/specs/:spec_id/intervene.
      → Request body: InterventionRequest discriminated union from
        shared.contracts.sailor_models. Discriminator field is `type`.
      → Valid type values: "edit_harness" | "force_outcome" | "edit_spec".
        "mode_a" / "mode_b" / "mode_c" are NOT valid — reject with 422.
      → EditHarnessRequest.artifact ∈ {"driver","slice","assertions"} — no .c
        extension on the wire. 422 if "driver.c" etc. is sent.
      → EditHarness: optimistic concurrency via base_version (→ 409 on conflict).

  B4. Artifacts (backend/api/artifacts.py).
      → GET /api/runs/:id/specs/:spec_id/artifacts → tree (refs only; no presigned
        URLs in the tree listing).
      → GET /api/runs/:id/specs/:spec_id/artifacts/*path
        → HTTP 302 to presigned URL (300s TTL). NEVER stream bytes through FastAPI.
        → No Range header proxying; Range is S3/MinIO's responsibility.
      → POST /api/runs/:id/specs/:spec_id/artifacts.tar.gz
        → enqueue export_task, return 202 + job_id.
      → GET /api/jobs/:job_id → poll export status.

  B5. Results, logs, workers.
      → GET /api/runs/:id/results, /logs, /workers, /workers/:id.
      → GET /api/runs/:id/results/compare?other=:id.

  B6. Auto/Manual config (backend/api/auto_config.py).
      → GET  /api/runs/:run_id/auto-config             [viewer+]
            Response 200: AutoConfig
            (full map; missing keys mean auto=true)
      → PATCH /api/runs/:run_id/auto-config            [operator+]
            Body: AutoConfigPatch (from shared.contracts.sailor_models)
            Keys are PipelineFunctionId values — flat snake_case strings.
            REJECT any key containing a dot (return 422
            code="invalid_function_name").
            Response 200: AutoConfig (full post-update config).
            Effect: takes effect at next function boundary.
            Side-effect: publish auto_config_changed SSE event on
              runs.<run_id> topic. Use SSEMessageAutoConfigChanged from
              shared.contracts.sailor_models — not a raw dict.

  B7. Interrupt panel endpoints (backend/api/interrupts.py).
      → GET  /api/runs/:run_id/interrupts              [viewer+]
            Query: status (default: waiting), function_name, spec_id, scope
            Response: paginated list of InterruptPoint.
      → GET  /api/runs/:run_id/interrupts/:interrupt_id [viewer+]
            Response: InterruptPoint with input_files populated.
            Each input_files[*].artifact_ref is an opaque ref resolvable
            via GET /api/artifacts/:ref (returns 302).
      → POST /api/runs/:run_id/interrupts/:interrupt_id/files  [intervener+]
            Multipart upload of one file at a time.
            Fields: "file" (binary), "name" (logical filename).
            Effect: uploads to artifact store, runs server-side validation,
            returns { artifact_ref: str, validation: FileValidationResult }.
            HTTP 200 even if validation.severity = "error" (see sse_contract.md §9).
      → POST /api/runs/:run_id/interrupts/:interrupt_id/resume [intervener+]
            Body: InterruptResumeRequest (from shared.contracts.sailor_models)
            Fields:
              modified_files: [{name, artifact_ref, base_version?}]
                artifact_ref must come from a prior /files upload, not be
                supplied as raw bytes. 422 if artifact_ref is unknown.
              option_overrides: validated per-function per
                interactive_control_spec.md §4.6
              apply_to_all_matching: bool (default false)
                If true: modified_files MUST be empty (422 otherwise,
                code="bulk_modify_with_files").
              re_enable_auto: bool (default false)
            Server re-validates all referenced files before resuming.
            If any has severity=error: return 422 code="validation_failed",
            detail contains the FileValidationResult.
            Response 200: { interrupt: InterruptPoint (status="resumed") }
            Response 409: code="version_mismatch"
            Side-effect: publish interrupt_resolved SSE event.
            Audit event: action="interrupt_resume".
      → POST /api/runs/:run_id/interrupts/:interrupt_id/skip   [intervener+]
            Body: InterruptSkipRequest (from shared.contracts.sailor_models)
            Response 200: { interrupt: InterruptPoint (status="skipped") }
            Side-effect: publish interrupt_resolved SSE event.
            Audit event: action="interrupt_skip".

  B8. File validation (backend/api/validate.py + services/validation_service.py).
      → POST /api/validate/file                        [public, no auth]
            Body: multipart/form-data with fields:
              "file"     — binary file content
              "filename" — logical filename including extension (drives validator
                           dispatch; "findings.sarif", "driver.c", etc.)
            Response 200: FileValidationResult (from shared.contracts.sailor_models)
              { valid, severity, message, detected_format, issues[] }
            Note: HTTP 200 even when severity="error". ApiError is only for
            endpoint-level failures (auth, server error).
      → ValidatorService.validate(filename: str, content: bytes) → FileValidationResult
        Dispatch table: see interactive_control_spec.md §4.7.
        CSourceValidator runs clang --syntax-only inside DockerRunner.
        replay_driver.c validation additionally checks for klee_* call sites
        (rule id "replay_driver.klee_call_present").

  B9. User management (extend backend/api/auth.py).
      → POST /api/auth/register — verify wired to router (implemented in A5).
      → GET  /api/users                                [admin]
      → POST /api/users/:user_id/role                  [admin]
            Body: { role: UserRole }
      → POST /api/users/:user_id/disable               [admin]
      → POST /api/users/:user_id/enable                [admin]
      → DELETE /api/users/:user_id                     [admin]
            Soft delete: anonymize, set disabled=true, preserve audit links.
            Last admin cannot be deleted (409 code="last_admin").

  B10. Phase-level download endpoints (backend/api/phase_downloads.py).
       → All endpoints per interactive_control_spec.md §5.6.
       → All file responses: HTTP 302 presigned redirect (300s TTL).
         NEVER stream bytes through FastAPI (see Constraint 10).
       → List endpoints return { items: [{ name, size_bytes, mime_type,
         created_at, artifact_ref }] }. No presigned URLs in list response.
       → Tarball endpoints ≤ 100MB: return 302 to pre-built tarball, or
         return 202 + job_id and let client poll GET /api/jobs/:job_id.

Step 5. Implement Phase C — Real-Time Push (SSE).

  Read spec/sse_contract.md in full before writing any SSE code.
  Every decision about wire format, auth, reconnect, batching, and
  keep-alive is made there. Do not invent alternatives.

  C1. Event service (backend/services/event_service.py).
      → Publish events to Redis Pub/Sub per sse_contract.md.
      → Always construct concrete SSEMessage* Pydantic models from
        shared.contracts.sailor_models before publishing. Never publish raw dicts.
        Example:
          msg = SSEMessageRunStatusChanged(
              topic=f"runs.{run_id}",
              sequence=next_seq(topic),
              timestamp=utcnow_iso(),
              kind="run_status_changed",
              payload=RunStatusChangedPayload(run_id=run_id, status=new, previous_status=old),
          )
          redis.publish(topic, msg.model_dump_json())
      → run_counters_updated: throttle to ≤ 1/second per run.
      → spec_state_changed: fan-out to BOTH runs.<run_id>.specs AND
        runs.<run_id>.specs.<spec_id> (same sequence, different topic field).
      → All 11 SSE kinds from sse_contract.md §8 must be implemented:
          run_status_changed, run_counters_updated, spec_state_changed,
          spec_intervention_applied, turn_appended, worker_heartbeat,
          log_line, resync_required,
          interrupt_created, interrupt_resolved, auto_config_changed.

  C2. Push service (backend/services/push_service.py).
      → Subscribe to Redis Pub/Sub channels per connection's topic set.
      → 60-second replay buffer in Redis sorted set per topic
        (ZADD on publish; ZRANGEBYSCORE on reconnect; trim every 10s).
      → 250ms batching window per topic; flush as SSEBatch when >1 message
        accumulated; flush as single SSEMessage otherwise.
        Use SSEBatch from shared.contracts.sailor_models for construction.
      → Keep-alive: emit `: keep-alive\n\n` comment every 15 seconds.
      → Drop connection at 1MB pending queue backlog.

  C3. SSE endpoint (backend/api/events.py).
      → GET /api/events?topics=<comma-separated>&token=<jwt>
      → Authentication: validate `token` query param — identical check to
        Authorization header on other endpoints. No other auth mechanism.
        Missing/invalid token: return 401 ApiError BEFORE opening the stream.
      → Parse Last-Event-ID header for reconnect. ?since= is NOT supported.
      → On reconnect with Last-Event-ID: replay from buffer; if gap >60s,
        emit resync_required (reason="buffer_overflow") then continue live.
      → Topic validation: reject unknown patterns with 400 code="invalid_topic".
      → Topic access control: if any topic is forbidden for this user's role,
        return 403 code="topic_forbidden" for the whole request (fail-closed).
      → Maximum 32 topics per connection; beyond that return 400
        code="too_many_topics".
      → Wire format per sse_contract.md §2.2:
          id: <sequence>
          event: <kind | "batch">
          data: <single-line JSON>
          (blank line)

Step 6. Implement Phase D — Celery Tasks.

  D1. phase1_task (backend/tasks/phase1.py).
      → Input: run_id.
      → Use DockerRunner to execute Phase 1 inside container.
      → Call Phase1Pipeline.
      → Persist Spec rows with deterministic spec_id.
      → Publish SSE events at each step via event_service.
      → Apply interrupt check (see D5 below) at each Phase 1
        function boundary.

  D2. phase2_task (backend/tasks/phase2.py).
      → Input: spec_id, continue_from_intervention=False.
      → Lease acquisition per spec §9.2.
      → Lease heartbeat every 30s.
      → Control-flag check at every turn boundary:
          1. Check run.status (paused → requeue, cancelled → errored).
          2. Check intervention_pending → apply per spec §6.
      → LLM API error → retry with exponential backoff, base 2s, max 5
        attempts, cap 60s per attempt. This applies to ALL providers
        including Gemini 429. After 5 failures → mark spec errored.
      → Apply interrupt check (D5) at each Phase 2 function boundary.

  D3. phase3_task (backend/tasks/phase3.py).
      → Input: spec_id.
      → Lease acquisition.
      → Call Phase3Pipeline via DockerRunner.
      → Build Verdict row + compute dedup_key.
      → Apply interrupt check (D5) at each Phase 3 function boundary.

  D4. export_task (backend/tasks/exports.py).
      → Input: job_id, spec_ids[], export_type.
      → Stream artifacts from artifact store into tarball.
      → Write tarball to artifact store.
      → Update export_jobs row with result ref.

  D5. Interrupt check pattern (used in D1, D2, D3).
      At every function boundary:
        function_name = PipelineFunctionId value, e.g. "phase2_klee_execution"
                        (snake_case, NO DOTS — reject any dotted string)

        config = load_auto_config(run_id)  # flat map from DB
        if config.get(function_name, True) is False:
            interrupt = create_interrupt_point(
                run_id=run_id,
                spec_id=spec_id,   # None for run-scope functions
                function_name=function_name,
                scope="run" if function_name.startswith("phase1_") or
                      function_name == "phase2_spec_selection" else "spec",
                turn=current_turn,
                status="waiting",
                input_files=[...],
                option_overrides=current_defaults,
            )
            # Publish using shared model — not a raw dict
            event_service.publish(SSEMessageInterruptCreated(
                topic=f"runs.{run_id}",
                ...
                payload=InterruptCreatedPayload(interrupt=interrupt),
            ))
            # Poll until resolved (5s interval)
            while True:
                row = db.get_interrupt(interrupt.interrupt_id)
                if row.status == "resumed":
                    apply_modified_files(row)   # artifact_refs, not base64
                    apply_option_overrides(row)
                    break
                if row.status == "skipped":
                    use_default_outputs()
                    break
                if run_cancelled():
                    skip_interrupt(interrupt.interrupt_id, resolved_by="system")
                    break
                await asyncio.sleep(5)

      14 supported function names (complete list, no others):
        phase1_db_build, phase1_query_execution, phase1_sarif_parsing,
        phase1_fact_enrichment, phase1_spec_generation,
        phase2_spec_selection, phase2_source_exploration,
        phase2_driver_synthesis, phase2_stub_synthesis,
        phase2_compile_diagnose, phase2_klee_execution,
        phase3_replay_driver_generation, phase3_asan_compilation,
        phase3_result_classification

      sailor/ pipeline code has NO knowledge of interrupt_points.
      Interrupt logic lives entirely in backend Celery tasks.

Step 7. Implement Phase E — Health, Metrics.
        → GET /api/health: check DB, Redis, MinIO connectivity.
        → GET /api/metrics: Prometheus text format.
          Metrics: runs_total, specs_total, turn_duration, llm_tokens_total,
          klee_seconds_total, lease_acquisitions, api_request_duration.
        (Idempotency and tracing middleware were implemented in A6.)

Step 8. Run tests.
        → pytest backend/tests/ -v
        → mypy backend/ --strict
        → Verify FastAPI /docs shows all expected endpoints including:
            GET/PATCH /api/runs/:id/auto-config
            GET /api/runs/:id/interrupts
            GET /api/runs/:id/interrupts/:interrupt_id
            POST /api/runs/:id/interrupts/:interrupt_id/files
            POST /api/runs/:id/interrupts/:interrupt_id/resume
            POST /api/runs/:id/interrupts/:interrupt_id/skip
            POST /api/validate/file
            POST /api/auth/register
            Phase download endpoints
        → pytest backend/tests/test_interrupts.py
            Test: interrupt created → waiting, resume with artifact_ref
                  from a prior /files upload, skip.
            Test: file validation returns FileValidationResult with issues[].
            Test: replay_driver.c with klee_make_symbolic → severity=error,
                  rule="replay_driver.klee_call_present".
            Test: first-user registration gets role="admin".
            Test: AutoConfigPatch with dotted key → 422 invalid_function_name.
            Test: bulk resume apply_to_all_matching with non-empty
                  modified_files → 422 bulk_modify_with_files.
        → pytest backend/tests/test_phase_downloads.py
            Test: presigned redirect for each phase artifact type.
        → pytest backend/tests/test_sse.py
            Test: subscribe with ?token= query param (not Authorization header).
            Test: 11 SSE kinds all produce valid SSEMessage* models.
            Test: Last-Event-ID reconnect replays buffer.
            Test: resync_required on 60s gap.
            Test: counters throttle ≤ 1/s.

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
        Read spec/sse_contract.md in full.
        Read shared/contracts/README.md.
        (interactive_control_spec.md overrides frontend_spec.md
         for features described in its §3, §4, §5.
         sse_contract.md is authoritative for all SSE wire-format details.)

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
      → Configure routes: include /register, /settings/users,
        /runs/:run_id/interrupts, /runs/:run_id/interrupts/:interrupt_id.

  A2. Shared type imports — DO NOT create frontend/src/lib/types.ts for
      wire types.
      → Copy or symlink shared/contracts/sailor.types.ts into the
        frontend's source tree (or configure tsconfig.json paths alias
        @/shared/contracts → ../../shared/contracts).
      → Import all wire types from sailor.types:
          import type { Run, Spec, Turn, TurnDetail, Verdict,
            RunStatus, Phase2Status, Phase3Status, RunConfig, RunCounters,
            SSEMessage, SSEBatch, InterruptPoint, AutoConfig, AutoConfigPatch,
            InterventionRequest, EditHarnessRequest, ForceOutcomeRequest,
            EditSpecRequest, ApiError, PaginatedSpecs, FileValidationResult,
            PipelineFunctionId } from '@/shared/contracts/sailor.types';
      → Create frontend/src/lib/pipelineLabels.ts:
          A map from each PipelineFunctionId value to its display string.
          Example: { "phase2_klee_execution": "KLEE Execution", ... }
          This is the ONLY place display labels live. All 14 functions
          must be present. Never use the raw PipelineFunctionId string as
          a user-visible label anywhere in the UI.
      → Create frontend/src/lib/ui-types.ts for purely-UI state that never
        appears in network payloads (FilterPreset, SpecFilters, ToastSeverity,
        etc.).
      → Verify: npm run build must succeed with zero TypeScript errors.

  A3. Implement frontend/src/api/client.ts.
      → axios instance, VITE_API_URL base.
      → Auth: inject Authorization: Bearer <jwt> header on every
        non-SSE request (token from localStorage).
      → Idempotency: inject Idempotency-Key: <uuid-v4> header on every
        POST/PATCH/DELETE. Generate a new key per user-initiated action;
        on programmatic retry of the same intent, reuse the same key.
      → 401 → redirect to /login; clear stored token.
      → Error normalization: non-2xx responses are typed as ApiError.
        The UI branches on ApiError.code, not solely on HTTP status.

  A4. Implement hooks/useSSE.ts.
      All wire-format decisions come from sse_contract.md. Do not invent.
      Key rules:
      → Connection URL: /api/events?topics=<comma-separated>&token=<jwt>
        (token in query param — EventSource cannot send custom headers).
      → Use native EventSource. The browser handles reconnect automatically
        with Last-Event-ID. Do NOT implement manual exponential backoff in
        JavaScript; that would fight the browser's built-in reconnect.
      → On message: parse JSON. If JSON contains a "batch" key it is an
        SSEBatch (dispatch each inner SSEMessage in sequence order).
        Otherwise dispatch the SSEMessage directly.
      → Dispatcher: exhaustive switch on msg.kind. TypeScript must compile
        without errors, meaning all 11 kinds need a case. Add a compile-time
        assertion at the bottom of the switch to catch new kinds:
          default: {
            const _exhaustive: never = msg;  // compile error if any kind missing
          }
      → The payload is a snapshot — replace the local entity by primary
        key. Never apply any patch or merge to incoming SSE data. The server
        sends full snapshots; the client replaces its local copy entirely.
      → Per-topic sequence deduplication: ignore any message whose sequence
        ≤ last_seen_sequence for that topic.
      → On resync_required: drop local cache for the affected topic,
        refetch via REST, reset last_seen_sequence to null for that topic.
      → The 11 kinds and their payload shapes are in sse_contract.md §8.
        Use the JSON examples in shared/contracts/examples/sse/ as test fixtures.

  A5. Implement hooks/useSpecStore.ts + hooks/useRunStore.ts.
      → useSpecStore: Map<spec_id, Spec>.
          upsert(spec: Spec): replace the local copy entirely (snapshot, not diff).
          clearForRun(run_id: string): drop all specs for a resync.
      → useRunStore: stores Run + live AutoConfig.
          setStatus(run_id, status): partial update.
          setCounters(run_id, counters: RunCounters): replace counters.
          setAutoConfig(run_id, config: AutoConfig): replace config.
      → useInterruptStore: Map<interrupt_id, InterruptPoint>.
          upsert(ip: InterruptPoint).
          markResolved(interrupt_id, resolution).
      → Never patch or diff incoming SSE data. upsert() always replaces the
        full entity from the snapshot in the payload.

Step 4. Implement Phase B — Core Views.

  B1. Dashboard (/).
      → RunTile with progress bars.
      → Subscribes to runs.all SSE topic.

  B2. New Run (/runs/new).
      → All form inputs from spec §1, using RunConfig field names
        (phase2_t_explore, phase2_t_klee_seconds, etc. — not T_explore, T_klee).
      → Zip upload with drag-and-drop.

  B3. Run Detail header (/runs/:run_id).
      → Live phase progress bars.
      → Pause/Resume/Cancel/Re-run controls.
      → PipelineControlsSidebar: collapsible panel with AutoCheckbox per
        function. See §4.9 of interactive_control_spec.md.

  B4. Spec Table (core of §3b).
      → TanStack Virtual — 30K rows at 60fps. Non-negotiable.
      → All columns, filter bar, URL-encoded filters via nuqs.
      → Saved filter presets, right-click context menu.
      → Subscribes to runs.<run_id>.specs SSE topic.

  B5. Charts Strip (§3c).
      → Phase 2 outcomes stacked area (Recharts).
      → Turn distribution histogram.

Step 5. Implement Phase C — Spec Detail.

  C1. Spec Header (§4a): JSON collapsible + phase chips.
  C2. Timeline (§4b): lazy-load payloads on click via GET turns/:turn_id.
      Never fetch all turn payloads on mount (list endpoint has no inline payload).
  C3. Artifact Tree (§4c): file tree + CodeMirror read-only viewer.
  C4. Intervention Panel (§4d).
      → Three intervention types: edit_harness, force_outcome, edit_spec.
        The wire value sent in the `type` field is these exact strings.
        "Mode A / Mode B / Mode C" are display labels only — do not use
        them as field values in any request body.
      → EditHarnessRequest.artifact ∈ {"driver","slice","assertions"} — no .c
        in the request body. The UI may label tabs "[driver.c]" for display.
      → Warn: "Editing will consume 1 of your remaining N turns."

  C5. Interrupt system (interactive_control_spec.md §4).
      → InterruptPanel.tsx (base component) with 14 function-specific variants,
        one per PipelineFunctionId value. See the full list in A2 / D5.
      → Display label for each variant comes from pipelineLabels.ts, not from
        the raw function_name string.
      → Panel does NOT open as a modal overlay automatically. When SSE
        interrupt_created fires and the user is NOT on the interrupt panel:
          → Show a toast notification with a "Go to interrupt →" link.
          → Increment a badge counter in the nav showing waiting interrupts.
        When the user IS on /runs/:run_id/interrupts/:interrupt_id already:
          → Refresh the panel data.
        This matches interactive_control_spec.md §4.3 (no auto-modal).
      → Add two routes: /runs/:run_id/interrupts (list) and
        /runs/:run_id/interrupts/:interrupt_id (panel).
      → File replacement workflow (two-step, per sse_contract.md and
        interactive_control_spec.md §4.8):
          1. User picks a file. Optional pre-flight:
               POST /api/validate/file (multipart) → FileValidationResult.
               Show FileValidationBanner with the result.
          2. User confirms upload:
               POST /api/runs/:run_id/interrupts/:interrupt_id/files (multipart)
               → response.artifact_ref + response.validation.
          3. User clicks Resume:
               POST /api/runs/:run_id/interrupts/:interrupt_id/resume
               Body: InterruptResumeRequest where modified_files[] carries
               artifact_ref values returned from /files uploads. Sending
               raw file bytes in the resume body is not supported.
      → InterruptFileRow.tsx:
          [View]:    fetch via GET /api/artifacts/:ref (302 redirect).
          [Edit]:    open CodeMirror editor; on save → POST /files (step 2 above).
          [Replace]: file input → POST /validate/file → POST /files.
      → FileValidationBanner.tsx:
          Props: validation: FileValidationResult
          severity="error":   red banner; disables Resume button.
          severity="warning": yellow banner; Resume allowed with confirmation.
          severity="info":    blue banner; informational only.
          Renders issues[] list below the summary message when present.
      → AutoCheckbox.tsx:
          Props: functionName: PipelineFunctionId, runId: string, checked: boolean
          On toggle: PATCH /api/runs/:runId/auto-config
          Body: AutoConfigPatch with one key (the PipelineFunctionId value, flat
          snake_case). Never send dotted keys.
          Optimistic update; revert on error.
      → PipelineControlsSidebar.tsx:
          Groups AutoCheckbox by phase prefix.
          "Reset all to Auto" button sends AutoConfigPatch with all 14 keys
          set to true.

Step 6. Implement Phase D — Supporting Views.

  D1. Worker View (/runs/:id/workers) — §5.
  D2. Logs View (/runs/:id/logs) — §6.
      → Virtualized. Never render >500 lines in DOM simultaneously.
  D3. Results Browser (Results tab) — §7.
  D4. Settings (/settings) — §8.
      → LLM API keys: write-only input, last-4 display only.

  D5. Phase-end downloads (interactive_control_spec.md §5).
      → PhaseDownloadButton.tsx + PhaseDownloadGroup.tsx.
      → EvidencePackageButton.tsx.
      → Download buttons on timeline event cards (Phase 1/2/3 completion).
      → "Download all Phase N" in Artifacts pane.
      → On click: GET endpoint follows HTTP 302 to presigned URL.
        Frontend does not stream bytes itself; the redirect is the download.

Step 7. Implement Phase E — Auth, Error Handling, Polish.

  E1. Login page + JWT token management + Registration page (/register).
      → Role-based rendering: hide intervention controls for viewer role.
      → /register page:
          Form fields per RegisterRequest schema.
          zxcvbn password strength meter: advisory display only.
          The "Create account" button is always enabled — the server is the
          authority on password strength (not the meter).
          On 201 with role="admin": show "You are the first user — admin role
          granted" banner.
          On 400: render field-level errors from ApiError.detail.field.
          Anti-enumeration: the UI cannot distinguish "email taken" from
          "success" — display "If this email is new, you'll receive a
          confirmation" regardless.
      → /settings/users page: admin-only; role management table.
        Role change takes effect on user's next login (or immediately on
        downgrade per interactive_control_spec.md §3.3).

  E2. Error handling per spec §9.
      → All ApiError responses expose `.code` for programmatic branching.
      → Red badge on spec row for spec-level errors.
      → Persistent banner for systemic errors (run failed, etc.).
      → ApiError.trace_id shown in developer/debug mode.

  E3. Skeleton UI, empty states, stale indicator (SSE disconnected).
      → Show "⚠ Live updates paused" banner when EventSource.onerror fires.
      → Clear banner when EventSource reconnects (onerror followed by a
        successful message).

Step 8. Build verification.
        → npm run build      (must succeed, zero TypeScript errors)
        → npm run lint       (zero ESLint errors)
        → npx tsc --noEmit   (strict mode; confirms all shared contract
                              types compile cleanly)
        → Verify the exhaustive switch in useSSE.ts: add a temporary fake
          kind to SSEMessageKind (in a local test file) and confirm that
          TypeScript raises an error at the default: never branch.

Step 9. Verify full stack in Docker.
        → docker compose up -d --build frontend
        → curl http://localhost:3000           →  HTML (not connection refused)
        → curl http://localhost:3000/api/health →  {"status": "ok"} (proxy works)
        → Open browser: http://localhost:3000
          Login page must render. Dashboard must load after login.
          /register must render with password strength meter.

Step 10. Run Standard Last Step.
```

---

## Session 11 — Worker Implementation (Celery Tasks)

**Trigger:** `Read CLAUDE.md and execute Session 11.`

**Prerequisite:** Session 9 (Backend) must be complete.
Verify: `curl http://localhost:8000/api/health` returns `{"status": "ok"}`.

```
Step 0. Read CLAUDE.md in full.
        Read CLAUDE_Sessions_prompt.md in full.

Step 1. Read spec/worker_spec.md in full.
        Read design/CLAUDE_worker.md in full.
        Read design/CLAUDE_backend.md §§ Gap 2–4 and Phase D.
        Read design/CLAUDE_infra.md §§ File 1 (docker_runner.py) and
          File 4 (Dockerfile.worker).
        Read spec/interactive_control_spec.md §4 (interrupt gate contract).
        Read spec/sse_contract.md §8 (event kinds and payload shapes).
        Read shared/contracts/README.md (PipelineFunctionId enum values).
        (CLAUDE_worker.md is the single implementation guide for this session.
         CLAUDE_backend.md Phase D provides supplementary context only.
         sse_contract.md is authoritative for all wire-level event details.)

Step 2. Verify prerequisites.

  2a. Schema completeness.
      → All 14 shared types required by interactive_control_spec.md §12
        must be present in shared/contracts/sailor.schema.json:
          PipelineFunctionId, InterruptScope, InterruptStatus,
          InterruptPoint, InterruptInputFile, InterruptResumeRequest,
          InterruptSkipRequest, AutoConfig, AutoConfigPatch,
          FileValidationResult, FileValidationSeverity,
          InterruptCreatedPayload, InterruptResolvedPayload,
          AutoConfigChangedPayload.
      → If any are missing: run ./scripts/regen_contracts.sh first.
        Do NOT proceed past Step 2 with incomplete shared types.

  2b. Database models.
      → Confirm ORM models exist in backend/models/:
          interrupt_point.py  (InterruptPoint with status, input_files,
                               option_overrides, modified_files columns)
          auto_config.py      (AutoConfig JSONB per run_id)
      → If missing: create them and generate + apply a migration before
        writing any task code.
      → Run: alembic upgrade head
             pytest tests/ -v  (existing tests must still pass)

  2c. Docker images.
      → Verify docker/Dockerfile.runner builds:
          docker build -f docker/Dockerfile.runner -t sailor-runner:latest .
      → Verify docker/Dockerfile.worker builds:
          docker build -f docker/Dockerfile.worker -t sailor-worker:latest .
      → If either fails: fix the Dockerfile before continuing.

Step 3. Implement Phase A — Shared Infrastructure.

  A1. Lease management additions to services/spec_service.py.
      → acquire_phase2_lease(), extend_lease(), drop_lease(), persist_turn()
      → All use optimistic locking (UPDATE ... WHERE ... RETURNING id).
      → Zero-row result = lease lost; caller raises CooperativeExit.

  A2. backend/tasks/_control.py
      → CooperativeExit exception class.
      → check_control_flags(session, spec_id, run_id, worker_id, event_service).
        Order: cancel → paused → intervention (process list in order).
      → apply_intervention() dispatcher for all three intervention types.

  A3. backend/tasks/_interrupt.py
      → interrupt_gate(session, function_id, run_id, spec_id, worker_id,
                       event_service, scope, input_files) → dict.
      → Creates InterruptPoint row, publishes interrupt_created SSE.
      → Polls every 2s; calls check_control_flags() in each iteration.
      → Extends lease every 60s while waiting.
      → Returns option_overrides and modified_file_refs on "resumed".
      → Returns {skipped: True} on "skipped".

  A4. run_counters_updated throttle in services/event_service.py.
      → publish_counters_throttled(run_id, counters): max 1 publish/second.
      → Deferred flush if suppressed (asyncio.call_later or asyncio.Task).

  After A1–A4: pytest tests/test_tasks.py::test_interrupt_gate_* -v

Step 4. Implement Phase B — phase1_task.

  B1. backend/tasks/phase1.py
      → Celery task with queue="phase1", acks_late=True,
        reject_on_worker_lost=True.
      → Idempotency guard: run.status != "queued" → return early.
      → DockerRunner(cve_id=run_id, config=RunnerConfig()).
      → 4 interrupt gates (phase1_codeql_build, phase1_codeql_analyze,
        phase1_fact_enrichment, phase1_spec_generation).
      → Default outputs on "skipped" per CLAUDE_worker.md §Gap W7 table.
      → Spec ID: deterministic SHA-256(run_id + rule_id + file + line)[:32].
      → INSERT spec ON CONFLICT DO NOTHING (idempotency).
      → Publish: RunStarted → SpecEmitted/SpecFiltered per finding →
        run_counters_updated (throttled) → enqueue phase2_task per spec.
      → Failure: codeql_build_failure → run.status=failed, RunFailed SSE.
      → runner.stop() in finally block (NON-NEGOTIABLE).

  After B1: pytest tests/test_tasks.py::test_phase1_* -v

Step 5. Implement Phase C — phase2_task.

  C1. backend/tasks/phase2.py — implement in this order:
      C1a. Lease acquisition + heartbeat loop (asyncio.Task, every 30s).
      C1b. State rehydration from last Turn row.
      C1c. Algorithm 1 main loop (T_max / T_explore / T_author budgets).
      C1d. Interrupt gates: phase2_source_exploration, phase2_driver_synthesis,
           phase2_stub_synthesis, phase2_klee_execution,
           phase2_harness_refinement.
      C1e. Turn persistence (atomic: Spec update + Turn insert in one txn).
      C1f. Intervention application for all three types.

  LLM retry: exponential backoff, base 2s, max 5 attempts, cap 60s.
             Gemini 429 follows the same path (see CLAUDE_backend.md Gap 3).
             After 5 failures: spec.phase2_status = "errored".

  Celery config: soft_time_limit=18_000, time_limit=18_060.

  After C1: pytest tests/test_tasks.py::test_phase2_* -v

Step 6. Implement Phase D — phase3_task.

  D1. backend/tasks/phase3.py
      → Lease acquisition (same pattern as Phase 2, for phase3_status).
      → 2 interrupt gates: phase3_asan_build, phase3_replay_execution.
      → Load Phase 2 artifacts: driver.c, slice.c, witness .ktest.
      → runner.build_asan_archive() → asan failure → errored.
      → ReplayDriverGenerator().generate() → replace klee_make_symbolic
        with memcpy of witness bytes.
      → runner.compile_harness() → compile failure → errored.
      → runner.run_asan_replay() → ResultClassifier().classify().
      → Write: asan_report.txt, replay_driver.c, verified_bug.json
        to artifact store.
      → Verdict row: dedup_key = SHA-256(file + func + line)[:32].
      → Update run.counters (unique_confirmed deduplicated by dedup_key).
      → Call _check_run_completion(): if all specs terminal →
        run.status=completed, publish RunCompleted SSE.
      → runner.stop() in finally block.

  After D1: pytest tests/test_tasks.py::test_phase3_* -v

Step 7. Implement Phase E — Logging and Container Streaming.

  E1. Log publication for long-running container steps.
      → _stream_and_log(): background asyncio.Task reading docker logs
        line-by-line during KLEE runs and ASan builds.
      → Each line: write LogLine to DB + publish log_line SSE.
      → Source tags: "klee" for KLEE, "clang" for compile, "asan" for ASan.
      → All worker log.info/warning/error calls also write to DB via
        a custom logging handler.

  E2. Worker heartbeat (idle state).
      → When no spec is leased: publish WorkerHeartbeat every 5s.
      → Status="idle", current_spec_id=null.

Step 8. Implement Phase F — Tests.

  F1. tests/test_tasks.py
      → Full test matrix per CLAUDE_worker.md Phase F.
      → Mock DockerRunner and sailor/ calls via unittest.mock.patch.
      → Use pytest-asyncio + in-memory PostgreSQL (or test DB from conftest).
      → Every test runs in an isolated DB transaction (rollback on teardown).

  F2. Run full test suite.
      → pytest tests/ -v         (all backend + task tests)
      → mypy backend/tasks/ backend/services/ --strict

Step 9. Verify full stack in Docker.

  9a. Build and start all services.
      → docker compose up -d --build worker
      → docker compose logs worker --tail=20  (must show "celery ready")

  9b. Submit a test run using the e2e workspace target.
      → curl -X POST http://localhost:8000/api/runs \
             -F "name=cwe_122_test" \
             -F "project_zip=@tests/e2e_workspace/cwe_122/target.c" \
             -H "Authorization: Bearer <token>"
      → curl http://localhost:8000/api/runs/<run_id>
        Watch for status progression: queued → running → completed.

  9c. Verify SSE event stream.
      → curl -N "http://localhost:8000/api/events?topics=runs.<run_id>&token=<jwt>"
        Events must appear (not silence). Expected kinds in order:
          run_status_changed (running)
          spec_state_changed (emitted) × N
          run_counters_updated
          turn_appended × per spec per turn
          spec_state_changed (terminal) × N
          run_status_changed (completed)

  9d. Verify interrupt functionality.
      This is NOT judged by clicks alone. All checks must be confirmed
      in the backend state store (database), not only in the SSE stream.
      → PATCH /api/runs/<run_id>/auto-config
               {"phase2_klee_execution": false}
      → Confirm interrupt_points row written with status="waiting".
      → Confirm interrupt_created SSE event received.
      → POST /api/runs/<run_id>/interrupts/<id>/skip
      → Confirm interrupt_points row updated to status="skipped".
      → Confirm interrupt_resolved SSE event received.
      → Confirm spec resumes processing (turn_count_total increments in DB).

  9e. Verify pause/resume/cancel propagate to workers.
      → POST /api/runs/<run_id>/pause while run is in progress.
      → Confirm: run.status=paused in DB within 1 turn cycle.
      → Confirm: in-progress spec phase2_status=queued in DB.
      → POST /api/runs/<run_id>/resume.
      → Confirm: spec re-queued and processing resumes.
      → POST /api/runs/<run_id>/cancel.
      → Confirm: run.status=cancelled; specs not yet started → errored.

Step 10. Run Standard Last Step.
```
