# CLAUDE_backend.md — Sailor Backend Implementation Prompt

> Claude Code reads this file during Session: Backend Implementation.
> Stack: FastAPI + Celery + Redis + PostgreSQL + MinIO (S3-compatible).
> All Absolute Rules in CLAUDE.md apply.
> sailor/ pipeline package is imported here — do not re-implement it.

---

## Spec Evaluation: Gaps and Decisions

The uploaded `backend_spec.md` is excellent. The following gaps must be
resolved before or during implementation.

### Gap 1: Framework Choices (spec intentionally left open)

```
Decision:
  Web framework:    FastAPI (async, OpenAPI auto-generation)
  Task queue:       Celery 5.x
  Broker:           Redis (also serves as result backend)
  State Store:      PostgreSQL 15 (ACID, cursor pagination, JSONB for config)
  Artifact Store:   MinIO (S3-compatible, local dev) / S3 (production)
  Event Bus:        Redis Pub/Sub (lossy is acceptable per spec §8.4)
  Push transport:   Server-Sent Events (SSE) via FastAPI StreamingResponse
  Auth:             JWT (access token 15min, refresh token 7 days)
  Secret store:     Environment variables for MVP; HashiCorp Vault reference
                    added to Settings model (§15.6)
```

### Gap 2: Database Schema Decisions

```
ORM: SQLAlchemy 2.x (async) with Alembic migrations

Tables:
  runs          → Run entity (§2.1)
  specs         → Spec entity + lease fields (§9.2)
  turns         → Turn entity, append-only (§2.1)
  verdicts      → Verdict entity (§2.1)
  audit_events  → AuditEvent, append-only (§2.1)
  users         → user_id, role, hashed_password, created_at
  settings      → single-row table (upsert pattern)
  log_lines     → LogLine rows (partitioned by run_id for retention)
  idempotency_keys → (user_id, endpoint, key) → response, expires_at
  export_jobs   → async tarball job tracking (§4.4)
  interventions → intervention payload list per spec (§9.4)
  interrupt_points → interrupt state per function per spec (spec §6)
    interrupt_id      UUID PK
    run_id            FK → runs
    spec_id           FK → specs (nullable — Phase 1 interrupts are run-level)
    function_name     str  e.g. "phase2.klee_execution"
    phase             int  (1 | 2 | 3)
    turn              int  (nullable)
    status            enum "waiting" | "resumed" | "skipped"
    created_at        timestamp
    resumed_at        timestamp (nullable)
    modified_files    JSONB  [{name, artifact_path}]
    option_overrides  JSONB  {klee_timeout, asan_options, ...}
  auto_config   → per-run Auto/Manual settings (spec §5.1)
    run_id            FK → runs (PK)
    config            JSONB  {"phase1.query_execution": true,
                              "phase2.klee_execution": false, ...}
    updated_at        timestamp

JSONB columns:
  runs.config         → RunConfig (queryable fields indexed)
  runs.counters       → RunCounters (updated atomically)
  runs.phase1_summary → Phase1Summary
  specs.*_vars, bounds_hints, build_context → JSONB
  turns.summary       → short string (payload stored in artifact store)
  audit_events.diff   → JSONB before/after

Indexes:
  specs(run_id, phase2_status)   for Phase 2 dispatch queries
  specs(run_id, phase3_status)   for Phase 3 dispatch queries
  specs(worker_id, locked_until) for lease expiry queries
  verdicts(dedup_key)            for deduplication
  log_lines(run_id, created_at)  for log pagination
```

### Gap 3: Open Questions Resolution (§15)

```
§15.1 State Store choice
  Decision: PostgreSQL. ACID + JSONB + cursor pagination + partitioning
  for log_lines. Operational familiarity is high.

§15.2 Event Bus durability
  Decision: Redis Pub/Sub (lossy). Simplicity wins.
  resync_required logic handles gaps (spec §8.4).
  Buffer: Push Service keeps last 60s of events per topic in Redis
  LRANGE for catch-up on reconnect.

§15.3 Task queue retry semantics
  Decision:
    Worker crash → Celery re-queues (task-level retry, max 3)
    LLM API error → orchestrator retries within the task (max 5,
                    exponential backoff). NOT a Celery retry.
  Gemini 429 → sleep 60s, retry once, then raise LLMRateLimitError
  (per CLAUDE_phase2.md LLM Provider Strategy).

§15.4 Artifact store consistency
  Decision: S3 read-after-write consistency (AWS S3 since 2020).
  API never lists artifacts; all access is via stored references (spec §2.2).

§15.5 Cross-run dedup
  Decision: deferred. dedup_key exists in Verdict; cross-run index is
  not built. Frontend §7d comparison works within a run pair via the
  compare endpoint (§4.5).

§15.6 LLM API key isolation
  Decision for MVP: env vars (ANTHROPIC_API_KEY, GEMINI_API_KEY).
  Settings model stores an optional vault_path reference for future
  migration. Keys are never returned by any API endpoint.
```

### Gap 4: Celery Queue Structure (not specified)

```
Queues:
  phase1          max_concurrency=4 (one per run, CPU-bound)
  phase2          max_concurrency=128 (spec-level parallelism)
  phase3          max_concurrency=32 (ASan + build, I/O-bound)
  exports         max_concurrency=4 (tarball generation)
  maintenance     max_concurrency=2 (log archival, retention cleanup)

Task routing:
  phase1_task → phase1 queue
  phase2_task → phase2 queue
  phase3_task → phase3 queue
  export_task → exports queue

Soft timeout: T_max × T_klee = 60 × 300 = 18,000s per phase2_task
Hard timeout: soft + 60s
```

### Gap 5: SSE Implementation Details (not specified)

```
Endpoint: GET /api/events
  Query params: topics=runs.all,runs.<id>.specs (comma-separated)
  Auth: Bearer token in Authorization header (not cookies; SSE spec
        doesn't support custom headers in browser EventSource)
        → Use ?token= query param for browser SSE; validate same as header

SSE reconnect:
  Client sends Last-Event-ID header (standard SSE mechanism)
  Server looks up events since that sequence in Redis LRANGE buffer
  If buffer miss (gap > 60s): push {kind: "resync_required"} immediately

Push Service implementation:
  FastAPI background task subscribes to Redis Pub/Sub
  Per-connection asyncio queue (max 1MB per spec §5.5)
  250ms batching via asyncio.sleep(0.25) flush loop
  Coalescing: counter_diff → keep latest per topic
```

### Gap 6: Artifact Store Abstraction

```
Interface: ArtifactStore (abstract base class)
  async def put(path: str, data: bytes | AsyncIterable) -> str
  async def get(path: str) -> AsyncIterable[bytes]
  async def exists(path: str) -> bool
  async def list_prefix(prefix: str) -> list[ArtifactMeta]
  async def delete(path: str) -> None
  async def presign_get(path: str, expires: int = 300) -> str

Implementations:
  MinIOArtifactStore   (development)
  S3ArtifactStore      (production, same API)
  LocalArtifactStore   (testing only)

The API always returns presigned URLs valid for 300 seconds.
The frontend never sees raw S3 paths.
```

### Gap 7: Missing API Endpoints (found in frontend_spec.md)

The following endpoints appear in frontend_spec.md §13 but are not
in backend_spec.md and must be added:

```
POST /api/runs/:run_id/specs/bulk-requeue    [operator+]
  body: { spec_ids: list[str] }
  effect: requeue multiple specs at once

POST /api/runs/:run_id/specs/bulk-skip       [operator+]
  body: { spec_ids: list[str], reason: string }

GET  /api/runs/:run_id/specs/export          [viewer+]
  query: filter params (same as GET /specs)
  response: NDJSON stream of matching specs

GET  /api/runs/:run_id/workers/:worker_id    [viewer+]
  response: single Worker detail + recent stderr

POST /api/auth/login                         (public)
POST /api/auth/refresh                       (public)
POST /api/auth/logout                        [viewer+]
GET  /api/users                              [admin]
POST /api/users                              [admin]
PATCH /api/users/:user_id                    [admin]
DELETE /api/users/:user_id                   [admin]
```

---

## Project Structure

```
backend/
├── Dockerfile                   # multi-stage build
├── main.py                      # FastAPI app factory + lifespan
├── config.py                    # Settings (pydantic-settings, env vars)
├── database.py                  # SQLAlchemy async engine + session
├── celery_app.py                # Celery app + queue config
│
├── api/                         # FastAPI routers
│   ├── __init__.py
│   ├── auth.py                  # /api/auth/*
│   ├── runs.py                  # /api/runs/*
│   ├── specs.py                 # /api/runs/:id/specs/*
│   ├── artifacts.py             # artifact download + upload
│   ├── logs.py                  # /api/runs/:id/logs
│   ├── workers.py               # /api/runs/:id/workers
│   ├── results.py               # /api/runs/:id/results
│   ├── settings.py              # /api/settings
│   ├── events.py                # GET /api/events (SSE)
│   └── health.py                # /api/health + /api/metrics
│
├── models/                      # SQLAlchemy ORM models
│   ├── __init__.py
│   ├── run.py
│   ├── spec.py
│   ├── turn.py
│   ├── verdict.py
│   ├── audit.py
│   ├── user.py
│   └── log_line.py
│
├── schemas/                     # Pydantic request/response schemas
│   ├── __init__.py
│   ├── run.py
│   ├── spec.py
│   ├── turn.py
│   ├── verdict.py
│   ├── intervention.py
│   ├── event.py
│   └── settings.py
│
├── tasks/                       # Celery task definitions
│   ├── __init__.py
│   ├── phase1.py                # phase1_task
│   ├── phase2.py                # phase2_task
│   ├── phase3.py                # phase3_task
│   └── exports.py               # export_task
│
├── services/                    # Business logic (no HTTP, no Celery)
│   ├── __init__.py
│   ├── run_service.py           # run CRUD + state transitions
│   ├── spec_service.py          # spec CRUD + lease management
│   ├── artifact_service.py      # ArtifactStore abstraction
│   ├── event_service.py         # publish to Redis Pub/Sub
│   ├── push_service.py          # SSE fan-out + batching
│   ├── auth_service.py          # JWT + password hashing
│   ├── audit_service.py         # AuditEvent writes
│   └── export_service.py        # tarball assembly
│
├── middleware/
│   ├── auth.py                  # JWT validation, role injection
│   ├── idempotency.py           # Idempotency-Key header handling
│   └── tracing.py               # trace_id propagation
│
├── migrations/                  # Alembic
│   ├── env.py
│   └── versions/
│
└── tests/
    ├── conftest.py
    ├── test_runs.py
    ├── test_specs.py
    ├── test_interventions.py
    ├── test_sse.py
    └── test_tasks.py
```

---

## Integration with sailor/ Package

```python
# tasks/phase1.py
from sailor.phase1.pipeline import Phase1Pipeline, Phase1Config
from sailor.infra.docker_runner import DockerRunner, RunnerConfig

# tasks/phase2.py
from sailor.phase2.pipeline import Phase2Pipeline, Phase2Config
from sailor.infra.docker_runner import DockerRunner

# tasks/phase3.py
from sailor.phase3.pipeline import Phase3Pipeline, Phase3Config
from sailor.infra.docker_runner import DockerRunner

# The backend NEVER reimplements pipeline logic.
# It only:
#   1. Resolves config from DB → creates PhaseNConfig
#   2. Creates DockerRunner for the run
#   3. Calls PhaseNPipeline(config).run(...)
#   4. Persists results to State Store
#   5. Publishes events to Event Bus
```

---

## `backend/Dockerfile`

```dockerfile
FROM python:3.11-slim AS base

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run Alembic migrations then start Uvicorn
CMD ["sh", "-c", "alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port 8000"]
```

Config reads all values from environment variables (injected by
docker-compose.yml). No hardcoded connection strings.

```python
# config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str              # postgresql+asyncpg://...
    redis_url: str                 # redis://redis:6379/0
    celery_broker_url: str
    celery_result_backend: str
    s3_endpoint: str               # http://minio:9000
    s3_access_key: str
    s3_secret_key: str
    s3_bucket: str = "sailor-artifacts"
    jwt_secret: str
    anthropic_api_key: str = ""
    anthropic_api_option: str = "false"
    gemini_api_key: str

    class Config:
        env_file = ".env"
        case_sensitive = False
```

---

## Claude Code Implementation Prompt

```
Read CLAUDE.md, then read CLAUDE_backend.md in full.

Your goal: implement the Sailor backend API + task workers.

Reference files:
  backend_spec.md     ← authoritative contract (source of truth)
  CLAUDE_backend.md   ← gap resolutions + framework decisions
  frontend_spec.md    ← API surface expected by the UI (§13)
  sailor/             ← pipeline package (import, do not reimplement)

IMPLEMENTATION ORDER:

Phase A — Foundation (implement first, everything depends on this)

  Step A1. Project setup.
           → pyproject.toml with: fastapi, uvicorn, celery, redis,
             sqlalchemy[asyncio], asyncpg, alembic, pydantic-settings,
             python-jose[cryptography], passlib[bcrypt], boto3,
             prometheus-client, httpx (testing)
           → config.py: Settings class reading from env vars
               DATABASE_URL, REDIS_URL, S3_*, JWT_SECRET,
               ANTHROPIC_API_KEY, GEMINI_API_KEY, ANTHROPIC_API_OPTION
           → database.py: async SQLAlchemy engine + session factory
           → celery_app.py: Celery app with queue definitions

  Step A2. Database models (models/).
           → Implement ALL models per §2.1 and Gap 2 above.
           → Generate initial Alembic migration.
           → Run migration; verify all tables created.

  Step A3. Pydantic schemas (schemas/).
           → Request and response schemas for all entities.
           → Discriminated union for Intervention (§6).
           → EventMessage schema (§5.3).

  Step A4. Artifact store abstraction (services/artifact_service.py).
           → ArtifactStore ABC.
           → MinIOArtifactStore implementation.
           → Presigned URL generation (300s TTL).
           → Wire to config: ARTIFACT_STORE=minio|s3|local

  Step A5. Auth (api/auth.py + services/auth_service.py + middleware/auth.py).
           → POST /api/auth/login → JWT access + refresh tokens
           → POST /api/auth/refresh
           → POST /api/auth/logout (token blacklist in Redis)
           → Dependency: get_current_user(token) → User + role
           → Role check decorator: require_role(min_role)

---

Phase B — Core API (implement in this order)

  Step B1. Run operations (api/runs.py + services/run_service.py).
           → POST /api/runs: zip upload, artifact store write, Run create,
             state transition to queued or needs_build_config.
           → GET /api/runs: paginated with cursor.
           → GET /api/runs/:id: full Run.
           → POST /api/runs/:id/build_config
           → POST /api/runs/:id/pause|resume|cancel|clone
           → DELETE /api/runs/:id (soft delete)
           → State transitions per §3.1 — enforce valid transitions.

  Step B2. Spec operations (api/specs.py + services/spec_service.py).
           → GET /api/runs/:id/specs: cursor-paginated, all filter params,
             page_size up to 500.
           → GET /api/runs/:id/specs/:spec_id
           → GET /api/runs/:id/specs/:spec_id/turns (summary only)
           → GET /api/runs/:id/specs/:spec_id/turns/:turn_id (with payload)
           → POST /api/runs/:id/specs/:spec_id/requeue
           → POST /api/runs/:id/specs/:spec_id/skip
           → POST /api/runs/:id/specs/bulk-requeue (Gap 7)
           → POST /api/runs/:id/specs/bulk-skip (Gap 7)

  Step B3. Intervention (api/specs.py §6).
           → POST /api/runs/:id/specs/:spec_id/intervene
           → Discriminated union dispatch: EditHarness|ForceOutcome|EditSpec
           → EditHarness: optimistic concurrency via base_version (→ 409 on conflict)
           → intervention_pending flag + payload stored in interventions table

  Step B4. Artifacts (api/artifacts.py).
           → GET /api/runs/:id/specs/:spec_id/artifacts → tree
           → GET /api/runs/:id/specs/:spec_id/artifacts/*path
             → redirect to presigned URL (or stream via proxy)
             → Range header support for large files
           → POST /api/runs/:id/specs/:spec_id/artifacts.tar.gz
             → enqueue export_task, return 202 + job_id
           → GET /api/jobs/:job_id → poll export status

  Step B5. Results, logs, workers (api/results.py, logs.py, workers.py).
           → GET /api/runs/:id/results (dedup by default)
           → GET /api/runs/:id/results/compare?other=:id
           → POST /api/runs/:id/exports/all-confirmed
           → GET /api/runs/:id/logs (cursor pagination via 'since' token)
           → GET /api/runs/:id/workers
           → GET /api/runs/:id/workers/:worker_id (Gap 7)
           → GET /api/runs/:id/workers/throughput

  Step B6. Auto/Manual config (api/auto_config.py).
           → GET  /api/runs/:id/auto-config
                Returns per-function Auto flags for all 15 pipeline functions.
           → PATCH /api/runs/:id/auto-config
                Body: {"phase2.klee_execution": false}
                Takes effect at next occurrence. Requires: operator role.

  Step B7. Interrupt panel state (api/interrupts.py).
           → GET  /api/runs/:id/interrupts
                Returns list of active interrupts (status="waiting").
           → GET  /api/runs/:id/interrupts/:interrupt_id
                Returns function name, input files (presigned URLs), status.
           → POST /api/runs/:id/interrupts/:interrupt_id/resume
                Body: {modified_files: [{name, content_base64}],
                       option_overrides: {...}}
                Requires: intervener role.
           → POST /api/runs/:id/interrupts/:interrupt_id/skip
                Requires: intervener role.

  Step B8. File validation (api/validate.py + services/validation_service.py).
           → POST /api/validate/file
                Body: {filename: str, content_base64: str}
                Returns: {valid: bool, severity: "error"|"warning"|"info",
                          message: str, detected_format: str}
                Public endpoint — no auth required (validation is stateless).

           ValidatorService.validate(filename, content_bytes) → ValidationResult:
             Dispatch by file type:
               *.sarif, *.json with "runs" key → SARIFValidator
               findings.json                   → FindingsValidator
               fact_packs.json                 → FactPacksValidator
               specifications.json / spec.json → SpecValidator
               *.c                             → CSourceValidator (clang --syntax-only)
               *.ql                            → CodeQLValidator (codeql query compile)
               *.ktest                         → KTestValidator (magic bytes check)
               *.bc                            → BitcodeValidator (magic bytes check)

             SARIFValidator rules (spec §3.19):
               ERROR:   not valid JSON
               ERROR:   missing "runs" array
               WARNING: results count = 0
               WARNING: type mismatch (PDF/ELF/ZIP detected in .sarif file)
             CSourceValidator: run clang --syntax-only inside DockerRunner.
             Returns ValidationResult(valid, severity, message, detected_format)

  Step B9. User registration and management (extend api/auth.py).
           → POST /api/auth/register
                Body: {username, email, password, display_name?}
                Returns: {user_id, username, role: "viewer"}
                Public. First registered user receives admin role.
           → GET  /api/users                  [admin]
           → POST /api/users/:id/role         [admin]
           → DELETE /api/users/:id            [admin]

  Step B10. Phase-level downloads (api/phase_downloads.py).
            → GET /api/runs/:id/phase1/artifacts          (list)
            → GET /api/runs/:id/phase1/artifacts/:filename (presigned redirect)
            → GET /api/runs/:id/phase1/artifacts.tar.gz
            → GET /api/runs/:id/specs/:sid/phase2/artifacts
            → GET /api/runs/:id/specs/:sid/phase2/artifacts/:filename
            → GET /api/runs/:id/specs/:sid/phase2/artifacts.tar.gz
            → GET /api/runs/:id/specs/:sid/phase3/artifacts
            → GET /api/runs/:id/specs/:sid/phase3/artifacts/:filename
            → GET /api/runs/:id/specs/:sid/phase3/artifacts.tar.gz
            → GET /api/runs/:id/specs/:sid/evidence.tar.gz
            → GET /api/runs/:id/results/evidence-all.tar.gz
            All return HTTP 302 presigned redirect (300s TTL).

---

Phase C — Real-Time Push (SSE)

  Step C1. Event service (services/event_service.py).
           → Publish events to Redis Pub/Sub per §8.
           → Event schema per §8.1.
           → Required event types per §8.2.
           → RunCountersUpdated throttled to ≤ 1/second per run.

  Step C2. Push service (services/push_service.py).
           → Subscribe to Redis Pub/Sub channels.
           → Per-connection asyncio queue (drop connection at 1MB).
           → 250ms flush loop with coalescing per §5.4.
           → 60-second replay buffer in Redis LRANGE.

  Step C3. SSE endpoint (api/events.py).
           → GET /api/events?topics=...&token=<jwt>
           → Parse Last-Event-ID for reconnect.
           → If buffer gap: emit {kind: "resync_required"}.
           → Per-topic subscription management.

---

Phase D — Celery Tasks

  Step D1. phase1_task (tasks/phase1.py).
           → Input: run_id
           → Use DockerRunner to execute Phase 1 inside container.
           → Call Phase1Pipeline with prebuilt_sarif=False (full run).
           → Persist Spec rows with deterministic spec_id.
           → Publish events at each step per §7.1.
           → Failure modes: codeql_build_failure → run.status=failed.

  Step D2. phase2_task (tasks/phase2.py).
           → Input: spec_id, continue_from_intervention=False
           → Lease acquisition per §9.2.
           → Lease heartbeat every 30s.
           → Control-flag check at every turn boundary per §7.2:
               1. Check run.status (paused → requeue, cancelled → errored)
               2. Check intervention_pending → apply per §6
           → Call Phase2Pipeline via DockerRunner.
           → Persist Turn row at every turn boundary (transactional).
           → Publish TurnAppended event after each turn.
           → LLM rate limit (Gemini 429): sleep 60s, retry once,
             then raise LLMRateLimitError → spec errored.

  Step D3. phase3_task (tasks/phase3.py).
           → Input: spec_id
           → Lease acquisition.
           → Call Phase3Pipeline via DockerRunner.
           → Build Verdict row + compute dedup_key.
           → Write verified_bug.json to artifact store.
           → Update run.counters.unique_confirmed.
           → Publish SpecPhase3Verdict event.

  Step D4. export_task (tasks/exports.py).
           → Input: job_id, spec_ids[], export_type
           → Stream artifacts from artifact store into tarball.
           → Write tarball to artifact store.
           → Update export_jobs row with result ref.

  Interrupt check in phase1_task, phase2_task, phase3_task:
    At every function boundary where auto_config[function_name] = false:
      1. Write interrupt_points row with status="waiting"
      2. Publish SSE event: {kind: "interrupt_created",
                             interrupt_id, run_id, spec_id, function_name}
      3. Pause task (poll interrupt_points row every 5s)
      4. On status="resumed": apply modified_files + option_overrides, continue
      5. On status="skipped": use default outputs, continue
      6. On run cancel: set status="skipped", continue teardown

    Function boundaries supporting interrupt (spec §3.2):
      Phase 1: db_build, query_execution, sarif_parsing,
               fact_enrichment, spec_generation
      Phase 2: source_exploration, spec_selection, driver_synthesis,
               stub_synthesis, compile_diagnose, klee_execution,
               harness_refinement
      Phase 3: replay_driver_gen, asan_compilation, result_classification

    Note: sailor/ pipeline code has NO knowledge of interrupt_points.
    Interrupt logic lives entirely in backend Celery tasks (Constraint 8).

---

Phase E — Middleware, Health, Metrics

  Step E1. Idempotency middleware (middleware/idempotency.py).
           → Read Idempotency-Key header.
           → Cache (user_id + endpoint + key) → response in Redis, 24h TTL.
           → On cache hit: return cached response, skip handler.

  Step E2. Tracing middleware (middleware/tracing.py).
           → Generate trace_id per request (UUID4).
           → Propagate to Celery tasks via task headers.
           → Include in all log_line rows and LogLine events.

  Step E3. Health + metrics (api/health.py).
           → GET /api/health: check DB, Redis, MinIO connectivity.
           → GET /api/metrics: Prometheus text format.
             Metrics per §13: runs_total, specs_total, turn_duration,
             llm_tokens_total, klee_seconds_total, lease_acquisitions,
             api_request_duration.

---

Phase F — Tests

  Step F1. Database tests (tests/test_runs.py, test_specs.py).
           → Use pytest-asyncio + SQLAlchemy in-memory or test DB.
           → Test all state transitions (§3.1, §3.2, §3.3).
           → Test optimistic concurrency on lease acquisition.
           → Test intervention concurrent edit → 409.

  Step F2. API tests (tests/test_interventions.py).
           → Use httpx.AsyncClient with FastAPI test client.
           → Test all three intervention modes.
           → Test role enforcement (viewer cannot requeue).

  Step F3. SSE tests (tests/test_sse.py).
           → Test subscription, event delivery, coalescing.
           → Test reconnect with Last-Event-ID.
           → Test resync_required when buffer gap detected.

  Step F4. Task tests (tests/test_tasks.py).
           → Mock DockerRunner and sailor/ pipeline calls.
           → Test lease heartbeat + expiry.
           → Test control-flag check (pause/cancel/intervention).
           → Test Gemini 429 → sleep 60s → retry → LLMRateLimitError.

---

CONSTRAINTS (non-negotiable):

1. The backend NEVER executes pipeline code directly.
   Phase 1/2/3 pipeline logic lives in sailor/ and runs inside Docker.
   Tasks only: create DockerRunner, call PipelineN, persist results.

2. All state transitions must be atomic.
   Use UPDATE ... WHERE status IN (...) pattern per §9.1.
   Zero-row match → return current status as 409.

3. Turns are append-only. Never UPDATE a Turn row.

4. Artifact paths are opaque to clients.
   Always return presigned URLs, never raw S3/MinIO paths.

5. intervention_pending is a list, not a bool.
   Process interventions in submission order (§9.4).

6. LLM keys are never returned by any API endpoint.
   Settings PATCH accepts keys; GET /api/settings returns last-4 only.

7. All write endpoints accept Idempotency-Key header.
   Implement idempotency middleware before any handler.

8. Auto/Manual mode must not be enforced inside sailor/ pipeline code.
   sailor/ always runs to completion when called.
   Interrupt logic lives entirely in backend Celery tasks.
   sailor/ pipeline code has no knowledge of interrupt_points.

9. File validation runs server-side only.
   The /api/validate/file endpoint is the single validation point.
   Frontend never validates file structure locally.

10. Phase-level downloads return presigned redirects (HTTP 302).
    Never stream artifact bytes through the FastAPI process.
    Always redirect to MinIO/S3 presigned URLs (300s TTL).

After completing each Phase (A through F):
  → Run: alembic upgrade head (Phase A only)
  → Run: pytest tests/ -v
  → Run: mypy backend/ --strict
  → Verify FastAPI /docs shows all expected endpoints.
```
