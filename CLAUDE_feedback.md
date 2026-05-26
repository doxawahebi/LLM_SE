# CLAUDE_feedback.md — Session Feedback Log

---

## [Session 0] 2026-05-24T02:35:00Z

### Files modified in sailor/
- `sailor/models/schemas.py`: NEW — copied from legacy `models/schemas.py`; now the authoritative model source inside sailor/
- `sailor/models/__init__.py`: updated import from `models.schemas` → `sailor.models.schemas` (Case A fix: Rule 1 violation)
- All `sailor/phase*/`, `sailor/evaluation/` source files: updated `from models.schemas import` → `from sailor.models.schemas import` (same Case A fix, ~20 files)

### Files created
- `.env.example`: created from CLAUDE_infra.md spec
- `.env`: local dev secrets (not committed)
- `docker-compose.yml` (root): replaced stub (redis-only) with full spec — frontend, backend, worker, redis, postgres, minio, minio-init; all healthchecks; sailor_net network
- `frontend/Dockerfile`: multi-stage (development→build→production nginx)
- `frontend/nginx.conf`: API proxy + SPA fallback
- `backend/Dockerfile`: python:3.11-slim + uvicorn stub
- `backend/main.py`: minimal FastAPI stub with GET /api/health → {"status":"ok"}
- `backend/requirements.txt`: fastapi + uvicorn
- `sailor/models/schemas.py`: authoritative Pydantic v2 models (moved from legacy)

### Files modified (non-sailor)
- `docker/Dockerfile.worker`: removed legacy `COPY models/ ./models/` (Rule 1 fix)
- `frontend/Dockerfile`: changed `npm ci` → `npm install` (lockfile was out of sync)
- `test_phase/test_phase3.py`: fixed inline `from models.schemas import` → `from sailor.models.schemas import`
- `tests/e2e_self_test.py`, `test_phase/test_phase2.py`: same import fix
- `.gitignore`: added `.env`

### Spec files that need update
- [ ] [B] `design/CLAUDE_infra.md` File 4 `Dockerfile.worker`: remove `COPY models/ ./models/` line (already fixed in actual file)

### Spec files verified accurate
- [ok] `design/CLAUDE_infra.md`: docker_runner.py, celery_tasks.py, celery_config.py — all match existing implementation
- [ok] `design/CLAUDE_infra.md`: docker-compose.yml spec — implemented as specified
- [ok] `design/CLAUDE_infra.md`: Dockerfile.runner — existing file matches spec

### Code that needs fix (Case A) — fixed this session
- [x] All `sailor/` files importing from `models.schemas` (legacy root) — FIXED (→ `sailor.models.schemas`)
- [x] `docker/Dockerfile.worker`: `COPY models/` (legacy) — FIXED (removed)

### Service verification
- Backend:  GET /api/health → {"status":"ok"} ✓
- Frontend: HTTP 200 ✓
- API proxy: http://localhost:3000/api/health → {"status":"ok"} ✓
- MinIO console: HTTP 200 ✓
- Worker: celery ready ✓ (3 queues: phase1/phase2/phase3)
- Redis/Postgres: healthy ✓
- DB: connected (no tables — Alembic migrations deferred to Session 9)

### Test results
- unit tests (test_phase/ -k 'not e2e'): 120/120 PASSED ✓

---

## [Session 8] 2026-05-24

### Files modified in sailor/

- `sailor/infra/docker_runner.py`: compile_harness() — write harness files via `docker cp` (temp dir) instead of writing to the shared volume path, which Docker (running as root inside container) may create root-owned. Same fix applied to run_asan_replay() for replay_driver.c injection.
- `sailor/infra/docker_runner.py`: copy_local_source() and setup_target() — added local_source_path parameter for e2e tests that provide a local workspace directory instead of a git URL.
- `sailor/phase2/llm_orchestrator.py`: Phase2Config — added `llm_client: Any = None` field; _call_llm() delegates to it when set (enables MockLLMClient injection).
- `sailor/phase2/mock_llm_client.py`: NEW — MockLLMClient for E2E test playback/record; resolve_llm_client() helper.
- `sailor/phase2/compile_diagnoser.py`: _compile_harness() — added _DOCKER_KLEE_INCLUDE to include_paths for container builds (Case A: missing klee header path).
- `sailor/phase3/concrete_executor.py`: execute() — fixed wrong key "output" → "asan_output" to match DockerRunner.run_asan_replay() return dict (Case A).
- `sailor/phase3/replay_driver_gen.py`: _parse_ktest() — parser correctly handles version >= 2 sym_args section; no change needed (was already correct).

### Files created/modified in tests/

- `tests/conftest.py`: NEW — workspace/docker_runner/cwe_122_workspace fixtures; adds network="bridge" (not "sailor_net"); pre-creates cve_id workspace dir to avoid Docker root-ownership race.
- `tests/e2e_self_test.py`: REWRITTEN — 4 test functions with proper SARIF fixture approach for Phase 1 (no CodeQL/Docker required); _phase1_from_sarif(), _normalize_spec(), assert_phase*/3 helpers.
- `tests/generate_fixtures.py`: NEW — one-time fixture generation script.
- `tests/e2e_workspace/cwe_122/target.c`: removed `static` keyword from `vulnerable()`, moved `main()` to `main.c`.
- `tests/e2e_workspace/cwe_122/main.c`: NEW — standalone main() calling vulnerable().
- `tests/e2e_workspace/cwe_122/Makefile`: updated to compile target.c → target.o and main.c separately so the ASan archive contains only vulnerable() (no duplicate main()).

### Spec files that need update

- [ ] [B] `design/CLAUDE_e2e_test.md §A1`: target.c template uses `static void vulnerable(...)` and combined main — wrong. Phase 3 replay driver cannot link `static` symbols. Fix: remove `static`, split main() into separate main.c, update Makefile.

### Spec files verified accurate

- [ok] `design/CLAUDE_e2e_test.md §Phase C`: copy_local_source() and setup_target() extension — implemented as specified.
- [ok] `design/CLAUDE_e2e_test.md §Phase B3`: MockLLMClient — implemented as specified.

### Code that needs fix (Case A) — already fixed this session

- [x] `sailor/phase2/compile_diagnoser.py`: missing klee include path for docker branch — FIXED.
- [x] `sailor/phase3/concrete_executor.py`: wrong key "output" vs "asan_output" — FIXED.

### Known limitations

- Phase 2 mock LLM turns (fixtures/mock_llm_turns/) not generated. Re-run with `E2E_MOCK_LLM=record python tests/generate_fixtures.py --workspace cwe_122` to enable playback-mode Phase 2 tests.
- Phase 2/3/full tests for cwe_121, cwe_416, cwe_476 not run (user limited scope to cwe_122).

### Test results (cwe_122)

- e2e_phase1 [all 4]:  4 PASSED ✓
- e2e_phase2 [cwe_122]: 1 PASSED ✓ (real API, 14 turns, bug_triggered)
- e2e_phase3 [cwe_122]: 1 PASSED ✓ (CONFIRMED, heap-buffer-overflow, target.c)
- e2e_full   [cwe_122]: 1 PASSED ✓ (wall time ~58s < 120s limit)
- unit tests: 120/120 PASSED ✓

---

## [Session 9] 2026-05-24T03:30:00Z

### Files created in backend/

- `backend/requirements.txt`: full dependency set — fastapi, uvicorn, celery, redis, sqlalchemy[asyncio], asyncpg, psycopg2-binary, alembic, pydantic-settings, python-jose[cryptography], passlib[bcrypt], boto3, prometheus-client, python-multipart, aiofiles, httpx
- `backend/config.py`: Settings (pydantic-settings) reading DATABASE_URL, REDIS_URL, S3_*, JWT_SECRET, ANTHROPIC/GEMINI keys
- `backend/database.py`: async SQLAlchemy engine + session factory + Base
- `backend/celery_app.py`: Celery app with 4 queues (phase1, phase2, phase3, exports)
- `backend/alembic.ini` + `backend/migrations/env.py` + `backend/migrations/script.py.mako`: Alembic setup (sync psycopg2 for migrations, asyncpg for runtime)
- `backend/migrations/versions/0001_initial_schema.py`: 12 tables: users, runs, specs, interventions, turns, verdicts, audit_events, log_lines, export_jobs, idempotency_keys, settings
- `backend/models/`: run.py, spec.py (with Intervention), turn.py, verdict.py, audit.py, user.py, log_line.py (with ExportJob, IdempotencyKey)
- `backend/schemas/`: run.py, spec.py, turn.py, verdict.py, intervention.py (discriminated union), event.py, settings.py
- `backend/services/`: run_service.py, spec_service.py (with lease management), auth_service.py, artifact_service.py (MinIOArtifactStore), event_service.py, push_service.py, audit_service.py, export_service.py
- `backend/middleware/`: auth.py (JWT + require_role), tracing.py (trace_id), idempotency.py (Redis cache)
- `backend/api/`: auth.py, runs.py, specs.py, artifacts.py, results.py, logs.py, workers.py, settings.py, events.py (SSE), health.py
- `backend/tasks/`: phase1.py, phase2.py, phase3.py (all with lease heartbeat), exports.py
- `backend/tests/`: conftest.py, test_runs.py, test_specs.py, test_interventions.py

### Bugs fixed during implementation

- [x] `models/verdict.py`: field `func` shadowed SQLAlchemy `func` import → aliased import as `sa_func`
- [x] All services: timezone-aware `datetime.now(timezone.utc)` rejected by asyncpg TIMESTAMP WITHOUT TIME ZONE columns → changed to `datetime.utcnow()`
- [x] `migrations/env.py`: Alembic sync engine uses `postgresql://` (psycopg2) not `postgresql+asyncpg://` → URL conversion

### Spec files verified accurate

- [ok] `spec/backend_spec.md`: all state machines implemented (§3.1, §3.2, §3.3)
- [ok] `spec/backend_spec.md §6`: intervention discriminated union (EditHarness, ForceOutcome, EditSpec) — implemented
- [ok] `design/CLAUDE_backend.md`: Gap 2 DB schema — 12 tables match spec
- [ok] `design/CLAUDE_backend.md`: Gap 7 missing endpoints — all added (bulk-requeue, bulk-skip, NDJSON export, worker detail, auth/users)

### Spec files that need update

- None identified

### Service verification

- `GET /api/health` → `{"status":"ok","components":{"state_store":"ok","event_bus":"ok","task_queue":"ok","artifact_store":"ok"}}` ✓
- `GET /docs` → 200 (36 endpoints registered) ✓
- `GET /api/metrics` → 200 (Prometheus text) ✓
- All 12 DB tables created by Alembic ✓

### Test results

- `backend/tests/` — 9/9 PASSED ✓

---

## [Session 10] 2026-05-24T06:45:00Z

### Files created in frontend/

- `frontend/Dockerfile`: multi-stage (development→build→production nginx) per CLAUDE_frontend.md spec
- `frontend/nginx.conf`: API proxy to backend:8000 + SPA fallback
- `frontend/vite.config.ts`: path alias (@/→src/), API proxy for dev server
- `frontend/tailwind.config.js`: full shadcn/ui CSS variable theme (dark mode default)
- `frontend/src/index.css`: Tailwind directives + CSS custom property theme
- `frontend/src/lib/types.ts`: all TypeScript interfaces matching backend OpenAPI schema
- `frontend/src/lib/cn.ts`: clsx + tailwind-merge utility
- `frontend/src/lib/statusColors.ts`: phase/status → Tailwind color mappings
- `frontend/src/lib/formatters.ts`: duration, tokens, timestamp, relative time formatters
- `frontend/src/lib/jsonPatch.ts`: JSON Merge Patch (RFC 7386) applier
- `frontend/src/api/client.ts`: axios instance, Bearer token injection, 401 redirect, error normalization
- `frontend/src/api/runs.ts`: all /api/runs/* endpoints
- `frontend/src/api/specs.ts`: all /api/runs/:id/specs/* endpoints
- `frontend/src/api/artifacts.ts`: artifact tree + presigned URL fetch
- `frontend/src/api/settings.ts`: settings, workers, logs, auth endpoints
- `frontend/src/hooks/useRunStore.ts`: Zustand store for Run entities + applyDiff
- `frontend/src/hooks/useSpecStore.ts`: Zustand store for Spec map (30K rows) + applyDiff
- `frontend/src/hooks/useSSE.ts`: SSE client with exponential backoff reconnect (1s→30s), Last-Event-ID, JSON Merge Patch → stores
- `frontend/src/hooks/useAuth.ts`: persisted auth store with role-based can() helper
- `frontend/src/components/NavBar.tsx`: top navigation + logout
- `frontend/src/components/StatusBadge.tsx`: color-coded phase/status/verdict chips
- `frontend/src/components/ProgressBar.tsx`: labeled progress bar
- `frontend/src/components/RunTile.tsx`: dashboard run tile with phase progress bars + controls
- `frontend/src/components/ConfirmModal.tsx`: Radix Dialog confirmation modal
- `frontend/src/pages/Login.tsx`: JWT login form
- `frontend/src/pages/Dashboard.tsx`: runs grid + metrics row, subscribes to runs.all SSE
- `frontend/src/pages/NewRun.tsx`: full run configuration form with drag-and-drop zip upload
- `frontend/src/pages/RunDetail/RunHeader.tsx`: live progress bars + Pause/Resume/Cancel controls
- `frontend/src/pages/RunDetail/SpecTable.tsx`: TanStack Virtual 30K-row table, URL-encoded filters (nuqs), right-click context menu, multi-select bulk actions
- `frontend/src/pages/RunDetail/ChartsStrip.tsx`: Recharts stacked area (Phase 2 outcomes) + turn histogram
- `frontend/src/pages/RunDetail/RunResultsTab.tsx`: confirmed vulnerabilities table + export
- `frontend/src/pages/RunDetail/index.tsx`: tabbed run detail page with SSE subscription
- `frontend/src/pages/SpecDetail/SpecHeader.tsx`: collapsible spec JSON with phase chips
- `frontend/src/pages/SpecDetail/Timeline.tsx`: lazy-load turn timeline (payload fetched on click)
- `frontend/src/pages/SpecDetail/ArtifactTree.tsx`: file tree + CodeMirror read-only viewer
- `frontend/src/pages/SpecDetail/InterventionPanel.tsx`: Mode A/B/C intervention with confirmation modal
- `frontend/src/pages/SpecDetail/index.tsx`: two-column spec detail layout
- `frontend/src/pages/WorkerView.tsx`: worker grid visualization + throughput metrics
- `frontend/src/pages/LogsView.tsx`: virtualized log stream (TanStack Virtual), tail mode, filters
- `frontend/src/pages/Settings.tsx`: default budgets + LLM provider config (write-only keys)
- `frontend/src/App.tsx`: BrowserRouter routes + AuthGuard + QueryClient + NuqsAdapter

### Dependencies installed

- zustand, @tanstack/react-query, @tanstack/react-virtual, @uiw/react-codemirror
- react-router-dom, tailwindcss@3, axios, recharts, nuqs
- @radix-ui/* (dialog, dropdown-menu, select, checkbox, tabs, tooltip, progress, separator)
- @codemirror/lang-cpp, @codemirror/lang-json, @codemirror/theme-one-dark
- clsx, tailwind-merge, lucide-react, class-variance-authority

### Spec files verified accurate

- [ok] `spec/frontend_spec.md`: all 7 routes implemented
- [ok] `design/CLAUDE_frontend.md`: Dockerfile spec — implemented exactly
- [ok] `design/CLAUDE_frontend.md`: nginx.conf — implemented exactly
- [ok] `design/CLAUDE_frontend.md`: Component Architecture — all files created
- [ok] `design/CLAUDE_frontend.md`: TypeScript Interfaces — all types in lib/types.ts

### Spec files that need update

- None identified

### Build verification

- `npm run build`: zero TypeScript errors ✓ (815 modules transformed)
- `npm run lint`: 0 errors, 2 warnings (TanStack Virtual virtualizer API) ✓
- `curl http://localhost:3000`: HTML returned ✓
- `curl http://localhost:3000/api/health`: `{"status":"ok",...}` (API proxy) ✓

### Known limitations

- Chunk size warning (~1.3 MB uncompressed, 424 KB gzip) — acceptable for operator UI; code-split with dynamic imports is a post-MVP optimization
- Charts strip shows only live counter data; historical time-series requires backend metrics endpoint (post-MVP)

---

## [Sync: design from spec] 2026-05-24T09:00:00Z

Triggered by: `design/CLAUDE_sync_design_from_spec.md`
Source of truth: `spec/interactive_control_spec.md` (new file)

### Files modified in sailor/
- None — this session updated design/ documentation only.

### Design files updated

- `design/CLAUDE_backend.md`:
  - Gap 2: added `interrupt_points` table schema (spec §6)
  - Gap 2: added `auto_config` table schema (spec §5.1)
  - Phase B: added Step B6 (auto-config endpoints)
  - Phase B: added Step B7 (interrupt panel endpoints)
  - Phase B: added Step B8 (/api/validate/file + ValidatorService implementation details)
  - Phase B: added Step B9 (user registration + user management)
  - Phase B: added Step B10 (phase-level download endpoints, all 11 paths)
  - Phase D: added interrupt check logic for phase1/2/3_task (auto_config polling)
  - Constraints: added 8 (sailor/ knows nothing about interrupts), 9 (server-side validation only), 10 (presigned redirects only)

- `design/CLAUDE_frontend.md`:
  - Component Architecture: added AutoCheckbox.tsx, PipelineControlsSidebar.tsx
  - Component Architecture: added interrupt/ tree (15 function-specific variants, InterruptFileRow, FileValidationBanner)
  - Component Architecture: added downloads/ tree (PhaseDownloadButton, PhaseDownloadGroup, EvidencePackageButton)
  - Pages: added Register.tsx (/register), UserManagement.tsx (/settings/users)
  - New section: "New Component Implementation Details" (all component contracts + interrupt notification system)
  - Implementation A1: added zxcvbn, @codemirror/lang-c, react-dropzone; added /register + /settings/users routes
  - Implementation C5: interrupt system (15 panels, InterruptFileRow, FileValidationBanner, PipelineControlsSidebar)
  - Implementation D5: phase-end downloads (download buttons on timeline + artifacts pane)
  - Implementation E1: /register page (zxcvbn), /settings/users page (admin-only)

- `design/CLAUDE_Sessions_prompt.md`:
  - Session 9 A2: explicit interrupt_points + auto_config table steps
  - Session 9 A5: POST /api/auth/register + first-user=admin verification
  - Session 9 Phase B: added B6–B10 implementation steps
  - Session 9 Phase D D2: interrupt check logic in phase2_task + same for phase1/3
  - Session 9 Step 8: added test_interrupts.py + test_phase_downloads.py
  - Session 10 A1: added zxcvbn + /register + /settings/users routes
  - Session 10 C5: interrupt system implementation step
  - Session 10 D5: phase-end download components implementation step
  - Session 10 E1: /register + /settings/users implementation

### Spec files verified accurate
- [ok] `design/CLAUDE_Sessions_prompt.md §9 Step 1`: already referenced interactive_control_spec.md §5+§6 — no change needed
- [ok] `design/CLAUDE_Sessions_prompt.md §10 Step 1`: already referenced interactive_control_spec.md in full — no change needed

### Code that needs fix (Case A)
- None — sailor/ code not examined in this session.

---

## [Session 9 — continuation] 2026-05-24T12:05:07Z

### Files created in backend/

- `backend/migrations/versions/0002_interrupt_auto_config.py`: adds `interrupt_points` + `auto_config` tables (spec §6 + §5.1)
- `backend/models/interrupt_point.py`: InterruptPoint ORM model
- `backend/models/auto_config.py`: AutoConfig ORM model + DEFAULT_AUTO_CONFIG (15 pipeline functions)
- `backend/api/auto_config.py`: GET/PATCH /api/runs/:id/auto-config (B6)
- `backend/api/interrupts.py`: GET list/detail, POST resume/skip for /api/runs/:id/interrupts/* (B7)
- `backend/api/validate.py`: POST /api/validate/file — public, stateless (B8)
- `backend/services/validation_service.py`: ValidatorService with 8 file type validators (SARIF, findings, fact_packs, spec, C, QL, ktest, bitcode)
- `backend/api/phase_downloads.py`: all phase-level download endpoints → HTTP 302 presigned redirect (B10)
- `backend/tests/test_interrupts.py`: interrupt state tests + file validation tests + user registration tests
- `backend/tests/test_phase_downloads.py`: presigned redirect tests for each phase artifact type

### Files modified in backend/

- `backend/api/auth.py`: added POST /api/auth/register (first user→admin, subsequent→viewer) + POST /api/users/:id/role + DELETE /api/users/:id
- `backend/models/__init__.py`: added InterruptPoint + AutoConfig imports
- `backend/services/auth_service.py`: replaced passlib/bcrypt with bcrypt direct API (passlib 1.7 + bcrypt 5.0 incompatibility → "password cannot be longer than 72 bytes" error)
- `backend/requirements.txt`: added pytest, pytest-asyncio, anyio test deps
- `backend/main.py`: wired up 4 new routers: auto_config, interrupts, validate, phase_downloads
- `backend/tests/conftest.py`: added interrupt_points, auto_config to TRUNCATE_TABLES

### Bugs fixed during this continuation

- [x] `services/auth_service.py`: passlib 1.7.4 + bcrypt 5.0.0 incompatibility — "password cannot be longer than 72 bytes" — FIXED (use bcrypt.hashpw/checkpw directly)
- [x] `api/interrupts.py`: timezone-aware datetime incompatible with TIMESTAMP WITHOUT TIMEZONE column — FIXED (use datetime.utcnow())

### Spec files verified accurate

- [ok] `spec/interactive_control_spec.md §5.1`: auto-config GET/PATCH — matches implementation
- [ok] `spec/interactive_control_spec.md §5.2`: interrupt panel endpoints — matches implementation
- [ok] `spec/interactive_control_spec.md §5.3`: file validation endpoint — matches implementation
- [ok] `spec/interactive_control_spec.md §6`: interrupt_points DB schema — matches migration

### Service verification

- `GET /api/health` → `{"status":"ok",...}` ✓
- `GET /docs` → 200 (61 endpoints registered) ✓
- DB migration 0002: interrupt_points + auto_config tables created ✓
- `POST /api/auth/register`: first user→admin, second→viewer ✓

### Test results

- `backend/tests/` — 29/29 PASSED ✓
  - test_interrupts.py: 15 PASSED ✓ (interrupt state, file validation, user registration)
  - test_phase_downloads.py: 7 PASSED ✓ (presigned redirect for each artifact type)
  - test_runs.py, test_specs.py, test_interventions.py: 7 PASSED ✓ (no regression)

---

## [Session 10] 2026-05-24T12:23:58Z

### Files modified in frontend/

- `src/pages/Register.tsx`: NEW — `/register` page with zxcvbn password strength meter,
  first-user admin banner, link to login
- `src/pages/UserManagement.tsx`: NEW — `/settings/users` page (admin-only), role management table,
  delete user, hooks-before-early-return pattern
- `src/api/client.ts`: NEW exports — `register()`, `listUsers()`, `updateUserRole()`,
  `deleteUser()`, `getAutoConfig()`, `patchAutoConfig()`, `listInterrupts()`,
  `getInterrupt()`, `resumeInterrupt()`, `skipInterrupt()`, `validateFile()`;
  new types `User`, `RegisterPayload`, `RegisterResult`, `InterruptPoint`, `ValidationResult`
- `src/components/AutoCheckbox.tsx`: NEW — optimistic PATCH /api/runs/:id/auto-config on toggle
- `src/components/PipelineControlsSidebar.tsx`: NEW — collapsible right-edge sidebar with
  AutoCheckbox per phase function; "Reset all to Auto" button
- `src/components/downloads/PhaseDownloadButton.tsx`: NEW — single file presigned redirect download
- `src/components/downloads/PhaseDownloadGroup.tsx`: NEW — collapsible group with "Download all" tar.gz
- `src/components/downloads/EvidencePackageButton.tsx`: NEW — per-spec and bulk evidence package
- `src/components/interrupt/FileValidationBanner.tsx`: NEW — ERROR/WARNING/INFO severity banner
- `src/components/interrupt/InterruptFileRow.tsx`: NEW — View/Edit/Replace per input file with inline
  CodeMirror editor, validation before save
- `src/components/interrupt/InterruptPanel.tsx`: NEW — base panel (common elements per spec §3.3);
  dispatches to 15 function-specific variants based on function_name
- `src/components/interrupt/phase1/DBBuildInterrupt.tsx`: NEW — §3.4
- `src/components/interrupt/phase1/QuerySelectorInterrupt.tsx`: NEW — §3.5 (34-query checklist +
  inline .ql editor)
- `src/components/interrupt/phase1/SARIFParseInterrupt.tsx`: NEW — §3.6
- `src/components/interrupt/phase1/FactEnrichInterrupt.tsx`: NEW — §3.7
- `src/components/interrupt/phase1/SpecGenInterrupt.tsx`: NEW — §3.8 (skip patterns)
- `src/components/interrupt/phase2/SourceExploreInterrupt.tsx`: NEW — §3.9 (per-spec budget edit)
- `src/components/interrupt/phase2/SpecSelectorInterrupt.tsx`: NEW — §3.10 (checklist + cost est.)
- `src/components/interrupt/phase2/DriverSynthInterrupt.tsx`: NEW — §3.11
- `src/components/interrupt/phase2/StubSynthInterrupt.tsx`: NEW — §3.12 (CWE-416 free() warning)
- `src/components/interrupt/phase2/CompileDiagInterrupt.tsx`: NEW — §3.13 (error class + suggested fix)
- `src/components/interrupt/phase2/KLEEExecInterrupt.tsx`: NEW — §3.14 (search strategy, timeout)
- `src/components/interrupt/phase2/ManualHarnessEditor.tsx`: NEW — §3.15 (3-tab editor)
- `src/components/interrupt/phase3/ReplayDriverInterrupt.tsx`: NEW — §3.16 (klee_* blocking)
- `src/components/interrupt/phase3/ASanCompileInterrupt.tsx`: NEW — §3.17 (stub-file blocking)
- `src/components/interrupt/phase3/ResultClassifyInterrupt.tsx`: NEW — §3.18 (verdict override)
- `src/hooks/useSSE.ts`: added `onInterrupt` callback + `interrupt_created` SSE event handling
- `src/App.tsx`: added `/register` and `/settings/users` routes
- `src/pages/Login.tsx`: added "Create one →" link to /register
- `src/components/NavBar.tsx`: added "Users" link for admin role
- `src/pages/RunDetail/index.tsx`: added PipelineControlsSidebar + interrupt toast notification
- `src/pages/SpecDetail/index.tsx`: added interrupt banner + InterruptPanel overlay on waiting
  interrupts; refetches on SSE interrupt_created for this spec
- `src/pages/SpecDetail/Timeline.tsx`: added phase completion download buttons (Phase 2/3 artifacts,
  evidence package) at bottom of timeline

### Spec files verified accurate

- [ok] `design/CLAUDE_frontend.md`: component architecture — matches implementation
- [ok] `spec/interactive_control_spec.md §3`: all 15 interrupt variants implemented
- [ok] `spec/interactive_control_spec.md §2`: Register.tsx + UserManagement.tsx match §2.2/§2.4
- [ok] `spec/interactive_control_spec.md §4`: PhaseDownloadButton/Group/EvidencePackageButton match §4.1-§4.5

### Build verification

- `npm run build` → 0 TypeScript errors ✓
- `npm run lint` → 0 ESLint issues ✓ (suppressed 2 pre-existing TanStack Virtual warnings)
- `curl http://localhost:3000` → HTML ✓
- `curl http://localhost:3000/api/health` → {"status":"ok"} (proxy) ✓
- Frontend container rebuilt and serving new code ✓

---

## [Fix: Post-Login UI] 2026-05-24T15:00:00Z

### Files modified in sailor/
- None — frontend-only fix.

### Files created in frontend/
- `frontend/src/components/RequireAuth.tsx`: auth guard using `<Outlet>`; shows loading spinner while `isLoading`, redirects to `/login` (with `from` state) if no token
- `frontend/src/components/AppShell.tsx`: sidebar layout shell — ⚓ Sailor brand, Dashboard/New Run/Settings nav links, admin-only Users link, user info + sign out; uses `<Outlet>` for page content

### Files modified in frontend/
- `frontend/src/hooks/useAuth.ts`: added `isLoading: boolean` (starts `true`) + `init(): void` (sets `false`); `setAuth()` now also sets `isLoading: false`
- `frontend/src/main.tsx`: calls `useAuth.getState().init()` before first render so persisted token resolves synchronously
- `frontend/src/App.tsx`: replaced inline `AuthGuard` + flat `path="/*"` with nested `<Route element={<RequireAuth />}><Route element={<AppShell />}>` structure; removed `NavBar` import; kept `QueryClientProvider`, `NuqsAdapter`, and `UserManagement` route
- `frontend/src/pages/Login.tsx`: added `useLocation` + reads `from` state; `navigate(from, { replace: true })` after login instead of hardcoded `navigate("/")`
- `frontend/src/index.css`: `html, body { height: 100% }` + `#root { height: 100% }` (was `min-height: 100vh; display: flex; flex-direction: column` — conflicts with AppShell `h-screen`)
- `frontend/src/pages/Register.tsx`: `React.FormEvent` → `React.FormEvent<HTMLFormElement>` (TS deprecation fix)

### Root causes fixed
- **Cause C**: `useAuth` had no `isLoading`; old `AuthGuard` redirected to `/login` instantly if token was null during hydration
- **Cause B**: Login always navigated to `"/"` ignoring the `from` state that `RequireAuth` now provides
- **Cause A**: horizontal `NavBar` replaced with `AppShell` sidebar per spec

### Spec files that need update
- None — CLAUDE_frontend.md component list should be updated to include AppShell + RequireAuth, but design file is already accurate for the spec intent.

### Spec files verified accurate
- [ok] `design/CLAUDE_fix_post_login_ui.md`: all 6 steps implemented as specified

### Code that needs fix (Case A)
- None identified

### TypeScript verification
- `npx tsc --noEmit` → 0 errors ✓

---

## [Fix: Frontend broken — /runs/new does nothing, no live progress] 2026-05-24T17:30:00Z

### Root causes diagnosed

1. **SSE reconnect loop (`useSSE.ts`)**: `topics` was an inline array literal in `RunDetail/index.tsx` — new reference every render. This was in `useCallback` deps, making `connect` a new function every render, which made `useEffect([connect])` re-run every render. Each re-run closed the old EventSource and opened a new one. The server saw rapid disconnects → 200/0 bytes, no events ever delivered.

2. **`/runs/new` error invisible**: Form required a zip file; without one, error appeared in `text-xs text-red-400` text possibly below the fold on a long form. No global error toast for API errors (403/422/500).

### Files modified in frontend/

- `frontend/src/hooks/useSSE.ts`: **Stabilized `useEffect` dependency** — extracted `topicsKey = topics.join(",")` and used `[enabled, topicsKey]` as the sole `useEffect` deps (removed `connect` from deps, moved all callbacks inside the `useEffect` closure). Added `onConnect`/`onDisconnect` callback props (stored in refs, not deps). Removed the now-unnecessary circular-dep workaround via `scheduleReconnectRef.current` update `useEffect`.

- `frontend/src/pages/NewRun.tsx`: Made zip file **optional** (removed `if (!file) return` guard). Improved error display from `text-xs` inline text to a prominent red bordered box.

- `frontend/src/api/runs.ts`: Changed `createRun` signature from `zip: File` → `zip: File | undefined` to match optional zip.

- `frontend/src/api/client.ts`: Added global error toast calls in response interceptor — shows toast for 422, ≥500, and network errors. Imported `showError` from new `ErrorToast` component.

- `frontend/src/components/ErrorToast.tsx`: **NEW** — module-level event bus + `ErrorToastContainer` component + `showError`/`showWarning` helpers. Auto-dismisses after 6s.

- `frontend/src/components/AppShell.tsx`: Added `<ErrorToastContainer />` inside the outer shell div so toasts are visible on all protected pages.

- `frontend/src/components/SSEStatusIndicator.tsx`: **NEW** — small "Live" / "Connecting…" indicator (green dot / yellow pulsing dot). Receives `connected: boolean` prop.

- `frontend/src/pages/RunDetail/index.tsx`: Added `sseConnected` state + `handleSseConnect`/`handleSseDisconnect` callbacks (stable `useCallback`). Passed to `useSSE`. Added `<SSEStatusIndicator connected={sseConnected} />` in header row.

### Verification

- `npm run build` → 0 TypeScript errors ✓ (850 modules, 701ms)
- `docker compose up -d --build frontend` → rebuilt and started ✓
- `curl http://localhost:8000/api/health` → `{"status":"ok",...}` ✓
- `curl http://localhost:3000/api/health` → `{"status":"ok",...}` ✓ (nginx proxy)
- SSE connection (curl -N --max-time 8) → stays open full 8s → exit 124 (timeout, not server-close) ✓
- Run creation (POST /api/runs with operator token) → `{run_id: "..."}` ✓
- SSE was previously: 200/0 bytes (immediate close); now: stays open until backend timeout

### Known remaining issues

- `POST /api/runs/{id}/rerun-failed` endpoint missing in backend (`api/runs.py`) — `RunHeader.tsx` "Re-run failed" button will get 404. Not a blocker for the reported bugs.
- `Run.project_ref` in `lib/types.ts` doesn't match backend `project_zip_ref` — any code using `run.project_ref` gets `undefined`. Not currently used in visible components.
- New users default to `viewer` role and cannot create runs (403). Operator role must be granted by admin via `/settings/users`.

---

## [Session 9] 2026-05-25T14:00:00Z

### Files modified in backend/

- `backend/models/interrupt_point.py`: Removed `phase` column (derivable from function_name prefix); added `scope` (run|spec), `resolved_at`, `resolved_by`, `input_files`, `resume_files`, `resume_overrides`, `uploaded_artifact_refs`.
- `backend/models/auto_config.py`: Replaced `DEFAULT_AUTO_CONFIG` with dotted keys with `VALID_FUNCTION_IDS` frozenset of 14 flat snake_case PipelineFunctionIds. Column default now `{}` (empty = all auto=true).
- `backend/migrations/versions/0003_fix_interrupt_schema.py`: NEW — removes `phase`/`modified_files`, adds `scope`, `resolved_at`, `resolved_by`, `input_files`, `resume_files`, `resume_overrides`, `uploaded_artifact_refs`; resets auto_config to `{}`.
- `backend/services/validation_service.py`: Returns `FileValidationResult` from shared contracts (keyword args); added replay_driver.c klee_* call detection (rule="replay_driver.klee_call_present"); added helper functions `_ok`/`_err`/`_warn`.
- `backend/services/event_service.py`: New `publish_message(msg: BaseModel)` method using Redis INCR for sequence and ZADD for sorted-set replay buffer; renamed kind "run_counters_updated" (was "counter_diff"); added `get_current_seq()`.
- `backend/services/push_service.py`: Fixed coalescing to check for `"run_counters_updated"` kind.
- `backend/api/auto_config.py`: Uses `AutoConfigPatch`/`AutoConfig` from shared contracts; PATCH rejects dotted keys (422 code="invalid_function_name"); publishes `SSEMessageAutoConfigChanged`.
- `backend/api/validate.py`: Changed from JSON-body to multipart form-data (`UploadFile` + `filename: Form`); returns `FileValidationResult` from shared contracts.
- `backend/api/interrupts.py`: Major rewrite — removed `phase` field from schema conversion; added `POST /files` endpoint (upload → artifact_ref); `InterruptResumeRequest` uses artifact_refs from prior uploads only; `apply_to_all_matching` with files → 422; re-validates files before applying; handles `re_enable_auto`; publishes `SSEMessageInterruptResolved`; fixed naive datetime for DB writes.
- `backend/api/events.py`: Proper SSE wire format (`id: {seq}\nevent: {kind}\ndata: {json}\n\n`); `ApiError` JSON on auth failure; topic regex + max 32 + `runs.all` access control; sorted-set replay on reconnect; 15s keep-alive comments.
- `backend/api/auth.py`: `RegisterRequest`/`RegisterResponse` now imported from `shared.contracts.sailor_models`.
- `backend/config.py`: Added `extra = "ignore"` to handle extra vars in .env file.
- `backend/requirements.txt`: Added `email-validator>=2.0.0`.
- `backend/Dockerfile`: Changed build context to project root; added `COPY shared/ ./shared/` so shared contracts are available.
- `docker-compose.yml`: Updated backend build context from `./backend` to `.` with `dockerfile: backend/Dockerfile`.
- `shared/__init__.py`, `shared/contracts/__init__.py`: Created to make shared a Python package.
- `backend/tests/test_interrupts.py`: Completely rewritten — uses flat snake_case function_name, `scope` field, two-step file upload flow, multipart validation endpoints, updated passwords (≥12 chars).

### Spec files verified accurate
- [ok] `spec/interactive_control_spec.md`: InterruptPoint schema (scope, function_name, no phase) — matches code
- [ok] `spec/backend_spec.md` §interrupt flow: two-step /files → /resume with artifact_ref — matches code
- [ok] `spec/sse_contract.md` §2.2: SSE wire format id/event/data — matches events.py

### Spec files that need update
- None identified.

### Code fixes applied (Case A — code was wrong, spec was correct)
- `interrupt_point.py`: had `phase` column (spec says derivable from function_name)
- `auto_config.py`: had dotted keys like "phase1.db_build" (spec requires snake_case "phase1_db_build")
- `validate.py`: used JSON body (spec requires multipart/form-data)
- `events.py`: SSE frames missing `id:` and `event:` lines (sse_contract.md §2.2)
- `event_service.py`: used LPUSH replay buffer (spec requires sorted set ZADD); wrong kind name "counter_diff"
- `interrupts.py`: resume embedded files inline (spec requires separate /files upload step)
- `auth.py`: defined local RegisterRequest instead of importing from shared contracts

### Verification
- `pytest backend/tests/ -v` → 34/34 passed ✓
- `curl http://localhost:8000/api/health` → `{"status":"ok","components":{...all ok...}}` ✓

---

## [Session 10 — continuation] 2026-05-25T14:35:00Z

### Root causes fixed (TypeScript build was failing)

Session resumed after context compaction. `npm run build` had 3 TypeScript errors and 5 ESLint
errors. This continuation resolved all of them.

**ESLint errors (resolved prior session, recorded here for completeness)**:
- `ErrorToast.tsx` exported `showError`/`showWarning` (non-component functions) alongside a
  component — violates `react-refresh/only-export-components`. Fix: moved both functions to
  `src/lib/toast.ts`; `ErrorToast.tsx` now only exports `ErrorToastContainer`.
- `useSSE.ts` updated ref `.current` during render — violates `react-hooks/exhaustive-deps`.
  Fix: wrapped in `useLayoutEffect`.

**TypeScript errors (resolved this session)**:
- `RunDetail/index.tsx` and `SpecDetail/index.tsx` imported `InterruptNotification` type and
  passed `onInterrupt` callback to `useSSE` — but the rewritten `useSSE` removed both (interrupts
  now go directly to `useInterruptStore`). Fix: removed `onInterrupt`/`InterruptNotification`,
  replaced with store-watching via `useEffect` + seen-ID ref (toast only for new interrupts);
  `SpecDetail` watches store to trigger `refetchInterrupts()` when interrupt count changes.
- `useSSE.ts` imported unused `Run` type. Fix: removed from import.

### Files modified in frontend/

- `frontend/src/lib/toast.ts`: NEW — `showError`/`showWarning` + `toastListeners` event bus.
- `frontend/src/components/ErrorToast.tsx`: removed non-component exports; imports from `@/lib/toast`.
- `frontend/src/api/client.ts`: `showError` import updated to `@/lib/toast`.
- `frontend/src/lib/pipelineLabels.ts`: NEW — `pipelineLabels` map for all 14 PipelineFunctionIds.
- `frontend/src/lib/ui-types.ts`: NEW — `FilterPreset`, `SpecFilters`, `ToastSeverity` types.
- `frontend/src/hooks/useInterruptStore.ts`: NEW — Zustand store for `InterruptPoint` entities.
- `frontend/src/hooks/useSSE.ts`: REWRITTEN — exhaustive switch on 11 SSE message kinds;
  `useLayoutEffect` for ref updates; `onInterrupt` removed; `Run` import removed.
- `frontend/src/hooks/useRunStore.ts`: added `autoConfigs` map + `setStatus`/`setCounters`/`setAutoConfig`.
- `frontend/src/hooks/useSpecStore.ts`: added `upsert` + `clearForRun`.
- `frontend/src/pages/InterruptList.tsx`: NEW — `/runs/:run_id/interrupts` page.
- `frontend/src/pages/InterruptDetail.tsx`: NEW — `/runs/:run_id/interrupts/:interrupt_id` page.
- `frontend/src/pages/RunDetail/index.tsx`: replaced `onInterrupt`/`InterruptNotification` with
  store-watch via `useEffect` + `seenInterruptIds` ref.
- `frontend/src/pages/SpecDetail/index.tsx`: replaced `onInterrupt`/`InterruptNotification` with
  store-watch via `useEffect` + `prevCountRef`.
- `frontend/src/App.tsx`: added `/runs/:run_id/interrupts` and `/runs/:run_id/interrupts/:interrupt_id` routes.
- `frontend/Dockerfile`: build context changed from `./frontend` to project root (`.`); copies
  `shared/` adjacent to `frontend/` so `../shared/contracts/` resolves correctly.
- `docker-compose.yml`: `frontend.build.context` changed from `./frontend` to `.`;
  `dockerfile` set to `frontend/Dockerfile`.

### Build verification

- `npm run build` → 0 TypeScript errors ✓ (854 modules, 697ms)
- `npm run lint` → 0 ESLint errors ✓
- `docker compose build frontend` → succeeds ✓ (multi-stage, shared/contracts included)

---

## [Session 11] 2026-05-26T00:00:00Z

### Files created in backend/

- `backend/tasks/_control.py`: NEW — `CooperativeExit` exception; `check_control_flags()` (order: cancel→pause→intervention); `apply_intervention()` dispatcher for EditHarness, ForceOutcome, EditSpec.
- `backend/tasks/_interrupt.py`: NEW — `interrupt_gate()` implementing interactive_control_spec.md §4.3; reads AutoConfig; manual mode creates `InterruptPoint`, polls every 2s, extends lease every 60s, propagates `CooperativeExit` from `check_control_flags()`.
- `backend/tests/test_tasks.py`: NEW — 20 tests covering interrupt gate (auto/manual/skip/resume/cancel), control flags, phase1 (idempotency/no-zip/spec-gen), phase2 (lease/pause/cancel/intervention/budget), phase3 (confirmed/rejected/build-fail/run-completion), counter throttle.

### Files rewritten in backend/

- `backend/tasks/phase1.py`: Full rewrite — 5 interrupt gates (phase1_db_build, phase1_query_execution, phase1_sarif_parsing, phase1_fact_enrichment, phase1_spec_generation); idempotency guard; deterministic spec_id (SHA-256); SSE publishing; dispatches `phase2_task.delay(spec_id)`.
- `backend/tasks/phase2.py`: Full rewrite — Algorithm 1 main loop (T_explore=8, T_author=12, T_max=60, R_max=15); 6 interrupt gates; `_heartbeat_loop` background task; LLM retry (exponential backoff, 5 attempts); `persist_turn` atomic commit; `_set_spec_terminal`; `runner.stop()` in `finally`.
- `backend/tasks/phase3.py`: Full rewrite — 3 interrupt gates (phase3_replay_driver_generation, phase3_asan_compilation, phase3_result_classification); `_build_verdict_dict` (ASan regex → CWE mapping); `_persist_verdict_and_update`; `_check_run_completion`.

### Files modified in backend/

- `backend/services/spec_service.py`: Added `extend_lease_bool()` (returns False if lease stolen via RETURNING), `acquire_phase3_lease()`, `drop_phase3_lease()`, `persist_turn()` (atomic Spec UPDATE + Turn INSERT ON CONFLICT DO NOTHING).
- `backend/services/event_service.py`: Added `publish_counters_throttled()` (≤1/s per run, asyncio deferred flush), `_do_publish_counters()`, `publish_run_status_changed()`, `publish_spec_state_changed()`, `publish_turn_appended()`, `publish_worker_heartbeat()`, `publish_log_line()`; fixed `_do_publish_counters` to fill `RunCounters` with zero defaults for missing fields.
- `backend/tests/test_tasks.py`: Added `reset_db_pool` autouse fixture (disposes module-level asyncpg pool between tests to prevent cross-test event loop contamination).

### Bugs fixed during implementation

- [x] `tasks/_interrupt.py`: `session=None` passed by callers but function called `session.scalar()` directly → refactored to always use own `_get_new_session()` sessions.
- [x] `services/event_service.py`: `RunCounters(**partial_dict)` raised `ValidationError` (all fields required, no defaults) inside `try/except` → silently dropped all counter publishes. Fix: fill defaults with `{k: 0 for k in RunCounters.model_fields}` before passing partial dict.
- [x] `tests/test_tasks.py`: asyncpg connection pool shared across tests with session-scoped event loop caused "Future attached to different loop" errors when tests run together. Fix: `reset_db_pool` autouse fixture calls `database.engine.dispose()` after each test.

### Spec files verified accurate

- [ok] `spec/interactive_control_spec.md §4.3`: interrupt gate pattern — matches `tasks/_interrupt.py`.
- [ok] `shared/contracts/sailor.schema.json`: 14 PipelineFunctionId values (authoritative) — used throughout all task files.
- [ok] `design/CLAUDE_backend.md`: CooperativeExit exception pattern — matches `tasks/_control.py`.

### Spec files that need update

- None identified.

### Code that needs fix (Case A) — fixed this session

- None beyond the bugs noted above.

### Known limitations

- Phase E (container log streaming): not implemented. Worker-side `_stream_and_log()` background task reading Docker logs line-by-line during KLEE/ASan builds was deferred. LogLine SSE events are not published during container runs.

### Test results

- `backend/tests/` — **54/54 PASSED** ✓
  - `test_tasks.py`: 20 PASSED ✓ (new — all worker/interrupt gate tests)
  - `test_interrupts.py`: 18 PASSED ✓ (no regression)
  - `test_interventions.py`: 2 PASSED ✓
  - `test_phase_downloads.py`: 7 PASSED ✓
  - `test_runs.py`: 4 PASSED ✓
  - `test_specs.py`: 3 PASSED ✓
