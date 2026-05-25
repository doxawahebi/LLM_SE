# Patch: `CLAUDE_backend.md`

Apply these changes to remove all duplicated type definitions and route
everything through `shared/contracts/`.

The motivation: `CLAUDE_backend.md` currently describes Pydantic schemas
implicitly across multiple sections (Gap 2, schemas/ folder layout, intervention
discriminator language, RunCounters fields). These will drift from the frontend.
The new rule is that backend Pydantic models are **generated** from the schema,
not hand-written, and `CLAUDE_backend.md` describes backend architecture only.

---

## Patch 1: Add the "Contracts are authoritative" preamble

**Insert** at the very top of `CLAUDE_backend.md`, immediately after the
existing first block:

```markdown
> **Pydantic models for shared types are NOT defined in this file or in
> `backend/schemas/`.**
> Every model that crosses the API boundary is generated into
> `shared/contracts/sailor_models.py` from
> `shared/contracts/sailor.schema.json`. Import; do not redefine.
> If you see a discrepancy between this file and the schema, the schema
> wins — open an issue and fix this file.
```

---

## Patch 2: Replace the `schemas/` directory layout

**Find** (around line 243 in "Project Structure"):

```
├── schemas/                     # Pydantic request/response schemas
│   ├── __init__.py
│   ├── run.py
│   ├── spec.py
│   ├── turn.py
│   ├── verdict.py
│   ├── intervention.py
│   ├── event.py
│   └── settings.py
```

**Replace with**:

```
# Shared contracts (generated, used by all API routes):
#   shared/contracts/sailor_models.py  ← imported as
#                                       `from shared.contracts.sailor_models import ...`
#
# backend/schemas/  contains ONLY backend-internal models that never
# leave the backend (DB-internal types, intermediate compute results,
# audit-only enums). If a type appears in any HTTP response body or
# request body, it MUST come from shared/contracts/sailor_models, not
# from backend/schemas/.

├── schemas/                     # Backend-internal Pydantic models only
│   ├── __init__.py
│   ├── internal.py              # types never sent over HTTP
│   └── celery_tasks.py          # task argument/result shapes
```

---

## Patch 3: Add a "Shared contracts" section to the Project Structure

**Insert** in the Project Structure block (right after the `backend/` tree
description), at the top level of the project:

```
shared/                          # IMPORTED, not in backend/
├── contracts/
│   ├── sailor.schema.json       # source of truth (JSON Schema)
│   ├── sailor_models.py         # auto-generated Pydantic models
│   ├── sailor.types.ts          # auto-generated TypeScript types
│   └── README.md                # conflict resolution log

scripts/
└── regen_contracts.sh           # regenerates the two above after schema edits
```

The backend's `pyproject.toml` must include `shared` as an importable
package (or set `PYTHONPATH=$REPO_ROOT` for worker startup):

```toml
[tool.hatch.build.targets.wheel]
packages = ["backend", "shared"]
```

---

## Patch 4: Rewrite Gap 2 (Database Schema Decisions)

**Find** (around line 31, "Gap 2"):

```markdown
### Gap 2: Database Schema Decisions

```
ORM: SQLAlchemy 2.x (async) with Alembic migrations

Tables:
  runs          → Run entity (§2.1)
  specs         → Spec entity + lease fields (§9.2)
  ...
```

**Replace** (keep the ORM choice and the table list, but reword the
relationship to the contracts):

```markdown
### Gap 2: Database Schema Decisions

ORM: SQLAlchemy 2.x (async) with Alembic migrations.

Tables map 1:1 to entities in `shared/contracts/sailor.schema.json`, with
storage-only fields added (lease columns, audit metadata, soft-delete
flags). The Pydantic models in `sailor_models.py` are the request/response
schema; the SQLAlchemy models are the storage schema. They are not the
same file — but the field names and types of the wire-facing columns
MUST match. Specifically:

- `runs.status` column → `RunStatus` enum (use SQLAlchemy `Enum` bound to
  the same string values).
- `specs.phase2_status` column → `Phase2Status` enum.
- `specs.phase3_status` column → `Phase3Status` enum.
- `verdicts.verdict` column → `VerdictValue` enum (lowercase).
- `runs.counters` JSONB column → must serialize as `RunCounters` shape.
- `runs.config` JSONB column → must serialize as `RunConfig` shape.

Storage-only columns (not in the shared contracts):

```
specs.worker_id            string | null
specs.locked_until         timestamp | null
specs.lease_acquired_at    timestamp | null
runs.deleted_at            timestamp | null   (soft delete marker)
```

These never appear in API responses — strip them at the FastAPI response
boundary via Pydantic `response_model=Run` (which uses the generated
model that lacks these fields).

Tables (full list — same as before):

  runs, specs, turns, verdicts, audit_events, users, settings,
  log_lines, idempotency_keys, export_jobs, interventions

(The interrupt-related tables — `interrupt_points`, `auto_config` — are
deferred until the interrupt contract is defined in the schema. See the
contracts README "What is NOT in this schema (yet)".)

Indexes: unchanged from the existing list.

JSONB columns: unchanged. Validate against the corresponding Pydantic
model on read AND write.
```

---

## Patch 5: Drop the schemas/ creation step from Phase A

**Find** (Step A3, around line 429):

```markdown
  Step A3. Pydantic schemas (schemas/).
           → Request and response schemas for all entities.
           → Discriminated union for Intervention (§6).
           → EventMessage schema (§5.3).
```

**Replace with**:

```markdown
  Step A3. Verify shared contracts.
           → Confirm `shared/contracts/sailor_models.py` and
             `shared/contracts/sailor.types.ts` are present and current
             (run `./scripts/regen_contracts.sh`).
           → If any wire type is missing, add it to
             `shared/contracts/sailor.schema.json` and regenerate.
             NEVER write request/response schemas in `backend/schemas/`
             for types that cross the API.
           → For backend-internal types (Celery task arguments, audit
             diffs), use `backend/schemas/internal.py`.
```

---

## Patch 6: Fix the LLM retry conflict

**Find** (Gap 3 around line 95, "§15.3 Task queue retry semantics"):

```markdown
§15.3 Task queue retry semantics
  Decision:
    Worker crash → Celery re-queues (task-level retry, max 3)
    LLM API error → orchestrator retries within the task (max 5,
                    exponential backoff). NOT a Celery retry.
  Gemini 429 → sleep 60s, retry once, then raise LLMRateLimitError
  (per CLAUDE_phase2.md LLM Provider Strategy).
```

The "Gemini 429 → sleep 60s, retry once" rule **contradicts** the
"max 5, exponential backoff" rule directly above it. Resolve:

**Replace with**:

```markdown
§15.3 Task queue retry semantics
  Decision:
    Worker crash → Celery re-queues (task-level retry, max 3).
    LLM API error → orchestrator retries within the task with
                    exponential backoff (base 2s, max 5 attempts,
                    cap 60s). NOT a Celery retry.
                    This applies to ALL providers including Gemini.
    Gemini 429   → counts as one LLM API error attempt; the same
                    exponential backoff loop applies (no special
                    "sleep 60s, retry once" path). The previous
                    CLAUDE_phase2.md guidance is superseded.
    After exhausting LLM retries → mark spec phase2_status="errored"
                    with phase2_error containing the upstream code.
```

---

## Patch 7: Fix the intervention type naming in §6 references

**Find** (Step B3 around line 472):

```markdown
  Step B3. Intervention (api/specs.py §6).
           → POST /api/runs/:id/specs/:spec_id/intervene
           → Discriminated union dispatch: EditHarness|ForceOutcome|EditSpec
           → EditHarness: optimistic concurrency via base_version (→ 409 on conflict)
           → intervention_pending flag + payload stored in interventions table
```

**Replace with**:

```markdown
  Step B3. Intervention (api/specs.py — see backend_spec.md §6).
           → POST /api/runs/:id/specs/:spec_id/intervene
           → Request body: shared.contracts.sailor_models.InterventionRequest
             (Pydantic discriminated union on the `type` field with values
             "edit_harness" | "force_outcome" | "edit_spec")
           → Dispatch by `request.type` — Pydantic validates the variant.
             Frontend MUST send `type`, never `mode`. UI's "Mode A/B/C"
             labels are display strings only.
           → EditHarnessRequest: optimistic concurrency via base_version
             (→ 409 on conflict).
           → EditHarnessRequest.artifact ∈ {"driver", "slice", "assertions"}
             (no .c extension on the wire).
           → intervention_pending becomes a LIST per spec (not a bool —
             see Constraint 5). Append the new InterventionRequest to it.
```

---

## Patch 8: Add the SSE wire-format reference at Phase C entry

**Find** (the "Phase C — Real-Time Push (SSE)" header, around line 566):

```markdown
Phase C — Real-Time Push (SSE)
```

**Replace with**:

```markdown
Phase C — Real-Time Push (SSE)

The wire format is the authoritative `SSEMessage` / `SSEBatch` /
`SSEMessageKind` types in `shared/contracts/sailor_models.py`. Backend
publishers MUST construct messages using these models — never raw dicts —
so Pydantic validation rejects any mismatched payload at publish time.

Eight `kind` values (see contracts README §"SSE message kinds" for the
full mapping from backend_spec.md §8.2 event names):
  run_status_changed, run_counters_updated, spec_state_changed,
  spec_intervention_applied, turn_appended, worker_heartbeat,
  log_line, resync_required

The old event names (`RunStatusChanged`, `SpecPhase2Started`, etc.) from
backend_spec.md §8.2 are INTERNAL labels for the Event Bus. The wire
format to clients uses the eight `kind` values above. The mapping is
N:1 (multiple internal events fold into one external `kind`); see the
contracts README for the table.
```

---

## Patch 9: Fix the artifact streaming/redirect contradiction

**Find** (Step B4 around line 478):

```markdown
  Step B4. Artifacts (api/artifacts.py).
           → GET /api/runs/:id/specs/:spec_id/artifacts → tree
           → GET /api/runs/:id/specs/:spec_id/artifacts/*path
             → redirect to presigned URL (or stream via proxy)
             → Range header support for large files
           → POST /api/runs/:id/specs/:spec_id/artifacts.tar.gz
             → enqueue export_task, return 202 + job_id
           → GET /api/jobs/:job_id → poll export status
```

The "(or stream via proxy)" wording conflicts with Constraint 10 below
("Never stream artifact bytes through the FastAPI process"). Resolve to
the constraint:

**Replace with**:

```markdown
  Step B4. Artifacts (api/artifacts.py).
           → GET /api/runs/:id/specs/:spec_id/artifacts → tree of refs
             (path, size, mime_type, created_at — NO presigned URLs in
             the tree; client requests presigned URLs per file on demand).
           → GET /api/runs/:id/specs/:spec_id/artifacts/*path
             → HTTP 302 to a presigned URL (300s TTL).
             → Range-header support is the responsibility of S3/MinIO via
               the presigned URL — backend does not proxy bytes.
             → Backend NEVER reads or streams the file contents.
           → POST /api/runs/:id/specs/:spec_id/artifacts.tar.gz
             → enqueue export_task, return 202 + job_id.
           → GET /api/jobs/:job_id → poll export status (returns artifact
             ref when complete; subsequent download is also 302).
```

This aligns with both Constraint 10 and CLAUDE_frontend.md Gap 5.1 (which
says "API returns presigned URLs valid for 5 minutes" — 5 min = 300s, same).

---

## Patch 10: Drop the inline TypeScript-ish ApiError mention

The backend has implied an error shape ad-hoc across Steps. Add an
explicit pointer:

**Insert** as a new bullet at the end of the "CONSTRAINTS (non-negotiable)"
list (around line 730):

```markdown
11. All error responses use the `ApiError` shape from
    `shared/contracts/sailor_models.py`:
      {code: str, message: str, detail?: any, trace_id?: str|null}
    Use FastAPI exception handlers to enforce this globally:
      @app.exception_handler(HTTPException)
      async def http_error_handler(req, exc):
          return JSONResponse(
              status_code=exc.status_code,
              content=ApiError(
                  code=exc.detail.get("code", "unknown"),
                  message=exc.detail.get("message", str(exc.detail)),
                  trace_id=req.state.trace_id,
              ).model_dump()
          )
    The `code` field is the stable machine-readable identifier; UI
    branches on `code`, not on HTTP status alone.
```
