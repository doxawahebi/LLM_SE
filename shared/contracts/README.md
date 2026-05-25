# `shared/contracts/` — Sailor API Contracts (single source of truth)

Every type that crosses the frontend/backend boundary lives here.
Frontend imports `sailor.types.ts`; backend imports `sailor_models.py`.
Both files are **generated** from `sailor.schema.json`.

If a type definition appears anywhere else (e.g. `frontend/src/lib/types.ts`,
`backend/schemas/`, or inside `CLAUDE_frontend.md` / `CLAUDE_backend.md`),
that is a bug — delete it and import from here instead.

---

## Files

| File                  | What it is                                            | Edit?            |
| --------------------- | ----------------------------------------------------- | ---------------- |
| `sailor.schema.json`  | JSON Schema (Draft 2020-12) — source of truth         | **Yes, by hand** |
| `sailor.types.ts`     | TypeScript types, generated from the schema           | No (generated)   |
| `sailor_models.py`    | Pydantic v2 models, generated from the schema         | No (generated)   |

## Regenerating after a schema edit

```bash
./scripts/regen_contracts.sh
```

CI runs this and fails if the committed generated files don't match the
schema. Don't hand-edit the `.ts` or `.py` files; the next regen will
overwrite them and any local change is lost.

## Frontend usage

```ts
import type { Run, Spec, SSEMessage, EditHarnessRequest } from '@/shared/contracts/sailor.types';

function handleMessage(m: SSEMessage) {
  switch (m.kind) {
    case 'run_status_changed':
      // m.payload is RunStatusChangedPayload (narrowed by `kind`)
      console.log(m.payload.run_id, m.payload.status);
      break;
    case 'spec_state_changed':
      // m.payload is SpecStateChangedPayload (carries a full Spec)
      console.log(m.payload.spec.spec_id);
      break;
    // ... TS will warn if any case is missing
  }
}
```

In `tsconfig.json`, add the path alias:

```json
{
  "compilerOptions": {
    "paths": {
      "@/shared/contracts/*": ["../shared/contracts/*"]
    }
  },
  "include": ["src/**/*", "../shared/contracts/sailor.types.ts"]
}
```

## Backend usage

```python
from shared.contracts.sailor_models import (
    Run, Spec, SSEMessageRunStatusChanged, RunStatus, EditHarnessRequest,
)
from fastapi import APIRouter

router = APIRouter()

@router.get("/api/runs/{run_id}", response_model=Run)
async def get_run(run_id: str) -> Run:
    ...
```

For Celery and worker code, the same import works:

```python
from shared.contracts.sailor_models import Spec, Turn, Phase2Status
```

In `backend/pyproject.toml`, make sure `shared` is on the import path:

```toml
[tool.hatch.build.targets.wheel]
packages = ["backend", "shared"]
```

Or set `PYTHONPATH=$REPO_ROOT` in worker startup.

---

## Wire-format contract: the things that were ambiguous before

This section is the **conflict log**: every prior disagreement between
`backend_spec.md`, `frontend_spec.md`, `CLAUDE_backend.md`,
`CLAUDE_frontend.md` was resolved here. If a spec or CLAUDE file
contradicts what follows, **this schema wins** — fix the docs.

### 1. SSE message envelope

```
field        type            notes
---------    -----------     -----------------------------------------------
topic        string          e.g. "runs.r_001.specs.s_042"
sequence     integer ≥ 0     monotonic per-topic. NOT named `seq`.
timestamp    ISO-8601 UTC    server send time
kind         enum (8 values) discriminator; selects payload shape
payload      object          full snapshot of the changed entity
```

- **`sequence` not `seq`.** Frontend `types.ts` previously used `seq`.
- **`payload` is a snapshot, not a patch.** Frontend `Gap 4` previously
  said "JSON Merge Patch (RFC 7386)". The backend has no patch generator;
  it sends the full updated entity. Frontend MUST replace, not merge.

### 2. SSE message kinds

The eight `kind` values, and which old backend events they unify:

| `kind` value                  | Replaces (old backend names)                                                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `run_status_changed`          | `RunStatusChanged`, `RunCompleted`, `RunFailed`, `RunCancelled`                                                          |
| `run_counters_updated`        | `RunCountersUpdated` (throttled ≤ 1/sec/run server-side)                                                                  |
| `spec_state_changed`          | `SpecEmitted`, `SpecFiltered`, `SpecPhase2Started`, `SpecPhase2Outcome`, `SpecPhase3Started`, `SpecPhase3Verdict`, `SpecErrored`, `SpecRequeued` |
| `spec_intervention_applied`   | `SpecInterventionAcknowledged`, `SpecInterventionApplied`                                                                |
| `turn_appended`               | `TurnAppended`                                                                                                            |
| `worker_heartbeat`            | `WorkerHeartbeat`, `WorkerTaskStarted`, `WorkerTaskFinished`, `WorkerDied`                                                |
| `log_line`                    | `LogLine`                                                                                                                 |
| `resync_required`             | (new) gap recovery signal — sent when the 60s replay buffer can't catch the client up                                     |

The eight old `state_change | counter_diff | new_turn | log_line | worker_heartbeat | resync_required` kinds that frontend/backend disagreed on are **all** subsumed by this list.

### 3. SSE reconnect and authentication

Three different proposals existed across the docs. The chosen mechanism:

- **Reconnect token**: `Last-Event-ID` HTTP header (standard SSE). When the
  client reconnects, the browser's `EventSource` automatically sends the
  last received `sequence` as `Last-Event-ID`. The server treats this as a
  request to replay from that sequence + 1.
- **Auth**: `?token=<jwt>` query parameter. `EventSource` does not support
  custom headers in browsers, so Authorization-Bearer over header is not
  available. The token query parameter is validated identically to the
  Authorization header for non-SSE endpoints.
- **Topics**: `?topics=runs.all,runs.<id>.specs` (comma-separated). The
  server validates that the user's role permits each topic.

### 4. RunCounters field names

`RunCounters` in `frontend/lib/types.ts` had **completely different field
names** from `backend_spec.md §2.1`. The backend names win.

Removed (frontend-only names that don't exist anywhere else):

- `total_specs` → use `specs_total`
- `phase1_done`, `phase2_done`, `phase3_done` → derive client-side from
  the more specific counters; the backend never exposed aggregate "done"
- `bug_triggered` → `specs_phase2_bug_triggered`
- `confirmed` → `specs_phase3_confirmed`
- `inconclusive` → `specs_phase2_inconclusive`
- `likely_fp` → `specs_phase2_likely_fp`
- `error` → `specs_phase2_errored` (Phase 2) or `specs_phase3_errored` (Phase 3)
- `token_cost_usd` → `total_llm_tokens` (pricing must be computed client-side from provider × tokens, since price changes don't belong in counters)

Added (from backend spec that frontend was missing):

- `specs_phase3_errored` (frontend had no Phase 3 error counter)

### 5. RunConfig field names

Frontend used uppercase Python-like names (`T_explore`, `T_max`); backend
spec used nested dotted keys (`phase2.t_explore`).

**Resolution: flat snake_case with phase prefix.**

| Old (frontend) | Old (backend spec) | Canonical          |
| -------------- | ------------------ | ------------------ |
| `T_explore`    | `phase2.t_explore` | `phase2_t_explore` |
| `T_author`     | `phase2.t_author`  | `phase2_t_author`  |
| `T_max`        | `phase2.t_max`     | `phase2_t_max`     |
| `T_klee`       | `phase2.t_klee_seconds` | `phase2_t_klee_seconds` |
| `R_max`        | `phase2.r_max`     | `phase2_r_max`     |
| `run_phase3`   | `phase3.enabled`   | `phase3_enabled`   |
| `query_ids`    | `phase1.query_suite` | `phase1_query_suite` |

`DockerRunner`'s `klee_timeout_per_run` stays internal to the runner; the
worker translates `RunConfig.phase2_t_klee_seconds` → `klee_timeout_per_run`
at the call site. The runner config does NOT cross the API boundary.

### 6. Verdict casing and shape

Frontend `Verdict` enum was `"CONFIRMED" | "inconclusive" | "likely_false_positive" | "rejected" | null`. This mixed Phase 2 outcomes with Phase 3 verdicts and used uppercase `CONFIRMED`.

Resolution:

- `VerdictValue`: `"confirmed" | "rejected"` (lowercase, Phase 3 only)
- `Phase2Outcome`: `"bug_triggered" | "inconclusive" | "likely_false_positive" | "errored"` (Phase 2 terminal states)
- These are two distinct fields on `Spec` (`phase2_outcome` and `phase3_verdict`) and on `Verdict` (the dedicated Phase 3 record).
- UI may upper-case for display, but the wire format is **always lowercase**.

### 7. Spec status enum completeness

| Status enum    | Old frontend missing                | Old backend missing                |
| -------------- | ----------------------------------- | ---------------------------------- |
| `Phase2Status` | `errored`                           | —                                  |
| `Phase3Status` | `errored`, `not_eligible`           | `skipped` (frontend invented this) |
| `RunStatus`    | `archived` (post soft-delete state) | —                                  |

All present now.

### 8. Turn list vs Turn detail

`backend_spec.md §4.3` defines two endpoints:

- `GET /turns` returns **summaries** (no `payload` inline; `payload_ref`
  is the artifact-store reference).
- `GET /turns/:turn_id` returns the **detail** with `payload` inlined.

Frontend `Turn` interface previously assumed `payload` was always inline.
That broke timeline rendering on the list endpoint.

Resolution:

- `Turn` — list/summary shape (no inline payload). Has `payload_ref`.
- `TurnDetail` — `{ turn: Turn, payload: TurnPayload }`. Returned by the
  detail endpoint only.

### 9. Turn `kind` enum

Old frontend had `klee_timeout` as a turn kind. Backend spec did not.

Resolution: KLEE timeout is not a turn kind — it's an outcome of a
`klee_run` turn. The new `KleeRunPayload.timed_out: boolean` field
captures it. `terminal` was added (backend spec lists it but it was
missing from frontend types).

### 10. Intervention request `type` discriminator

Frontend used "Mode A / Mode B / Mode C" naming with no wire-format
mapping. Backend `§6` defined the discriminator as `type: "edit_harness" | "force_outcome" | "edit_spec"`.

The TS/Python types now expose `EditHarnessRequest`, `ForceOutcomeRequest`,
`EditSpecRequest` directly. The discriminator on the wire is `type` (not
`mode`). UI labels (Mode A/B/C) are display strings only — they MUST NOT
appear in any HTTP body.

### 11. EditHarness `artifact` field

Old frontend assumed strings like `"driver.c" / "slice.c" / "assertions.c"`
(from the three-tab UI). Backend `§6.1` defines `"driver" | "slice" | "assertions"` (no `.c`).

Resolution: wire format is **without** the `.c` extension. UI may display
with the extension; the request body strips it.

### 12. `ApiError` shape

Frontend client.ts had ad-hoc `{code, message, detail}`. Backend spec
mentions error responses but never pinned the shape.

Canonical:

```ts
{ code: string, message: string, detail?: unknown, trace_id?: string | null }
```

- `code`: stable, snake_case, machine-readable. e.g. `spec_not_found`, `invalid_transition`, `lease_expired`.
- `message`: human-readable summary.
- `detail`: free-form; may carry validation errors or nested context.
- `trace_id`: matches the request's `trace_id` header for log correlation.

### 13. What is NOT in this schema (yet)

The following exist in the docs but are deferred:

- **Interrupt system** (`interrupt_points` table, `auto_config`,
  `interrupt_created` events, the 15 function-specific interrupt UIs).
  The two `CLAUDE_*.md` files reference an `interactive_control_spec.md`
  that was never uploaded. Until that spec is written, the interrupt
  system is **out of scope** for this contracts file. Frontend should
  not depend on `interrupt_created` SSE events; they don't exist yet.
- **Cross-run dedup index.** Backend `§15.5` defers this; comparison
  endpoint exists but no `dedup_key`-keyed cross-run lookup.
- **Live KLEE progress streaming.** Frontend `§14.6` opens this; no SSE
  event for KLEE intra-turn progress is defined here.

If these are needed, write them into `sailor.schema.json` first, then
the docs.

---

## How to add a new type

1. Open `sailor.schema.json`, add the new `$def`.
2. Run `./scripts/regen_contracts.sh`.
3. If validation or TS compilation fails, fix the schema.
4. Commit `sailor.schema.json` AND the two generated files together.

## How to change an existing type (breaking change)

1. Bump the API version (the schema's `$id` and the API route prefix).
2. Add the new type alongside the old one in the schema.
3. Migrate clients before removing the old type.

Backwards-compatibility rules from `backend_spec.md §14` still apply.

---

## Anti-patterns to watch for

- Defining types in `lib/types.ts` "just for the frontend". They will
  drift. Import from `sailor.types.ts` instead.
- Adding fields to Pydantic models that aren't in the schema. The next
  regen wipes them. Add to the schema first.
- Sending different field names on the wire than the schema defines.
  If you need a different naming convention internally (e.g. Postgres
  column names), use Pydantic field aliases — keep the wire format
  matching the schema.
- Reading SSE messages without a `switch (m.kind)` (or Pydantic
  discriminated union). The type system protects you only if you use it.
