# Patch: `CLAUDE_frontend.md`

Apply these changes to remove all duplicated type definitions in
`CLAUDE_frontend.md` and route everything through `shared/contracts/`.

The motivation: every type currently in §"TypeScript Interfaces"
(roughly lines 321–446) drifts from the backend. The new rule is that
`CLAUDE_frontend.md` describes **frontend architecture** only — state
management choices, component layout, performance budgets — and never
defines wire-level types.

---

## Patch 1: Replace the entire "TypeScript Interfaces" section

**Find** (around line 321):

```markdown
## TypeScript Interfaces (mirrors API schema)

```typescript
// lib/types.ts

export type RunStatus =
  | "queued" | "running" | "paused" | "completed" | "failed" | "cancelled"
  | "needs_build_config";

export type Phase2Status =
  | "queued" | "exploring" | "authoring" | "refining"
  | "bug_triggered" | "inconclusive" | "likely_false_positive";

...

export interface SSEDiff {
  seq: number;
  topic: string;
  diffs: Array<{ id: string; patch: Partial<Spec | Run> }>;
}
```
```

**Replace with**:

```markdown
## TypeScript Types — DO NOT REDEFINE HERE

All types that cross the API boundary live in `shared/contracts/sailor.types.ts`,
generated from `shared/contracts/sailor.schema.json`. Frontend code MUST
import from there:

```ts
import type {
  Run, Spec, Turn, TurnDetail, Verdict,
  RunStatus, Phase2Status, Phase3Status,
  RunConfig, RunCounters,
  SSEMessage, SSEBatch, SSEMessageKind,
  InterventionRequest, EditHarnessRequest, ForceOutcomeRequest, EditSpecRequest,
  ApiError, PaginatedSpecs,
} from "@/shared/contracts/sailor.types";
```

There must be no `lib/types.ts` redefining these. If you find yourself
typing `export type RunStatus =` anywhere in the `frontend/` tree, stop
and import instead.

The contracts directory's `README.md` documents every contract decision
that was previously ambiguous (SSE envelope, RunCounters field names,
RunConfig naming, Verdict casing, intervention discriminators). Read it
before disagreeing with any field name.

### Frontend-only types

Some types are **purely UI state** and never cross the API. Those may
live in `frontend/src/lib/ui-types.ts`:

```ts
// frontend/src/lib/ui-types.ts
export type FilterPreset = { name: string; filters: SpecFilters };
export type SpecFilters = {
  phase?: 1 | 2 | 3;
  status?: string;
  cwe?: string;
  fileGlob?: string;
  verdict?: string;
  search?: string;
};
export type ToastSeverity = "info" | "success" | "warning" | "error";
```

These never appear in network payloads.
```

---

## Patch 2: Fix the SSE Gap section

**Find** (Gap 4, around line 62):

```markdown
### Gap 4: SSE Client Implementation (sketched, not defined)

```
Decision: custom useSSE() hook with reconnect + sequence tracking

Behavior:
  - Subscribes with ?topics=runs.{id}.specs on mount
  - On disconnect: exponential backoff (1s, 2s, 4s, max 30s)
  - On reconnect: sends ?since={last_seq} to catch up
  - Batched diffs: server sends {seq, diffs: [{spec_id, patch}]}
  - Client applies JSON Merge Patch (RFC 7386) to useSpecStore
```
```

**Replace with**:

```markdown
### Gap 4: SSE Client Implementation

Wire format is defined by `shared/contracts/sailor.schema.json`
(`SSEMessage`, `SSEBatch`). Frontend MUST NOT diverge.

```
Decision: custom useSSE() hook on top of native EventSource

Connection:
  - URL: `/api/events?topics=<comma-separated>&token=<jwt>`
    (browser EventSource cannot send Authorization headers — token
    must be a query parameter. Backend validates the same as a header.)
  - Topics format: see `SSETopicPattern` in the schema.

Reconnect:
  - Native EventSource handles reconnect; on each reconnect it sends
    the `Last-Event-ID` HTTP header automatically. The server uses
    this to replay from the 60-second buffer.
  - If the server sends `{kind: "resync_required"}`, the client drops
    its local store for that topic and refetches via REST.

Payload handling:
  - Each `SSEMessage` carries a full snapshot in `payload` — NOT a
    JSON Merge Patch. Frontend replaces by `spec_id`/`run_id`, not
    merges. Anything still using RFC 7386 is wrong; delete it.
  - Batches (`SSEBatch`) wrap multiple messages within a 250ms window.
    Process them in order; the batch's `sequence` is the last message's
    sequence (not a separate counter).

Dispatch:
  - Use a `switch (msg.kind)` exhaustively. TypeScript's discriminated
    union will warn if a case is missing.
```
```

---

## Patch 3: Fix the API client section

**Find** (Step A3, around line 571):

```markdown
  Step A3. Implement api/client.ts.
           → axios instance with baseURL from VITE_API_URL env var
           → Auth token injection (Bearer from localStorage)
           → 401 → redirect to login
           → Error normalization: {code, message, detail}
```

**Replace with**:

```markdown
  Step A3. Implement api/client.ts.
           → axios instance with baseURL from VITE_API_URL env var
           → Auth token injection: Authorization: Bearer <jwt>
             (from localStorage), on every request EXCEPT EventSource —
             see Gap 4 for SSE auth.
           → On every POST/PATCH/DELETE: inject
             `Idempotency-Key: <uuid-v4>` (generate one per logical
             intent; on user retry of the same intent, reuse the same
             key so the backend short-circuits).
           → 401 → redirect to /login
           → Non-2xx responses are typed as `ApiError`
             (from `shared/contracts/sailor.types`). Do not redefine.
```

---

## Patch 4: Remove the SSE event-shape mention from Step C4 / C5

**Find** (around lines 657–662 in "Step C5. Interrupt system"):

```markdown
           → Interrupt notification: SSE event → toast → navigate
               ("interrupt_created" event on runs.{run_id} topic)
```

**Replace with**:

```markdown
           → Interrupt notification: SSE event → toast → navigate.
             The interrupt event kind is NOT yet defined in
             shared/contracts/sailor.schema.json. Until the interrupt
             contract is added there, this UI is deferred — see the
             contracts README "What is NOT in this schema (yet)".
             Do not invent an `interrupt_created` event name; that
             string has no backend support.
```

---

## Patch 5: Fix the "Phase 2 budgets" field names in §1 of the spec reference

This is a smaller fix in the section that lists run-creation form inputs:

**Find** (around line 82 of `frontend_spec.md`, referenced from CLAUDE_frontend.md):

```
Phase 2 budgets        T_explore, T_author, T_max, T_klee, R_max
                       (defaults: 8 / 12 / 60 / 300s / 15)
```

**Replace with**:

```
Phase 2 budgets        phase2_t_explore, phase2_t_author, phase2_t_max,
                       phase2_t_klee_seconds, phase2_r_max
                       (defaults: 8 / 12 / 60 / 300s / 15)
                       UI labels may abbreviate (e.g. "T_max"); wire format
                       uses the snake_case names. See RunConfig in
                       shared/contracts/sailor.schema.json.
```

---

## Patch 6: Add the "Contracts are authoritative" preamble

**Insert** at the very top of `CLAUDE_frontend.md`, immediately after the
existing first block ("Claude Code reads this file..."):

```markdown
> **Type definitions are NOT in this file.**
> Every shared type lives in `shared/contracts/sailor.types.ts`,
> generated from `shared/contracts/sailor.schema.json`. Import; do not
> redefine. If you see a discrepancy between this file and the schema,
> the schema wins — open an issue and fix this file.
```
