# `spec/sse_contract.md`
# Sailor SSE Wire Contract

> **Status**: authoritative for everything wire-level about Sailor's SSE
> stream. Both spec files (`frontend_spec.md`, `backend_spec.md`), both
> CLAUDE files (`CLAUDE_frontend.md`, `CLAUDE_backend.md`), and the
> `interactive_control_spec.md` reference this document instead of
> redefining SSE format details. If those documents contradict this one,
> this one wins — fix the others.

> **Source of types**: every type referenced here (`SSEMessage`,
> `SSEBatch`, `SSEMessageKind`, all `*Payload` types, etc.) lives in
> `shared/contracts/sailor.schema.json`. The TypeScript and Pydantic
> bindings are generated from that schema. Do **not** redefine them.

---

## Table of contents

1. [Why this exists](#1-why-this-exists)
2. [Endpoint and transport](#2-endpoint-and-transport)
3. [Authentication](#3-authentication)
4. [Topics and subscription](#4-topics-and-subscription)
5. [Message envelope](#5-message-envelope)
6. [Batching](#6-batching)
7. [Sequences, reconnect, and replay](#7-sequences-reconnect-and-replay)
8. [The eleven message kinds](#8-the-eleven-message-kinds)
9. [Error responses (non-streaming)](#9-error-responses-non-streaming)
10. [Implementation guidance — server](#10-implementation-guidance--server)
11. [Implementation guidance — client](#11-implementation-guidance--client)
12. [Conformance tests](#12-conformance-tests)
13. [Changelog and versioning](#13-changelog-and-versioning)

---

## 1. Why this exists

Earlier drafts of `frontend_spec.md` and `backend_spec.md` disagreed on:

- whether the sequence field is `seq` or `sequence`
- whether the payload is a JSON Merge Patch or a snapshot
- how the client reconnects (`Last-Event-ID`, `?since=`, or "expo backoff")
- how the client authenticates (Bearer header, query param, or both)
- how many "kinds" there are (frontend: 6, backend: ~14 internal event names)
- which fields each kind's payload carries

These disagreements produced runtime bugs that the type system could
not catch, because the type definitions themselves were duplicated and
divergent. The contract is now consolidated here, with bindings
auto-generated from one schema. **Read this document before writing
SSE code anywhere.**

---

## 2. Endpoint and transport

### 2.1 Endpoint

```
GET /api/events
    ?topics=<comma-separated SSETopicPattern>
    &token=<jwt>

Accept: text/event-stream
```

- Single endpoint for every topic. The query string controls what the
  connection receives. Different routes in the UI subscribe to different
  topic sets but always hit `/api/events`.
- `Accept: text/event-stream` is required. Any other Accept gets
  `406 Not Acceptable` from the server with an `ApiError` body.
- The server responds with:
  ```
  HTTP/1.1 200 OK
  Content-Type: text/event-stream; charset=utf-8
  Cache-Control: no-cache, no-transform
  Connection: keep-alive
  X-Accel-Buffering: no              ← important for nginx; disables proxy buffering
  ```

### 2.2 Wire format

Standard W3C Server-Sent Events. Each event on the wire is:

```
id: <sequence>
event: <message_kind | "batch">
data: <single-line JSON>

```

(blank line terminator).

- `id`: ASCII decimal representation of `SSEMessage.sequence` (or the
  batch's `SSEBatch.sequence`). The browser stores this and sends it
  back as `Last-Event-ID` on reconnect.
- `event`: the `SSEMessage.kind` value, OR the literal string `"batch"`
  when sending a `SSEBatch`. Clients that consume via `EventSource` get
  `event.type` populated from this — they MAY route on it, but the
  authoritative discriminator is the JSON `kind` field, NOT the SSE
  event name. **Always parse the JSON and switch on `kind`.**
- `data`: exactly one line. JSON must be serialized without embedded
  newlines (`json.dumps(..., separators=(",", ":"))` in Python; `JSON.stringify`
  in JS). Multi-line `data:` is legal in W3C SSE but trips up several
  intermediaries; do not produce it.

### 2.3 Keep-alive

The server emits an SSE comment line every **15 seconds** when no real
messages are due:

```
: keep-alive

```

This prevents intermediaries (nginx, ELB, Cloudflare, browser-side
network stacks) from idling the connection out. Comments are ignored by
`EventSource`; they exist purely for transport survival.

### 2.4 Connection lifetime

- **No server-side timeout.** The connection is intended to stay open
  for the duration of the user's session.
- **Client closes** by calling `EventSource.close()`; the server detects
  via `Request.is_disconnected()` and unsubscribes from the bus.
- **Network drops** are handled by the browser auto-reconnect with
  `Last-Event-ID` (§7).

---

## 3. Authentication

### 3.1 Mechanism

**`?token=<jwt>` query parameter.** This is the only mechanism for SSE.

Rationale: browsers do not allow custom headers on `EventSource`
connections. `Authorization: Bearer …` cannot be set. Cookie-based auth
is the alternative but introduces CSRF surface for a streaming endpoint
that the rest of the API does not need to deal with.

The server validates `token` identically to the Authorization header on
other endpoints: same JWT signature check, same expiry check, same
role-based permissions on subsequent topic-access checks.

### 3.2 Failure modes

| Condition                | Server response                                                  |
| ------------------------ | ---------------------------------------------------------------- |
| `token` missing          | `401 Unauthorized`, `ApiError code="missing_token"`              |
| `token` malformed        | `401 Unauthorized`, `ApiError code="invalid_token"`              |
| `token` expired          | `401 Unauthorized`, `ApiError code="token_expired"`              |
| user disabled            | `403 Forbidden`, `ApiError code="account_disabled"`              |
| topic forbidden for role | `403 Forbidden`, `ApiError code="topic_forbidden"` (detail: topic)|

All failure responses are **standard JSON `ApiError`**, not SSE. The
client should detect non-200 on the EventSource creation and surface
the `ApiError` to the UI.

### 3.3 Token refresh

If a token expires mid-stream:

- The connection is **NOT killed** by the server upon mid-stream
  expiry. The server checks the token once on connection setup and on
  each new topic subscription change; routine messages do not re-check.
- The client should refresh the token on its normal cadence (e.g.
  before expiry for REST calls). When the client refreshes, it should
  close and reopen the SSE connection with the new token. The browser's
  automatic `Last-Event-ID` reconnect mechanism does the rest.

This trades a small auth-freshness window for connection stability.
For Sailor's use case (admin-grade users watching their own runs),
this is the right trade.

---

## 4. Topics and subscription

### 4.1 Topic grammar

Defined by `SSETopicPattern` in the schema. Production:

```
topic       ::=  "runs." (run_scope | "all")
run_scope   ::=  run_id ( "." sub_scope )?
sub_scope   ::=  "specs"   ( "." spec_id ( ".logs" )? )?
              |  "workers"
              |  "logs"

run_id      ::=  [A-Za-z0-9_-]+
spec_id     ::=  [A-Za-z0-9_-]+
```

Valid examples:

```
runs.all
runs.r_42
runs.r_42.specs
runs.r_42.specs.s_001
runs.r_42.specs.s_001.logs
runs.r_42.workers
runs.r_42.logs
```

Invalid (server returns 400 `invalid_topic`):

```
runs                    (no scope)
runs..specs             (empty segment)
runs.r_42.events        (unknown sub-scope)
spec.s_001              (must start with "runs.")
runs.r 42               (whitespace not allowed)
```

### 4.2 Subscription model

- The client passes a comma-separated list in `?topics=`. Maximum 32
  topics per connection. Beyond that, server returns 400
  `too_many_topics`.
- The server resolves each topic against the user's role (per
  `frontend_spec.md §10`). Any forbidden topic in the list fails the
  whole request with 403 `topic_forbidden`. Partial subscriptions are
  not allowed — fail-closed.
- A connection's topic set is **fixed**. To change topics, the client
  closes and reopens with a new `?topics=` value. There is no in-band
  `subscribe`/`unsubscribe` message.

### 4.3 Topic-to-kind matrix

Each kind is emitted on specific topic prefixes. Clients should
subscribe to the prefix that covers what they need:

| Kind                          | Topic                                        |
| ----------------------------- | -------------------------------------------- |
| `run_status_changed`          | `runs.<run_id>`                              |
| `run_counters_updated`        | `runs.<run_id>`                              |
| `auto_config_changed`         | `runs.<run_id>`                              |
| `interrupt_created`           | `runs.<run_id>`                              |
| `interrupt_resolved`          | `runs.<run_id>`                              |
| `spec_state_changed`          | `runs.<run_id>.specs` and `runs.<run_id>.specs.<spec_id>` (duplicated; see §4.4) |
| `spec_intervention_applied`   | `runs.<run_id>.specs.<spec_id>`              |
| `turn_appended`               | `runs.<run_id>.specs.<spec_id>`              |
| `worker_heartbeat`            | `runs.<run_id>.workers`                      |
| `log_line`                    | `runs.<run_id>.logs` and `runs.<run_id>.specs.<spec_id>.logs` (filtered; see §4.4) |
| `resync_required`             | any (sent on whichever topics are affected)  |

### 4.4 Fan-out rules

- A `spec_state_changed` event is published to BOTH the spec-specific
  topic (`runs.<run_id>.specs.<spec_id>`) AND the run-level specs topic
  (`runs.<run_id>.specs`). The two messages share the same `sequence`
  but different `topic` strings. Subscribers receive only the messages
  for topics they subscribed to. This avoids forcing a list-view
  client to subscribe to every per-spec topic.
- `log_line` events are published once to `runs.<run_id>.logs` and once
  to `runs.<run_id>.specs.<spec_id>.logs` IF the line has a `spec_id`.
  Lines without `spec_id` (e.g. orchestrator-level) appear only on the
  run-level topic.
- A subscriber to `runs.all` receives all run-level events for all runs
  in the system. Restricted to `admin` and `operator` roles.

---

## 5. Message envelope

### 5.1 Shape

Every SSE message is a `SSEMessage` (or a `SSEBatch` containing
`SSEMessage` items). The envelope is:

```
{
  "topic":     string,                    // matches §4.1 grammar
  "sequence":  integer (≥ 0, monotonic),  // per-topic counter
  "timestamp": string (RFC 3339 UTC),     // server send time
  "kind":      string (enum),             // §8 catalog
  "payload":   object                     // shape determined by `kind`
}
```

**Field is `sequence`, not `seq`.** Pre-rewrite drafts used both;
backend wins. `seq` is invalid and rejected by the schema.

### 5.2 Discriminated union

`kind` is the discriminator. Each `kind` value maps to **exactly one**
payload shape. The schema encodes this as a tagged union (each variant
pins `kind` to a `const`), so:

- TypeScript: `switch (m.kind)` narrows `m.payload` automatically.
  Adding a new kind without handling it causes a compile error.
- Python (Pydantic): `TypeAdapter(SSEMessageUnion).validate_python(d)`
  returns the concrete variant class. Unknown `kind` raises
  `ValidationError`.

### 5.3 Snapshot semantics

**The payload is a snapshot of the changed entity, NOT a patch.**

For `spec_state_changed`, `turn_appended`, `interrupt_created`, etc.,
the payload includes the FULL post-change object. Clients **replace**
their local copy by primary key (`spec_id`, `turn_id`, `interrupt_id`,
…). They do NOT merge.

This is a deliberate departure from JSON Merge Patch (RFC 7386), which
an earlier draft of `CLAUDE_frontend.md` proposed. Merge patches would
require:
- a separate per-entity patch generator on the backend,
- careful handling of `null` semantics (RFC 7386 treats `null` as
  field deletion),
- a per-entity merge implementation on the frontend.

For a system where state objects are small (≤ 2 KB after gzip), the
snapshot approach is simpler and more robust.

### 5.4 Empty / null fields

The wire format follows JSON conventions:

- Optional fields with no value are **omitted** (preferred) OR set to
  `null`. Producers may use either; consumers MUST handle both.
- Required fields are always present (schema enforced).
- Fields with default values (e.g. `intervention_pending: false`) are
  always present.

### 5.5 Timestamp format

RFC 3339 / ISO-8601, UTC, with millisecond precision when available.
Examples:

```
2026-05-25T09:30:14Z
2026-05-25T09:30:14.521Z
2026-05-25T09:30:14.521000Z       (Pydantic default — accepted)
```

Clients MUST parse all three forms. Producers SHOULD emit one of the
first two (millisecond or second precision).

---

## 6. Batching

### 6.1 When the server batches

The server accumulates messages on a topic for up to **250 ms**. If
multiple messages accumulate within the window, they are sent as a
single `SSEBatch`. Otherwise they are sent immediately as individual
`SSEMessage`s.

Rationale: in a busy run, `run_counters_updated` may fire 4–5 times per
second, and `turn_appended` may fire for many specs in parallel.
Batching reduces packet count and client wakeups by ~5x at peak load
without adding noticeable latency.

### 6.2 Batch shape

```
{
  "topic":    string,                    // same topic as inner messages
  "sequence": integer,                   // the LAST message's sequence
  "batch":    [SSEMessage, …]            // 1+ messages, all same topic, ascending sequence
}
```

On the wire, the SSE `event` line is the literal string `"batch"`:

```
id: 132
event: batch
data: {"topic":"runs.r_42.specs.s_001","sequence":132,"batch":[{"topic":"runs.r_42.specs.s_001","sequence":130,...},{"topic":"runs.r_42.specs.s_001","sequence":132,...}]}

```

### 6.3 Sequence rules inside a batch

- All inner messages share the same `topic` as the batch.
- Inner `sequence` values are **strictly ascending**.
- The batch's outer `sequence` equals the LAST inner message's
  `sequence`. (Not a separate counter.)
- The SSE `id:` line is the outer `sequence`. On reconnect, the
  `Last-Event-ID` reflects the last message the browser saw, which
  for a batch is the highest inner sequence — this works correctly
  because the outer sequence equals the highest inner sequence by
  definition.

### 6.4 Client handling

```
on receiving a frame:
  parse JSON
  if "batch" in JSON:
    for msg in JSON.batch:
      dispatch(msg)               # by msg.kind
  else:
    dispatch(JSON)
```

Clients MUST NOT distinguish behavior between a 1-message batch and a
non-batched single message — they are interchangeable. The server may
choose either; clients tolerate both.

### 6.5 What is NEVER batched

- `resync_required` (it's a control signal; latency matters)
- Messages from different topics (each topic has its own batcher)

Different kinds *within* the same topic CAN be batched together. The
example `examples/sse/batch.json` shows a `spec_state_changed` and a
`turn_appended` in one batch on `runs.r_42.specs.s_001`.

---

## 7. Sequences, reconnect, and replay

### 7.1 Per-topic monotonic sequence

Every topic has its own monotonic `sequence` counter, starting at `0`
when the topic's first event is published. The counter is server-side
state; clients do not generate sequences.

- Sequences are dense (no gaps) under normal operation.
- After a `resync_required`, the new sequence may not connect
  contiguously to the old — clients MUST treat resync as a discontinuity
  and refetch state via REST.

### 7.2 Reconnect mechanism

**`Last-Event-ID` HTTP header**, the W3C SSE standard. The browser
`EventSource` sets this automatically on reconnect.

Flow:

```
1. Client connects:                GET /api/events?topics=...&token=...
2. Server emits messages with:     id: 0, id: 1, id: 2, ...
3. Network drop after id: 17
4. Browser auto-reconnects:        GET /api/events?topics=...&token=...
                                   Last-Event-ID: 17
5. Server replays from 18 onward.
```

The `?since=<sequence>` query parameter is **NOT supported**. An earlier
draft used it; it is removed. The single mechanism is `Last-Event-ID`.

### 7.3 Server replay buffer

The server maintains a **60-second sliding window** of recent messages
per topic in Redis (or equivalent in-memory store). When a client
reconnects with `Last-Event-ID: N`:

```
let target = N + 1
let buffered = redis.range(topic, target, latest)
if buffered.first.sequence == target:
    # contiguous; replay from target
    for msg in buffered: send(msg)
elif buffered is empty AND target == latest + 1:
    # client is fully caught up
    pass
else:
    # gap — buffer doesn't reach back to target
    send(resync_required(reason="buffer_overflow", last_known_sequence=N))
```

### 7.4 `Last-Event-ID` handling

- Server parses as integer. Non-integer → log warning, treat as 0
  (replay everything in buffer, then live).
- Negative → treated as 0.
- `Last-Event-ID: 0` is special-cased to "start of buffer, do not
  replay" — this is the initial connection (the browser sets nothing,
  or the very first connect after page load).
- Per-topic interpretation: a single `Last-Event-ID` value is applied
  to every topic in the connection's subscription. Because topics have
  independent sequences, the server actually treats this as "for each
  topic, replay starting at min(buffer_start, Last-Event-ID + 1)" with
  per-topic accounting. The browser only knows one `Last-Event-ID`
  value; in practice this is the highest sequence the client has seen
  across any topic, and the server tolerates over-replay (a few
  duplicates) on the topics where it's stale. Idempotency by
  `sequence` on the client handles duplicates.

### 7.5 `resync_required` event

When the server cannot replay contiguously, it emits a
`resync_required` message and the client must:

1. Drop local cache for the affected topic(s).
2. Refetch authoritative state via REST (`GET /api/runs/:id`,
   `GET /api/runs/:id/specs`, etc.).
3. Update `Last-Event-ID` from the live stream from that point onward.

The `resync_required` payload carries `last_known_sequence` for
diagnostic logging on the client side; it is not used for replay.

### 7.6 Client-side sequence tracking

Each client maintains, per topic:

```
last_seen_sequence: int | null
```

On receiving any message (single or inside a batch):

```
if msg.sequence ≤ last_seen_sequence:
    # duplicate; ignore silently
    return
if last_seen_sequence is not null and msg.sequence > last_seen_sequence + 1:
    # gap detected (shouldn't happen under normal SSE, but defensive)
    request_resync(topic)
    return
apply(msg)
last_seen_sequence = msg.sequence
```

Duplicates are normal during reconnect; the silent dedup matters.

---

## 8. The eleven message kinds

For each kind: purpose, payload shape, example JSON. The examples below
were generated from the actual Pydantic models in `sailor_models.py`
and round-trip cleanly through the schema's discriminated union. They
are the **canonical reference**. Frontend tests should validate
against these; backend tests should produce these.

### 8.1 `run_status_changed`

Run lifecycle state transition. Replaces backend internal events
`RunStatusChanged`, `RunCompleted`, `RunFailed`, `RunCancelled`.

**Payload**: `RunStatusChangedPayload`

```
run_id          string              required
status          RunStatus           required   new status
previous_status RunStatus           required   value before transition
error           string | null       optional   if status=failed
```

**Example** (`examples/sse/run_status_changed.json`):

```json
{
  "topic": "runs.r_42",
  "sequence": 128,
  "timestamp": "2026-05-25T09:30:14.521Z",
  "kind": "run_status_changed",
  "payload": {
    "run_id": "r_42",
    "status": "running",
    "previous_status": "queued"
  }
}
```

Emitted on `runs.<run_id>`. One message per actual transition; idempotent
states are not re-emitted.

### 8.2 `run_counters_updated`

Run-level counter snapshot. Throttled to **≤ 1 per second per run**:
multiple counter changes within a second are coalesced into a single
emission carrying the latest values.

**Payload**: `RunCountersUpdatedPayload`

```
run_id    string         required
counters  RunCounters    required   FULL snapshot (16 fields; see schema)
```

**Example** (`examples/sse/run_counters_updated.json`):

```json
{
  "topic": "runs.r_42",
  "sequence": 129,
  "timestamp": "2026-05-25T09:30:15.001Z",
  "kind": "run_counters_updated",
  "payload": {
    "run_id": "r_42",
    "counters": {
      "specs_total": 1260,
      "specs_filtered_out": 8,
      "specs_emitted": 1252,
      "specs_phase2_queued": 994,
      "specs_phase2_running": 128,
      "specs_phase2_bug_triggered": 42,
      "specs_phase2_inconclusive": 58,
      "specs_phase2_likely_fp": 27,
      "specs_phase2_errored": 3,
      "specs_phase3_queued": 10,
      "specs_phase3_confirmed": 18,
      "specs_phase3_rejected": 14,
      "specs_phase3_errored": 0,
      "unique_confirmed": 15,
      "total_llm_tokens": 8420000,
      "total_klee_seconds": 14200
    }
  }
}
```

Field names match the schema exactly; legacy aliases like `total_specs`,
`bug_triggered`, `token_cost_usd` are removed.

### 8.3 `spec_state_changed`

A `Spec`'s state transitioned. Replaces backend internal events
`SpecEmitted`, `SpecFiltered`, `SpecPhase2Started`, `SpecPhase2Outcome`,
`SpecPhase3Started`, `SpecPhase3Verdict`, `SpecErrored`, `SpecRequeued`.

**Payload**: `SpecStateChangedPayload`

```
spec    Spec    required   FULL post-transition snapshot
```

**Example** (`examples/sse/spec_state_changed.json`):

```json
{
  "topic": "runs.r_42.specs.s_001",
  "sequence": 130,
  "timestamp": "2026-05-25T09:30:16.117Z",
  "kind": "spec_state_changed",
  "payload": {
    "spec": {
      "spec_id": "s_001",
      "run_id": "r_42",
      "rule_id": "local/cpp/cwe-122-heap-overflow",
      "cwe": "CWE-122",
      "file": "bfd/elfxx-x86.c",
      "line": 2286,
      "func": "elf_x86_link_hash_table",
      "message": "Potential heap buffer overflow at memcpy site",
      "phase1_status": "emitted",
      "phase2_status": "bug_triggered",
      "current_turn": 24,
      "turn_count_total": 24,
      "refine_count": 3,
      "phase2_outcome": "bug_triggered",
      "intervention_pending": false,
      "artifacts_root": "runs/r_42/phase2/s_001/",
      "created_at": "2026-05-25T09:00:00Z",
      "last_event_at": "2026-05-25T09:30:16.117Z",
      "token_cost": 47200
    }
  }
}
```

Emitted on BOTH `runs.<run_id>.specs` (run-level fan-out) AND
`runs.<run_id>.specs.<spec_id>` (per-spec). The two carry the same
sequence but different topic fields. Subscribers on the run-level topic
see all specs' state changes; subscribers on a per-spec topic see only
theirs.

### 8.4 `spec_intervention_applied`

A manual intervention (`edit_harness`, `force_outcome`, or `edit_spec`)
was applied to a spec.

**Payload**: `SpecInterventionAppliedPayload`

```
spec_id            string                                        required
intervention_type  "edit_harness" | "force_outcome" | "edit_spec" required
applied_at         RFC3339                                        required
actor              string | null                                  optional   user id
```

**Example** (`examples/sse/spec_intervention_applied.json`):

```json
{
  "topic": "runs.r_42.specs.s_001",
  "sequence": 131,
  "timestamp": "2026-05-25T09:30:17.401Z",
  "kind": "spec_intervention_applied",
  "payload": {
    "spec_id": "s_001",
    "intervention_type": "edit_harness",
    "applied_at": "2026-05-25T09:30:17.380Z",
    "actor": "u_alice"
  }
}
```

Note: this is a **notification only**. The actual spec state change is
delivered via a subsequent `spec_state_changed`. Frontends typically
show this as a transient toast and let `spec_state_changed` update the
view.

### 8.5 `turn_appended`

A new `Turn` was appended to a spec's history. The payload contains the
Turn summary only; the detailed `payload_ref` resolves via
`GET /api/runs/:id/specs/:id/turns/:turn_id` (returns `TurnDetail`).

**Payload**: `TurnAppendedPayload`

```
turn  Turn  required   summary form, NOT TurnDetail; no inline turn_payload
```

**Example** (`examples/sse/turn_appended.json`):

```json
{
  "topic": "runs.r_42.specs.s_001",
  "sequence": 132,
  "timestamp": "2026-05-25T09:30:18.005Z",
  "kind": "turn_appended",
  "payload": {
    "turn": {
      "turn_id": "t_5731",
      "spec_id": "s_001",
      "turn_number": 24,
      "kind": "klee_run",
      "started_at": "2026-05-25T09:30:00Z",
      "ended_at": "2026-05-25T09:30:18Z",
      "duration_ms": 18000,
      "payload_ref": "runs/r_42/phase2/s_001/turns/24.json",
      "summary": "KLEE: bug_triggered after 18s (heap-buffer-overflow at line 2286)",
      "tokens_consumed": 0,
      "klee_seconds": 18
    }
  }
}
```

The `kind` inside `payload.turn.kind` is the **turn kind**
(`TurnKind` enum: `explore | author | compile_fail | klee_run |
refinement | intervention | terminal`), distinct from the outer SSE
`kind`. Don't confuse the two.

### 8.6 `worker_heartbeat`

Periodic worker health and throughput report. Emitted every **5 seconds
per active worker**. Replaces backend internal events `WorkerHeartbeat`,
`WorkerTaskStarted`, `WorkerTaskFinished`, `WorkerDied` — these are all
folded into the heartbeat stream by including `status` and
`current_spec_id`.

**Payload**: `WorkerHeartbeatPayload`

```
worker_id                  string                  required
status                     "idle" | "busy" | "died" required
current_spec_id            string | null           optional
last_heartbeat             RFC3339                 required
throughput_specs_per_min   number | null           optional
tokens_per_min             number | null           optional
klee_seconds_per_min       number | null           optional
```

**Example** (`examples/sse/worker_heartbeat.json`):

```json
{
  "topic": "runs.r_42.workers",
  "sequence": 133,
  "timestamp": "2026-05-25T09:30:18.500Z",
  "kind": "worker_heartbeat",
  "payload": {
    "worker_id": "celery@worker-7",
    "status": "busy",
    "current_spec_id": "s_001",
    "last_heartbeat": "2026-05-25T09:30:18.500Z",
    "throughput_specs_per_min": 2.4,
    "tokens_per_min": 8200.0,
    "klee_seconds_per_min": 42.0
  }
}
```

Worker death is signaled by emitting one final heartbeat with
`status="died"` from the orchestrator process (not the dead worker
itself). After that, no more heartbeats for that `worker_id`.

### 8.7 `log_line`

A structured log line. The system emits these for cross-cutting events
that don't fit other kinds: orchestration decisions, LLM API errors
that didn't fail the spec, KLEE warnings, etc.

**Payload**: `LogLinePayload`

```
timestamp   RFC3339                                              required
level       "error" | "warn" | "info" | "debug"                  required
source      "celery"|"phase1"|"phase2"|"phase3"|"llm"|"klee"|"clang"|"asan"|"api"  required
run_id      string | null                                        optional
spec_id     string | null                                        optional
worker_id   string | null                                        optional
trace_id    string | null                                        optional
message     string                                               required
fields      object (additionalProperties: true) | null           optional   structured fields
```

**Example** (`examples/sse/log_line.json`):

```json
{
  "topic": "runs.r_42.logs",
  "sequence": 134,
  "timestamp": "2026-05-25T09:30:19.220Z",
  "kind": "log_line",
  "payload": {
    "timestamp": "2026-05-25T09:30:19.220Z",
    "level": "info",
    "source": "phase2",
    "run_id": "r_42",
    "spec_id": "s_001",
    "worker_id": "celery@worker-7",
    "trace_id": "trc_8a1f9c",
    "message": "KLEE search strategy=random-path; depth=347",
    "fields": {
      "strategy": "random-path",
      "depth": 347
    }
  }
}
```

The outer `timestamp` (SSE envelope's send time) and inner
`payload.timestamp` (the log event's actual time) usually differ by a
few milliseconds. UIs should display `payload.timestamp` since that's
when the event happened, not when the server forwarded it.

`fields` is open-schema for forward compatibility. UIs render it as a
collapsible JSON tree under the message line.

### 8.8 `resync_required`

The server cannot replay contiguously from the client's `Last-Event-ID`.
The client must drop local cache for the affected topic and refetch via
REST.

**Payload**: `ResyncRequiredPayload`

```
reason               "buffer_overflow" | "topic_subscription_reset" | "unknown" required
last_known_sequence  integer | null                                              optional
```

**Example** (`examples/sse/resync_required.json`):

```json
{
  "topic": "runs.r_42.specs",
  "sequence": 200,
  "timestamp": "2026-05-25T09:31:00Z",
  "kind": "resync_required",
  "payload": {
    "reason": "buffer_overflow",
    "last_known_sequence": 99
  }
}
```

Reasons:
- `buffer_overflow`: client was disconnected longer than 60s and the
  replay buffer has rotated past `Last-Event-ID`.
- `topic_subscription_reset`: server restarted; in-memory buffer is
  empty. (Persistent journals could change this in the future.)
- `unknown`: catch-all; client must resync.

Sequence numbering RESETS for the topic after this event. The next
real message will start a new sequence (typically 0).

### 8.9 `interrupt_created`

A pipeline function with `AutoConfig=false` is now paused waiting for
user input. See `interactive_control_spec.md §4`.

**Payload**: `InterruptCreatedPayload`

```
interrupt  InterruptPoint  required   FULL InterruptPoint snapshot
```

**Example** (`examples/sse/interrupt_created.json`):

```json
{
  "topic": "runs.r_42",
  "sequence": 135,
  "timestamp": "2026-05-25T09:30:20.001Z",
  "kind": "interrupt_created",
  "payload": {
    "interrupt": {
      "interrupt_id": "i_88",
      "run_id": "r_42",
      "spec_id": "s_001",
      "function_name": "phase2_klee_execution",
      "scope": "spec",
      "turn": 24,
      "status": "waiting",
      "created_at": "2026-05-25T09:30:20Z",
      "input_files": [
        {
          "name": "harness.bc",
          "artifact_ref": "runs/r_42/phase2/s_001/bitcode/harness.v3.bc",
          "size_bytes": 48211,
          "mime_type": "application/octet-stream",
          "editable": false,
          "version": 3
        }
      ],
      "option_overrides": {
        "klee_search_strategies": ["random-path"],
        "klee_timeout_seconds": 300,
        "klee_max_depth": 1000
      }
    }
  }
}
```

Run-scope interrupts have `spec_id: null`. Spec-scope interrupts have
`spec_id` set; the matching topic is still `runs.<run_id>` because the
interrupts list view is run-level.

### 8.10 `interrupt_resolved`

An interrupt was resumed or skipped (by a user or by the system, e.g.
on run cancellation).

**Payload**: `InterruptResolvedPayload`

```
interrupt_id  string                       required
run_id        string                       required
spec_id       string | null                optional
resolution    "resumed" | "skipped"        required
resolved_by   string | null                optional   user id, or null if system-resolved
```

**Example** (`examples/sse/interrupt_resolved.json`):

```json
{
  "topic": "runs.r_42",
  "sequence": 140,
  "timestamp": "2026-05-25T09:32:11.500Z",
  "kind": "interrupt_resolved",
  "payload": {
    "interrupt_id": "i_88",
    "run_id": "r_42",
    "spec_id": "s_001",
    "resolution": "resumed",
    "resolved_by": "u_alice"
  }
}
```

For bulk resume (`apply_to_all_matching=true`), one
`interrupt_resolved` is emitted per affected interrupt — not one
aggregate event. This matches the audit-log granularity from
`interactive_control_spec.md §8`.

### 8.11 `auto_config_changed`

`AutoConfig` was modified via `PATCH /api/runs/:id/auto-config`. Emitted
so other open browser tabs reflect the new sidebar state.

**Payload**: `AutoConfigChangedPayload`

```
run_id      string         required
auto_config AutoConfig     required   FULL snapshot (only explicitly-set keys)
changed_by  string | null  optional   user id
```

**Example** (`examples/sse/auto_config_changed.json`):

```json
{
  "topic": "runs.r_42",
  "sequence": 141,
  "timestamp": "2026-05-25T09:32:12Z",
  "kind": "auto_config_changed",
  "payload": {
    "run_id": "r_42",
    "auto_config": {
      "phase2_klee_execution": false,
      "phase3_result_classification": false
    },
    "changed_by": "u_alice"
  }
}
```

A key absent from `auto_config` means **default (true)**. The frontend
must apply this consistently: never assume missing = false.

---

## 9. Error responses (non-streaming)

Errors that prevent the stream from starting are returned as standard
JSON `ApiError` bodies with appropriate HTTP status, NOT as SSE events.

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "code": "token_expired",
  "message": "JWT signature is valid but token expired at 2026-05-25T09:00:00Z",
  "trace_id": "trc_abc123"
}
```

Mid-stream errors that should NOT close the connection (e.g. a worker
crash, a transient failure) are surfaced as `log_line` events with
`level="error"`. Mid-stream errors that DO close the connection (e.g.
a server shutdown) are not signaled in-band; the client detects the
disconnect and reconnects. After reconnect, if state has diverged, the
server emits `resync_required`.

There is **no SSE "error" event kind**. Browsers' `EventSource.onerror`
fires for transport-level errors only.

---

## 10. Implementation guidance — server

### 10.1 Architecture sketch

```
Worker / API ──pub──▶ Redis Pub/Sub ──sub──▶ Push Service ──SSE──▶ Browser
                          │
                          ├─ replay buffer (Redis sorted set per topic, 60s window)
                          └─ topic registry
```

- **Publishers** (workers, API handlers) construct concrete
  `SSEMessage*` Pydantic models (NEVER raw dicts) and publish to Redis.
  Pydantic validation rejects malformed payloads at publish time, not
  at deserialize time.
- **Push Service** subscribes to per-connection topic sets, fans out
  to SSE connections, manages batching window and keep-alive.
- **Replay buffer** is a Redis sorted set per topic, scored by
  `sequence`. ZADD on publish; ZRANGEBYSCORE on reconnect; ZREMRANGEBYSCORE
  by age every 10s for the 60s window.

### 10.2 Publisher pattern

```python
from datetime import datetime, timezone
from shared.contracts.sailor_models import (
    SSEMessageSpecStateChanged, SpecStateChangedPayload, Spec,
)

def publish_spec_state(publisher, topic: str, sequence: int, spec: Spec) -> None:
    msg = SSEMessageSpecStateChanged(
        topic=topic,
        sequence=sequence,
        timestamp=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        kind="spec_state_changed",
        payload=SpecStateChangedPayload(spec=spec),
    )
    publisher.publish(topic, msg.model_dump_json())
```

Bad patterns the schema prevents:

```python
# WRONG — raw dict bypasses validation
publisher.publish(topic, json.dumps({"topic": ..., "seq": 42, ...}))
#                                                ^^^ "seq" not "sequence"

# WRONG — manually concatenating SSE wire format
yield f"data: {{\"kind\": \"spec_state_changed\", ...}}\n\n"
# Use a helper that serializes from the model.
```

### 10.3 SSE serializer

```python
def to_sse_frame(msg) -> bytes:
    """
    msg: SSEMessage* or SSEBatch instance.
    """
    if isinstance(msg, SSEBatch):
        event_type = "batch"
        seq = msg.sequence
    else:
        event_type = msg.kind          # type: ignore
        seq = msg.sequence
    body = msg.model_dump_json()       # single line, no embedded newlines
    return f"id: {seq}\nevent: {event_type}\ndata: {body}\n\n".encode()
```

Note `model_dump_json()` does NOT emit newlines, matching §2.2.

### 10.4 Batching window

```python
async def batched_send(connection, topic):
    buffer: list[SSEMessage] = []
    timer_task: asyncio.Task | None = None

    async def flush():
        nonlocal buffer, timer_task
        if not buffer:
            return
        if len(buffer) == 1:
            await connection.send(to_sse_frame(buffer[0]))
        else:
            batch = SSEBatch(
                topic=topic,
                sequence=buffer[-1].sequence,
                batch=buffer,
            )
            await connection.send(to_sse_frame(batch))
        buffer = []
        timer_task = None

    async for msg in pubsub.listen(topic):
        buffer.append(msg)
        if timer_task is None:
            timer_task = asyncio.create_task(asyncio.sleep(0.25))
            timer_task.add_done_callback(lambda _: asyncio.create_task(flush()))
```

(Production code needs more care around cancellation and back-pressure;
this is illustrative.)

### 10.5 Keep-alive

```python
async def keep_alive(connection):
    while True:
        await asyncio.sleep(15)
        await connection.send(b": keep-alive\n\n")
```

### 10.6 Replay on reconnect

```python
async def handle_connection(request):
    token = request.query_params.get("token")
    if not token:
        return JSONResponse({"code": "missing_token", "message": "..."}, 401)
    user = verify_token(token)
    if user is None:
        return JSONResponse({"code": "invalid_token", "message": "..."}, 401)

    topics = parse_topics(request.query_params.get("topics", ""))
    check_topic_access(user, topics)   # raises 403 ApiError if forbidden

    last_event_id = request.headers.get("Last-Event-ID")
    try:
        last_seq = int(last_event_id) if last_event_id else None
    except ValueError:
        last_seq = None

    async def stream():
        # Replay phase
        for topic in topics:
            if last_seq is not None:
                replay = await redis.zrangebyscore(
                    f"replay:{topic}", last_seq + 1, "+inf"
                )
                first_seq = json.loads(replay[0])["sequence"] if replay else None
                if first_seq is not None and first_seq > last_seq + 1:
                    # Gap; emit resync_required
                    yield to_sse_frame(make_resync(topic, last_seq))
                    continue
                for raw in replay:
                    yield raw   # already SSE-framed bytes

        # Live phase
        async for raw in pubsub_listen(topics):
            yield raw

    return StreamingResponse(stream(), media_type="text/event-stream")
```

### 10.7 Counters throttling

`run_counters_updated` is the highest-frequency kind. Throttle on the
publisher side:

```python
class CountersThrottle:
    def __init__(self, max_hz: float = 1.0):
        self.last_sent: dict[str, float] = {}
        self.pending: dict[str, RunCounters] = {}
        self.min_interval = 1.0 / max_hz

    def submit(self, run_id: str, counters: RunCounters):
        now = time.monotonic()
        if run_id not in self.last_sent or (now - self.last_sent[run_id]) >= self.min_interval:
            publish(run_id, counters)
            self.last_sent[run_id] = now
            self.pending.pop(run_id, None)
        else:
            self.pending[run_id] = counters
            # ensure timer fires later to flush
            asyncio.create_task(self._flush_later(run_id, now + self.min_interval))
```

---

## 11. Implementation guidance — client

### 11.1 Hook structure (React, TypeScript)

```ts
import type {
  SSEMessage,
  SSEBatch,
} from '@/shared/contracts/sailor.types';

interface UseSSEOptions {
  topics: string[];
  token: string;
  onMessage: (m: SSEMessage) => void;
  onResync?: (topic: string) => void;
}

export function useSSE(opts: UseSSEOptions) {
  useEffect(() => {
    const url = new URL('/api/events', window.location.origin);
    url.searchParams.set('topics', opts.topics.join(','));
    url.searchParams.set('token', opts.token);

    const es = new EventSource(url.toString());
    es.onmessage = (e) => {
      const data: unknown = JSON.parse(e.data);
      if (isBatch(data)) {
        for (const msg of data.batch) opts.onMessage(msg);
      } else if (isMessage(data)) {
        opts.onMessage(data);
      }
    };
    es.onerror = () => {
      // Browser will auto-reconnect with Last-Event-ID.
      // Surface a status badge to the user; do not destroy state.
    };
    return () => es.close();
  }, [opts.topics.join(','), opts.token]);
}
```

### 11.2 Dispatcher

The dispatcher MUST use an exhaustive switch on `kind`. TypeScript will
fail to compile if a new kind is added without a corresponding case:

```ts
function dispatch(m: SSEMessage, stores: Stores) {
  switch (m.kind) {
    case 'run_status_changed':       stores.run.setStatus(m.payload.run_id, m.payload.status); return;
    case 'run_counters_updated':     stores.run.setCounters(m.payload.run_id, m.payload.counters); return;
    case 'spec_state_changed':       stores.spec.upsert(m.payload.spec); return;
    case 'spec_intervention_applied': stores.toast.show(`Intervention applied to ${m.payload.spec_id}`); return;
    case 'turn_appended':            stores.timeline.append(m.payload.turn); return;
    case 'worker_heartbeat':         stores.worker.upsert(m.payload); return;
    case 'log_line':                 stores.log.append(m.payload); return;
    case 'resync_required':          stores.resync(m.topic); return;
    case 'interrupt_created':        stores.interrupts.upsert(m.payload.interrupt); return;
    case 'interrupt_resolved':       stores.interrupts.markResolved(m.payload.interrupt_id, m.payload.resolution); return;
    case 'auto_config_changed':      stores.autoConfig.set(m.payload.run_id, m.payload.auto_config); return;
  }
}
```

### 11.3 Sequence dedup

Per `topic`, store `lastSeq: number | null` and ignore any incoming
`sequence <= lastSeq`. Otherwise update `lastSeq = sequence` after
applying.

### 11.4 Resync flow

```ts
function onResync(topic: string) {
  // Drop local cache for this topic's scope.
  if (topic.endsWith('.specs') || topic.match(/\.specs\.[^.]+$/)) {
    stores.spec.clearForRun(extractRunId(topic));
  }
  // Refetch authoritative state.
  apiClient.get(`/api/runs/${extractRunId(topic)}/specs`).then(stores.spec.replaceAll);
}
```

After refetch, the live stream continues. The new sequence may start
from a lower value than `lastSeq` (because the topic's sequence has
been reset). The dedup logic must reset `lastSeq = null` on resync.

### 11.5 What never to do client-side

- Do **not** read `event.type` (from `EventSource.MessageEvent.type`) as
  the kind discriminator. The JSON `kind` field is authoritative.
- Do **not** apply a JSON Merge Patch. The payload is a snapshot.
- Do **not** open multiple EventSource connections to the same set of
  topics — that doubles server load with no benefit. One per route.
- Do **not** send `?since=` in the URL. The server ignores it; use
  `Last-Event-ID` (which the browser sets automatically).

---

## 12. Conformance tests

A conforming implementation MUST pass these tests. They live in
`tests/sse/`; the test fixtures are the JSON files in
`shared/contracts/examples/sse/`.

### 12.1 Backend conformance

```
1. For each *.json in examples/sse/ except batch.json:
   - The JSON parses through TypeAdapter[SSEMessageUnion] without error.
   - The resulting model's .model_dump_json() round-trips to a structurally
     equivalent JSON (allowing key reordering and timestamp precision normalization).

2. For batch.json:
   - Parses as SSEBatch.
   - All inner messages parse as the union.
   - batch.sequence equals batch[-1].sequence.

3. For every kind, publish a constructed message and verify:
   - The SSE wire frame begins with `id: <sequence>\n`.
   - The SSE wire frame contains `event: <kind>\n`.
   - The SSE wire frame's data: line is single-line JSON.

4. Reconnect simulation:
   - Publish 30 messages, sequence 0..29.
   - Disconnect.
   - Reconnect with Last-Event-ID: 17.
   - Receive messages 18..29 in order, no duplicates.
   - Receive no messages 0..17.

5. Buffer overflow simulation:
   - Publish 100 messages with 70s of total wall time.
   - Disconnect before message 50.
   - Wait 65s past the publish of message 50.
   - Reconnect with Last-Event-ID: 49.
   - Receive resync_required with reason="buffer_overflow".
```

### 12.2 Frontend conformance

```
1. The dispatcher's switch on `kind` is exhaustive against the
   SSEMessageKind enum (TypeScript compile check via control flow analysis;
   adding a new kind without a case must produce TS2366).

2. For each examples/sse/*.json:
   - Parse the file.
   - Run through dispatch().
   - Verify the matching store method was called with the expected payload subset.

3. Batch dispatching:
   - Feed the batch.json content.
   - Verify dispatch() was called twice in order
     (sequence 130, then sequence 132).

4. Sequence dedup:
   - Feed a message with sequence 5 twice; verify dispatch() called once.

5. Resync handling:
   - Feed resync_required.json.
   - Verify the matching store clear method was called.
   - Feed a subsequent message with sequence 0; verify it is NOT dropped
     as a duplicate (resync resets the dedup state).
```

---

## 13. Changelog and versioning

This contract's stability is tied to `shared/contracts/sailor.schema.json`.
Changes are governed by the same rules as `backend_spec.md §14`:

| Change                                   | Compatibility               | Action                                |
| ---------------------------------------- | --------------------------- | ------------------------------------- |
| Add a new `kind` value                   | Non-breaking                | Clients ignore unknown kinds          |
| Add an optional field to a payload       | Non-breaking                | Clients ignore unknown fields         |
| Add a new value to a payload string enum | Non-breaking with caveat    | Clients must tolerate unknown values |
| Remove or rename a `kind` value          | **Breaking** — API version bump | Migrate clients before removing       |
| Remove a required payload field          | **Breaking** — API version bump | Migrate clients before removing       |
| Change `sequence` semantics              | **Breaking** — API version bump | This would require a redesign         |

The current contract is **version 1** of the SSE wire format. Schema
location: `shared/contracts/sailor.schema.json` at the commit referenced
by this document's revision.

---

## Appendix A: where to find what

| You need                                | Look at                                                          |
| --------------------------------------- | ---------------------------------------------------------------- |
| Type definitions (TS / Python)          | `shared/contracts/sailor.types.ts`, `shared/contracts/sailor_models.py` |
| JSON examples for every kind            | `shared/contracts/examples/sse/*.json`                           |
| Frontend reference implementation       | `shared/contracts/examples/frontend_useSSE.example.ts`           |
| Backend reference implementation        | `shared/contracts/examples/backend_router.example.py`            |
| The schema itself                       | `shared/contracts/sailor.schema.json`                            |
| Decisions log (why field X is named Y)  | `shared/contracts/README.md`                                     |
| Interrupt-system kinds                  | `interactive_control_spec.md §7`                                 |
| Run-level kinds (status, counters)      | `backend_spec.md §3` and §4 (entity definitions)                 |

## Appendix B: which documents must NOT redefine SSE contract details

The following files reference this document and MUST NOT have their own
versions of envelope shape, kind enum, payload shapes, reconnect
mechanism, auth mechanism, or batch format. If they do, that is a bug
to be fixed.

- `spec/frontend_spec.md`
- `spec/backend_spec.md`
- `spec/interactive_control_spec.md`
- `CLAUDE_frontend.md`
- `CLAUDE_backend.md`
- `CLAUDE_infra.md` (only references topic names and Redis usage; not the wire format)

Patches `PATCH_CLAUDE_frontend.md`, `PATCH_CLAUDE_backend.md`, and the
v2 rewrite of `interactive_control_spec.md` already incorporate this
rule. Any future doc must do the same.
