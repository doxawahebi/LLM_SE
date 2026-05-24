# Sailor Backend Specification

Cross-reference: `frontend_spec.md`, `paper_overview.md`, `paper_phase1.md`,
`paper_phase2.md`, `paper_phase3.md`.

This spec describes the backend's contract: what state it owns, what
operations it exposes, what guarantees it makes. Implementation
framework choices (web framework, task queue, broker, push transport)
are decisions for the implementer; the spec is written so they can be
swapped without changing the contract.

---

## 1. Components

The backend has six logical components. They may be deployed as one
process or six; the boundary is what matters, not the packaging.

```
API Service          synchronous HTTP entry point. Validates requests,
                     authenticates, mutates the State Store, enqueues
                     tasks. Never executes pipeline work itself.

Task Workers         long-running processes that execute pipeline tasks
                     (Phase 1 run, single Phase 2 spec, single Phase 3
                     validation). Read/write the State Store and the
                     Artifact Store. Publish events to the Event Bus.

State Store          authoritative database for Run, Spec, Turn, and
                     Verdict entities. ACID for transitions; optimistic
                     concurrency on Spec/Run state changes.

Artifact Store       blob storage for files produced by the pipeline:
                     spec JSON, harness drafts, bitcode, .ktest, ASan
                     reports, evidence tarballs. Content-addressed for
                     deduplication.

Event Bus            pub/sub for real-time updates from workers to push
                     consumers. Lossy is acceptable; the State Store is
                     the source of truth.

Push Service         subscribes to the Event Bus, batches events into
                     250ms windows per topic, fans out to connected UI
                     clients. May coalesce duplicate diffs.
```

---

## 2. Domain Model

### 2.1 Entities

#### Run

```
run_id              string, opaque, server-generated
name                string, user-provided
project_zip_ref     artifact store reference to uploaded source
build_command       string, may be empty (autodetection)
codeql_build_mode   enum: autodetect | none | custom
config              embedded RunConfig (budgets, query suite, parallelism)
status              enum: see §3.1
created_at, started_at, completed_at  timestamps
created_by          user id
counters            embedded RunCounters (denormalized for the dashboard)
phase1_summary      embedded Phase1Summary (raw_findings, after_filter, etc.)
error               string | null, present when status=failed
```

#### RunConfig

```
phase1.query_suite       list of query ids (default: all 34)
phase1.skip_files        list of regex patterns
phase1.skip_functions    list of regex patterns
phase2.t_explore         int, default 8
phase2.t_author          int, default 12
phase2.t_max             int, default 60
phase2.t_klee_seconds    int, default 300
phase2.r_max             int, default 15
phase2.parallelism       int, default 128
phase2.llm_provider      string id
phase2.llm_model         string
phase3.enabled           bool, default true
phase3.asan_options      string, optional
```

#### RunCounters

```
specs_total                  int
specs_filtered_out           int
specs_emitted                int
specs_phase2_queued          int
specs_phase2_running         int
specs_phase2_bug_triggered   int
specs_phase2_inconclusive    int
specs_phase2_likely_fp       int
specs_phase2_errored         int
specs_phase3_queued          int
specs_phase3_confirmed       int
specs_phase3_rejected        int
unique_confirmed             int   # deduplicated by (file, func, line)
total_llm_tokens             int
total_klee_seconds           int
```

Counters are derived but maintained denormalized for fast dashboard
queries. The backend MUST guarantee they converge to the truth in the
State Store; they may lag the live event stream by seconds.

#### Spec

```
spec_id              string, deterministic from (run_id, rule_id, file, line)
run_id               string
rule_id, file, line, message, snippet         from Phase 1
trace, suspect_calls, pointer_vars,
length_vars, bounds_hints, build_context      from Phase 1
entrypoint           string, "LLM_INFER" or explicit function name
assertion_template   string | null

phase1_status        enum: emitted | filtered_out
phase2_status        enum: see §3.2
phase3_status        enum: see §3.3

current_turn         int, 0..t_max, valid during phase2
turn_count_total     int, ≥ current_turn (counts compile failures etc.)
refine_count         int, 0..r_max, valid during phase2

phase2_outcome       enum: bug_triggered | inconclusive | likely_false_positive
                     | errored | (null while running)
phase2_error         string | null
phase3_verdict       enum: confirmed | rejected | (null while running)
phase3_error         string | null

worker_id            string | null, set when a worker is processing
locked_until         timestamp | null, lease expiration
intervention_pending bool, true after user submits intervention
                     until worker observes it
artifacts_root       artifact store path prefix
created_at, last_event_at  timestamps
```

#### Turn

```
turn_id          string, deterministic from (spec_id, turn_number)
spec_id          string
turn_number      int, 0..t_max
kind             enum: explore | author | compile_fail | klee_run
                       | refinement | intervention | terminal
started_at, ended_at  timestamps
duration_ms      int
payload_ref      artifact store reference to the turn's payload
                 (LLM prompt+response, compile diagnostic, KLEE log)
summary          short string for the timeline card (no large blobs)
tokens_consumed  int | null
klee_seconds     int | null
```

Turns are append-only. They are the audit log of Phase 2.

#### Verdict

```
verdict_id        string
spec_id           string
verdict           enum: confirmed | rejected
cwe               string, e.g. "CWE-122"
asan_type         string, e.g. "heap-buffer-overflow"
file              string, ASan-reported source file
line              int, ASan-reported line
func              string
inputs            list of {name, value}  (witness summary)
asan_report_ref   artifact store reference to full ASan report
replay_driver_ref artifact store reference
verified_bug_json the verified_bug.json content (small, kept inline)
dedup_key         string, hash of (file, func, line) for unique counting
```

#### AuditEvent

```
event_id      string
actor         user id
action        enum: run_create | run_pause | run_resume | run_cancel
                  | spec_requeue | spec_intervene | spec_skip
                  | settings_change | role_change | login | logout
target        string, e.g. "run:<id>" or "spec:<id>"
diff          json | null, before/after for state-changing actions
created_at    timestamp
```

### 2.2 Storage Layout for Artifact References

Artifact references are opaque strings. They look like paths but they
ARE NOT filesystem paths to clients; they go through the API.

```
runs/<run_id>/project.zip
runs/<run_id>/phase1/codeql.db.tar.gz           # archived after Phase 1
runs/<run_id>/phase1/findings.sarif
runs/<run_id>/phase1/specs/<spec_id>.json
runs/<run_id>/phase2/<spec_id>/turns/<turn_number>.json
runs/<run_id>/phase2/<spec_id>/drafts/driver.v<N>.c
runs/<run_id>/phase2/<spec_id>/drafts/slice.v<N>.c
runs/<run_id>/phase2/<spec_id>/drafts/assertions.v<N>.c
runs/<run_id>/phase2/<spec_id>/bitcode/harness.bc
runs/<run_id>/phase2/<spec_id>/klee_runs/<run_index>/...
runs/<run_id>/phase3/<spec_id>/replay_driver.c
runs/<run_id>/phase3/<spec_id>/asan_report.txt
runs/<run_id>/phase3/<spec_id>/verified_bug.json
runs/<run_id>/exports/evidence-<spec_id>.tar.gz
runs/<run_id>/exports/all-confirmed.tar.gz
```

The implementation is free to use any blob store. Clients only ever see
artifact references through the API; they never construct paths themselves.

---

## 3. State Machines

### 3.1 Run States

```
                 ┌────────────────────────────────┐
                 ▼                                │
created → needs_build_config ─┐                  │
                              ▼                  │
                          queued ─────► running ─┤
                                       /  │  \   │
                                      /   ▼   \  │
                                     /  paused ─┘ (resume)
                                    ▼            
                            completed | failed | cancelled
```

Transitions and their triggers:

```
created          → needs_build_config   build autodetection failed
created          → queued               build OK or user-provided command
queued           → running              Phase 1 worker picks it up
running          → paused               user PAUSE
paused           → running              user RESUME
running, paused  → cancelled            user CANCEL
running          → completed            all specs reached terminal state
running          → failed               unrecoverable error in Phase 1
                                        (e.g. project doesn't build)
```

Once in `completed`, `failed`, or `cancelled`, a run is immutable except
for archival operations (deletion, tarball regeneration).

### 3.2 Spec phase2_status

```
queued
  └─► exploring  (worker picked up, t < T_explore)
       └─► authoring  (T_explore ≤ t < T_author)
            └─► refining  (t ≥ T_author, in compile-execute-refine loop)
                 ├─► bug_triggered           [terminal]
                 ├─► inconclusive            [terminal]
                 ├─► likely_false_positive   [terminal]
                 └─► errored                 [terminal]
```

The "intervention_pending" flag is orthogonal to phase2_status. When set,
the worker at its next turn-boundary check observes the flag, loads the
intervention payload from the State Store, applies it, and clears the
flag.

### 3.3 Spec phase3_status

```
not_eligible    (set when phase2_status != bug_triggered)
queued          (set when phase2_status = bug_triggered and run config has phase3.enabled)
running         (Phase 3 worker picked it up)
  ├─► confirmed   [terminal]
  ├─► rejected    [terminal]
  └─► errored     [terminal]
```

---

## 4. API Surface

The API is RESTful with one push channel. Request/response shapes are
described as object schemas; serialization format is JSON.

### 4.1 Authentication

All endpoints except `/api/health` and `/api/auth/login` require an
authenticated session. Sessions are bound to a user with a role
(`viewer | operator | intervener | admin`).

Permission requirements are stated per-endpoint as `[viewer+]`,
`[operator+]`, `[intervener+]`, `[admin]`.

### 4.2 Run Operations

```
POST   /api/runs                                                 [operator+]
  body:
    name: string
    project_zip: multipart upload OR project_zip_url: string
    build_command: string (optional)
    config: RunConfig (optional, falls back to settings defaults)
  response: { run_id, status }
  effect:
    - validates zip (must contain buildable C/C++ project markers)
    - writes zip to artifact store at runs/<run_id>/project.zip
    - creates Run row in state=created
    - attempts build autodetection; transitions to queued or needs_build_config
    - if queued, enqueues a phase1_task(run_id)

GET    /api/runs                                                  [viewer+]
  query: status, page, page_size, sort, search
  response: paginated list of Run summaries
            (id, name, status, counters, created_at, created_by)

GET    /api/runs/:run_id                                          [viewer+]
  response: full Run including config, counters, phase1_summary, error

POST   /api/runs/:run_id/build_config                            [operator+]
  body: { build_command: string }
  valid only when status = needs_build_config
  effect: stores build command, transitions to queued, enqueues phase1_task

POST   /api/runs/:run_id/pause                                   [operator+]
  valid only when status = running
  effect: sets status=paused; new Phase 2 tasks are not dispatched;
          in-flight tasks complete their current turn and check the flag

POST   /api/runs/:run_id/resume                                  [operator+]
  valid only when status = paused
  effect: sets status=running; re-enqueues all specs in phase2_status=queued

POST   /api/runs/:run_id/cancel                                  [operator+]
  valid when status ∈ {running, paused, queued}
  effect:
    - sets status=cancelled
    - revokes all pending Phase 2 / Phase 3 tasks for this run
    - in-flight tasks: signaled via cancellation flag, terminate at next
      turn boundary, persist their state as errored with reason=cancelled
    - specs not yet started: marked errored with reason=cancelled

POST   /api/runs/:run_id/clone                                   [operator+]
  body: optional RunConfig overrides
  response: new run in state=needs_build_config or queued (clones zip ref)

DELETE /api/runs/:run_id                                         [operator+]
  effect: soft-delete; status=archived. Hard deletion is admin-only and
  occurs after retention policy expires.
```

### 4.3 Spec Operations

```
GET    /api/runs/:run_id/specs                                    [viewer+]
  query: phase, status, cwe, file_glob, verdict, search,
         page, page_size, sort
  response: paginated list of Spec summaries.
            MUST support page_size up to 500 efficiently.
            MUST return Link header with next/prev cursors.

GET    /api/runs/:run_id/specs/:spec_id                           [viewer+]
  response: full Spec including current turn count, last event, artifacts
            root reference.

GET    /api/runs/:run_id/specs/:spec_id/turns                     [viewer+]
  query: since_turn (int), kind, limit
  response: list of Turn rows (no large payloads, just summaries)

GET    /api/runs/:run_id/specs/:spec_id/turns/:turn_id            [viewer+]
  response: Turn with payload inlined (LLM prompt/response, compile
            diagnostic, KLEE log). May be large; clients should request
            on demand.

POST   /api/runs/:run_id/specs/:spec_id/requeue                  [operator+]
  body: { reset_turn: bool, default false }
  valid when phase2_status is terminal
  effect:
    - if reset_turn: archive existing turns/artifacts to /v<n>/ prefix,
      reset current_turn=0, transition phase2_status=queued
    - else: re-enter the loop at the last refinement step
    - enqueues a phase2_task(spec_id)

POST   /api/runs/:run_id/specs/:spec_id/skip                     [operator+]
  body: { reason: string }
  effect: marks spec as errored with reason; not processed further

POST   /api/runs/:run_id/specs/:spec_id/intervene              [intervener+]
  body: one of three discriminated payloads (see §6 below)
  effect: sets intervention_pending=true, stores payload in spec record;
          if worker not currently processing, enqueues phase2_task
```

### 4.4 Artifact Operations

```
GET    /api/runs/:run_id/specs/:spec_id/artifacts                 [viewer+]
  response: tree of artifact references for this spec
            { path, size, mime_type, created_at }

GET    /api/runs/:run_id/specs/:spec_id/artifacts/*path           [viewer+]
  response: streamed file contents; supports Range header for large files.
            Path must be a valid artifact under this spec; 403 otherwise.

POST   /api/runs/:run_id/specs/:spec_id/artifacts.tar.gz          [viewer+]
  initiates evidence package build; returns 202 with a job id
GET    /api/jobs/:job_id                                          [viewer+]
  poll for export status; returns artifact ref when complete
```

Asynchronous tarball generation is required because evidence packages
for multi-thousand-spec runs are too large to build synchronously.

### 4.5 Run-Level Results

```
GET    /api/runs/:run_id/results                                  [viewer+]
  query: group_by (cwe | file | asan_type), deduplicate (bool, default true)
  response: list of Verdict rows for confirmed bugs.
            If deduplicate=true, one row per dedup_key.

GET    /api/runs/:run_id/results/compare?other=:other_run_id      [viewer+]
  response: { in_a_only, in_b_only, shared }
            each list contains Verdict summaries keyed by dedup_key

POST   /api/runs/:run_id/exports/all-confirmed                    [viewer+]
  initiates bulk evidence package; returns 202 with job id
```

### 4.6 Logs

```
GET    /api/runs/:run_id/logs                                     [viewer+]
  query: level, source, spec_id, worker_id, since, until, search, limit
  response: list of LogLine rows (timestamp, level, source, spec_id,
            worker_id, message)
  MUST support cursor pagination via 'since' token.

  Live tailing happens over the push channel (§5), not via this endpoint.
```

### 4.7 Workers

```
GET    /api/runs/:run_id/workers                                  [viewer+]
  response: list of Worker rows
            (worker_id, status, current_spec_id, last_heartbeat,
             throughput_specs_per_min, tokens_per_min, klee_seconds_per_min)

GET    /api/runs/:run_id/workers/throughput                       [viewer+]
  query: window (1m | 5m | 15m | 1h)
  response: aggregate throughput series
```

### 4.8 Settings

```
GET    /api/settings                                                [admin]
PATCH  /api/settings                                                [admin]
  body: partial Settings object
  effect: writes settings; some changes (e.g. budget defaults) take
          effect for new runs only

GET    /api/settings/audit                                          [admin]
  query: actor, action, target, since, until, page
  response: list of AuditEvent rows
```

---

## 5. Real-Time Push Channel

### 5.1 Connection

```
GET /api/events
  This endpoint upgrades to a server-push channel (SSE, WebSocket, or
  equivalent — choice is implementation-private). The contract:

  - Client sends a list of topic subscriptions after connecting.
  - Server pushes messages tagged with topic and sequence number.
  - Client may subscribe/unsubscribe at any time.
  - On reconnect, client provides last_sequence_seen; server replays
    missed messages from a bounded buffer (≥ 60 seconds of history).
  - If the gap exceeds the buffer, server signals "resync_required" and
    the client refetches state via REST.
```

### 5.2 Topics

```
runs.all                          all runs' status/counter changes
runs.<run_id>                     one run's status, counters, errors
runs.<run_id>.specs               diffs to spec status/turn/verdict
                                  for any spec in this run
runs.<run_id>.specs.<spec_id>     full per-spec stream:
                                    state changes, new turns,
                                    intervention acknowledgments
runs.<run_id>.specs.<spec_id>.logs   per-spec log lines
runs.<run_id>.workers             worker heartbeat, throughput
runs.<run_id>.logs                aggregated log stream
```

Frontend §11 specifies which topics each route subscribes to.

### 5.3 Message Shape

```
{
  topic:       string,
  sequence:    int,
  timestamp:   ISO-8601,
  kind:        "state_change" | "counter_diff" | "new_turn" |
               "log_line" | "worker_heartbeat" | "resync_required",
  payload:     object  (shape depends on kind)
}
```

### 5.4 Batching

The Push Service MUST batch events by topic in 250ms windows.
A batched message:

```
{
  topic:    string,
  sequence: int,            (sequence of the last event in the batch)
  batch:    [Message, ...]
}
```

Within a batch, the Push Service MAY coalesce events:
- For `counter_diff` on the same topic, keep only the latest.
- For `state_change` on the same spec, keep only the latest IF the
  intermediate states are not user-visible (e.g. queued → running can
  be coalesced; bug_triggered → confirmed cannot).

### 5.5 Backpressure

If a client's send buffer exceeds a threshold (implementation choice,
recommend 1 MB), the Push Service drops the connection. The client
reconnects and resyncs via REST. This prevents one slow client from
starving the rest.

---

## 6. Intervention Payloads

Submitted via `POST /api/runs/:run_id/specs/:spec_id/intervene`.
A discriminated union:

### 6.1 EditHarness

```
{
  type: "edit_harness",
  artifact: "driver" | "slice" | "assertions",
  contents: string,           // new file contents (UTF-8)
  base_version: int,          // optimistic concurrency: the version
                              // the user was editing
}
```

Backend behavior:

```
- Acquire lock on the spec record.
- If spec's latest version of `artifact` != base_version, return 409
  Conflict with the current contents (UI shows merge prompt).
- Else:
    write new artifact at drafts/<artifact>.v<latest+1>.c
    set intervention_pending = true
    record intervention payload referencing this draft
    append a Turn row with kind=intervention
    publish state_change event
- If worker is currently processing the spec:
    set the cancellation+resume flag in the State Store; the worker
    observes it at the next turn boundary, applies the intervention,
    continues from compile step.
- If worker is not processing (spec is in a terminal state):
    transition phase2_status back to refining
    enqueue phase2_task(spec_id) with continue_from_intervention=true
- Increment current_turn by 1 (intervention costs 1 turn, per
  frontend §4d). If current_turn ≥ T_max, the spec terminates
  as inconclusive immediately after the resumed compile attempt.
```

### 6.2 ForceOutcome

```
{
  type: "force_outcome",
  outcome: "skip_to_phase3" | "mark_inconclusive" | "mark_likely_fp",
  witness_ktest_ref?: artifact ref       // required if outcome=skip_to_phase3
}
```

Backend behavior:

```
- mark_inconclusive / mark_likely_fp:
    set phase2_outcome = the forced value
    set phase2_status terminal
    record Turn with kind=intervention, summary describing the forced state
    do not enqueue Phase 3
- skip_to_phase3:
    store the provided .ktest as the spec's witness
    set phase2_outcome = bug_triggered
    set phase2_status = bug_triggered
    enqueue phase3_task(spec_id)
```

### 6.3 EditSpec

```
{
  type: "edit_spec",
  spec: VulnerabilitySpec   // full replacement
}
```

Backend behavior:

```
- Archive existing Phase 2 artifacts to phase2/<spec_id>/v<n>/...
- Reset spec's phase2 fields:
    current_turn = 0
    turn_count_total = 0
    refine_count = 0
    phase2_status = queued
    phase2_outcome = null
    phase2_error = null
- Replace spec fields with new values (rule_id, message, etc.)
- Append Turn row with kind=intervention, summary="spec replaced"
- Enqueue phase2_task(spec_id)
```

---

## 7. Task Definitions

The backend runs three task types. Each is described by its inputs,
its idempotency rules, and its required behaviors. The task queue
implementation is unspecified.

### 7.1 phase1_task

```
Input: run_id

Steps:
  1. Mark run.status = running, set started_at.
  2. Materialize the project zip from artifact store to a working dir.
  3. Detect/run the project's build to satisfy CodeQL.
  4. Build CodeQL database.
  5. Run the configured query suite; collect SARIF findings.
  6. For each finding:
       a. Apply skip filters (file path, function name).
         - If filtered: write phase1_status = filtered_out, continue.
       b. Run fact enrichment regex extractors.
       c. Select entrypoint (LLM_INFER algorithm).
       d. Look up assertion template by CWE.
       e. Persist Spec row, write spec.json to artifact store.
       f. Append phase1_summary counters.
  7. Mark phase 1 done. Enqueue one phase2_task per emitted spec
     (respecting run.config.phase2.parallelism via task queue settings).
  8. Publish events at each step (see §8).

Failure modes:
  - codeql_build_failure: project doesn't build under CodeQL.
    Mark run.status = failed, error = "codeql_build_failure: <details>".
  - codeql_query_error: one query failed. Log and continue with the rest.
  - no_findings: legitimate empty result. Run completes with 0 specs.

Idempotency:
  Phase 1 is idempotent at the run level: re-running phase1_task with
  the same run_id MUST produce the same Spec rows (deterministic
  spec_id from rule_id + file + line). Implementations should detect
  prior progress and resume rather than restart.
```

### 7.2 phase2_task

```
Input: spec_id, continue_from_intervention?: bool

Lease model:
  Worker acquires a lease on the Spec row:
    locked_until = now + lease_duration (e.g. 5 minutes)
    worker_id = self
  Worker periodically extends the lease (heartbeat).
  If lease expires without extension, another worker may acquire it.

State persistence:
  At every turn boundary, the worker MUST persist:
    - updated current_turn, turn_count_total, refine_count
    - new Turn row with payload written to artifact store
    - any new draft artifacts produced this turn
  Persistence is transactional: the State Store update and the Turn
  row are committed together. Artifact writes are best-effort but
  content-addressed (see §7.4), so duplicate writes are harmless.

Control-flag check at each turn boundary:
  1. Read spec.run.status. If cancelled or paused, exit cooperatively:
       - paused: rewrite phase2_status=queued, drop lease
       - cancelled: write phase2_status=errored, reason=cancelled, drop lease
  2. Read spec.intervention_pending. If true:
       - load intervention payload from spec record
       - apply per §6
       - clear intervention_pending
       - resume loop

Loop body: implements paper Algorithm 1 (paper_phase2.md).

Termination:
  - bug_triggered: write witness artifacts, transition phase2_status,
    enqueue phase3_task if Phase 3 enabled
  - inconclusive / likely_false_positive: write outcome
  - errored: write error message and traceback

Failure modes (errored sub-types):
  llm_api_error            retry with exponential backoff (max 5 retries)
                           per-retry within the same task; only after
                           exhaustion is the spec marked errored
  llm_unrecoverable        e.g. content filter rejected, mark errored immediately
  klee_crash               not a timeout; KLEE itself died. Mark errored.
  bitcode_link_failure     persistent llvm-link failure after refinement attempts
  orchestrator_crash       uncaught exception in our code. Mark errored,
                           preserve traceback in spec.phase2_error.

Idempotency:
  Tasks may be re-delivered. Workers MUST be safe to re-execute against
  the same spec. The lease + turn-boundary persistence is the mechanism:
  a re-executing worker rehydrates state from the last persisted turn
  and continues. Turns are not duplicated because each turn's row has
  a deterministic id from (spec_id, turn_number).
```

### 7.3 phase3_task

```
Input: spec_id

Steps:
  1. Acquire lease.
  2. Load Phase 2 artifacts: driver, slice, witness .ktest.
  3. Build replay driver: replace klee_make_symbolic with memcpy of
     witness bytes. Strip klee_assume / klee_assert / klee_warning_once.
  4. Compile project with -fsanitize=address (re-invoke project build
     with ASan flags). Produces instrumented .a.
  5. Compile and link replay driver against .a → reproducer binary.
  6. Execute reproducer with configured ASAN_OPTIONS.
  7. Parse ASan output:
       - if no crash: phase3_verdict = rejected
       - if crash but no frame in project source: phase3_verdict = rejected
       - if crash with frame in project source:
           phase3_verdict = confirmed
           extract file/line/func from project-source frame
           refine CWE per ASan crash type (paper_phase3.md mapping)
           build Verdict row, write verified_bug.json
  8. Compute dedup_key = hash(file, func, line); set verdict.dedup_key
  9. Update run.counters.

Failure modes:
  asan_build_failure       project doesn't build with -fsanitize=address.
                           Mark spec.phase3_status = errored.
  replay_compile_failure   replay driver doesn't compile.
                           Mark errored.
  replay_runtime_failure   reproducer crashes outside ASan or in startup.
                           Mark errored.
  replay_clean_exit        reproducer ran without ASan firing.
                           Phase3 verdict = rejected (not errored).
  replay_crash_in_harness  ASan fired but all frames are in harness code.
                           Phase3 verdict = rejected.

Idempotency:
  Re-running phase3_task overwrites the prior Verdict for the spec.
  This is safe because Verdict is keyed by spec_id.
```

### 7.4 Artifact Storage Rules

Workers writing to the artifact store MUST:

```
- Use content-addressed paths where deterministic input → deterministic
  output (spec.json, witness .ktest from a specific KLEE run).
- For mutable artifacts (drafts/driver.v<N>.c), use a version counter
  read from the State Store, not from blob listing.
- Be safe against concurrent writes: an artifact write is either
  fully visible or not visible; no partial reads.
- Never overwrite a content-addressed path. Different content with the
  same logical name (e.g. KLEE output across runs) gets a different
  path via version suffixing.
```

---

## 8. Event Publication

Workers publish events to the Event Bus on every state transition.
Events are CONSUMED by the Push Service to drive the UI; the State
Store is the source of truth for any client doing a fresh fetch.

### 8.1 Event Schema

```
{
  event_id:    string  (deterministic from origin + sequence, for dedup)
  topic:       string
  sequence:    int     (monotonic per-topic)
  timestamp:   ISO-8601
  kind:        string  (see types below)
  payload:     object
}
```

### 8.2 Required Events

```
RunCreated, RunStarted, RunStatusChanged, RunCountersUpdated,
RunCompleted, RunFailed, RunCancelled

SpecEmitted, SpecFiltered, SpecPhase2Started, SpecPhase2Outcome,
SpecPhase3Started, SpecPhase3Verdict, SpecErrored,
SpecInterventionAcknowledged, SpecInterventionApplied,
SpecRequeued

TurnAppended         (kind = explore | author | compile_fail |
                      klee_run | refinement | intervention)

WorkerHeartbeat      (every 5s while idle, every 30s while busy)
WorkerTaskStarted, WorkerTaskFinished, WorkerDied

LogLine              (one per log emission, source-tagged)
```

### 8.3 Counter Update Discipline

`RunCountersUpdated` events MUST be emitted on a coarser cadence than
spec transitions (recommended: at most 1/second per run). The Push
Service further batches per §5.4.

### 8.4 Event Bus Loss Tolerance

The Event Bus MAY drop events. The Push Service MUST detect gaps via
sequence numbers and emit `resync_required` to affected clients. The
State Store is always the truth; events are an optimization.

---

## 9. Concurrency and Locking

### 9.1 Run-level

A run's status is the synchronization point for batch operations
(pause, resume, cancel). The State Store provides:

```
update Run set status = ? where id = ? and status in (...)
```

If zero rows match, the operation is rejected with the current status.
This prevents resume-while-cancelled and similar races.

### 9.2 Spec-level

Spec state changes from workers are protected by the lease:

```
update Spec set phase2_status = ?, current_turn = ?, ...
where id = ? and worker_id = ? and locked_until > now
```

Lease acquisition uses optimistic locking:

```
update Spec set worker_id = ?, locked_until = ? + lease_duration
where id = ? and (worker_id is null or locked_until < now)
```

Lease duration: long enough that a single turn rarely exceeds it
(recommend 5 minutes; per-turn KLEE timeout is 300s).

### 9.3 Intervention vs Worker

The control flow for an intervention arriving while a worker is active:

```
1. API writes intervention_pending = true (no lock needed; single field).
2. Worker reads intervention_pending at next turn boundary (every turn).
3. If true: worker applies intervention, clears flag. No need for
   the API to wait or coordinate.
4. If the worker has crashed or hung past lease expiration:
   - lease expires
   - any worker may acquire and observes intervention_pending
```

The intervention itself does NOT preempt the worker mid-turn. Pre-emption
is undesirable: it could corrupt KLEE state mid-run or leave an LLM
call half-completed. Worst case: user waits up to one turn (~3 seconds
for an explore turn, up to 300s for a KLEE turn).

### 9.4 Concurrent Interventions

If two interventions are submitted before the worker processes either:
- The State Store stores intervention payloads in a list, not as a
  single field; the worker processes them in submission order.
- Optimistic concurrency on EditHarness via `base_version` (§6.1)
  prevents two users from editing the same draft.

---

## 10. Logging

### 10.1 Log Sources

```
celery           task queue lifecycle events
phase1           Phase 1 stage messages
phase2           Phase 2 orchestrator messages
phase3           Phase 3 validation messages
llm              LLM API requests/responses (sanitized; tokens, model, latency)
klee             KLEE subprocess output
clang            compile diagnostics from build subprocesses
asan             AddressSanitizer output
api              HTTP request log
```

### 10.2 Log Shape

```
{
  timestamp:   ISO-8601
  level:       error | warn | info | debug
  source:      string from §10.1
  run_id:      string | null
  spec_id:     string | null
  worker_id:   string | null
  message:     string
  fields:      object (structured)
}
```

### 10.3 Log Routing

- All logs are written to the State Store's log table (or a sidecar
  log store) for the `GET /api/logs` endpoint.
- Logs are simultaneously published as `LogLine` events on the
  appropriate run-level and spec-level topics.
- Retention: configurable, default 30 days; older logs may be archived
  out of the hot path.

---

## 11. Idempotency Keys

The API accepts an `Idempotency-Key` header on every POST. The backend
MUST:

- Cache the response keyed by (user_id, endpoint, idempotency_key) for
  24 hours.
- On retry with the same key, return the cached response without
  re-executing.
- Use deterministic spec_id and turn_id to make worker-side writes
  idempotent without explicit keys.

---

## 12. Resource Limits and Quotas

Per-run defaults, configurable via Settings:

```
max_zip_size                500 MB
max_specs_per_run           50,000
max_concurrent_runs         configurable (default 4)
max_artifact_age            90 days before automatic archival
max_log_age                 30 days
max_evidence_tarball_size   2 GB
```

Per-spec safety limits (independent of T_max budget):

```
max_artifact_size_per_spec  500 MB total
max_turn_payload_size       50 MB (LLM prompts can be large)
max_klee_output_size        200 MB per run
```

Exceeding these limits transitions the spec to errored.

---

## 13. Health, Metrics, Tracing

```
GET /api/health
  response: { status, components: { state_store, artifact_store,
              event_bus, task_queue: ok|degraded|down } }

GET /api/metrics
  Prometheus-style metrics:
    sailor_runs_total{status}
    sailor_specs_total{phase, status}
    sailor_turn_duration_seconds{kind} (histogram)
    sailor_llm_tokens_total{provider, model}
    sailor_klee_seconds_total
    sailor_worker_lease_acquisitions_total
    sailor_api_request_duration_seconds (histogram)

Tracing:
  Each HTTP request and task execution carries a trace id propagated
  to subprocess boundaries (CodeQL, KLEE, clang, ASan reproducer).
  Logs include trace_id for correlation.
```

---

## 14. Backwards-Compatibility Rules

Once the API ships:

- Adding new fields to response objects: allowed.
- Adding new endpoints: allowed.
- Removing fields, renaming fields, changing types: requires API version
  bump (`/api/v2/...`).
- Adding new enum values: clients MUST tolerate unknown enum values.
- Adding new event kinds on the push channel: allowed; clients MUST
  ignore unknown kinds.

---

## 15. Open Questions for Implementation

These mirror the frontend's open questions and add backend-specific ones:

1. **State Store choice.** ACID with frequent small writes (turn rows,
   counter updates) and large read fan-out (spec list queries). A
   relational store is the obvious fit; NoSQL is viable if it supports
   transactions on spec rows. Recommend choosing based on operational
   familiarity, not novelty.

2. **Event Bus durability.** Section 8.4 allows the bus to drop events,
   but a perfectly durable bus simplifies client logic. Tradeoff:
   throughput vs reconnect complexity.

3. **Task queue retry semantics.** Distinguish between "retry the whole
   task" (worker crash) and "retry within the task" (LLM API error).
   The latter is the orchestrator's responsibility, not the task queue's.

4. **Artifact store consistency.** Object stores typically offer
   read-after-write but not list-after-write consistency. The spec
   assumes the API never lists; clients always traverse via stored
   references. Verify this assumption.

5. **Cross-run dedup.** Frontend §7d comparison view dedups within a
   run. Cross-run dedup (showing "this bug was found in every run of
   this project") requires a cross-run dedup index. Defer until
   product-asked.

6. **LLM API key isolation.** Settings stores provider API keys.
   Workers need to read them. Recommend a secret store rather than
   plain DB columns, with the State Store holding only secret-store
   references.
