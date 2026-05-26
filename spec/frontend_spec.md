# Sailor Frontend Specification

A real-time monitoring and intervention UI for the Sailor pipeline.

---

## Goals

1. Run a Sailor pipeline end-to-end by submitting a project (as a zip).
2. Observe every spec moving through Phase 1 → 2 → 3 in real time.
3. Diagnose failures with enough context to fix them.
4. Intervene mid-pipeline — modify a harness, retry a phase, skip a spec —
   without restarting the run.
5. Browse all results and download artifacts from any phase.

Non-goals: this is an operator/researcher UI, not a public dashboard.
Authentication, multi-tenant isolation, and audit logging are required
but not the focus of this document.

---

## Vocabulary

The UI surfaces these entities. Each is a route, a panel, and an object
in the API.

```
Run         One pipeline invocation against one uploaded project.
            Has a status (queued | running | paused | completed | failed | cancelled),
            timestamps, a project zip reference, and aggregate counters.

Spec        One VulnerabilitySpec (Phase 1 output).
            Belongs to a Run. Has its own phase status:
              phase1: emitted / filtered
              phase2: queued / exploring / authoring / refining /
                      bug_triggered / inconclusive / likely_false_positive
              phase3: queued / running / confirmed / rejected / skipped

Turn        One step inside a Phase 2 loop iteration.
            Has a turn number (0..T_max), a kind (explore | author |
            compile_fail | klee_run | refinement), a duration, and
            a payload (LLM prompt/response, compiler diagnostic,
            KLEE outcome).

Artifact    A file produced by a phase: spec JSON, driver C, slice C,
            stubs C, assertion fragment, harness.bc, KLEE log,
            .ktest files, replay driver, ASan report, verified_bug.json.

Verdict     Final per-spec outcome at end of Run.
```

---

## Top-Level Routes

```
/                         Dashboard (all runs, summary tiles)
/runs/new                 Upload zip, configure run
/runs/:run_id             Run overview (live progress, spec table)
/runs/:run_id/specs/:i    Spec detail (timeline + artifacts + intervention)
/runs/:run_id/workers     Worker view (Celery queue, parallelism, throughput)
/runs/:run_id/logs        Aggregated log stream (filterable)
/settings                 Budgets, defaults, query suite config, API keys
```

---

## 1. Upload & Run Configuration (`/runs/new`)

### Inputs

```
Project source         drag-and-drop zip, or upload from URL
Project name           free-text label
Build command          text field, default empty (Sailor will attempt
                       autodetection: ./configure && make, cmake, etc.)
CodeQL build mode      autodetect / build-mode=none / custom command

Phase 1 query suite    multi-select from the 34-query catalog
                       (default: all 34; per-CWE toggles available)

Phase 2 budgets        phase2_t_explore, phase2_t_author, phase2_t_max,
                       phase2_t_klee_seconds, phase2_r_max
                       (defaults: 8 / 12 / 60 / 300s / 15)
                       UI labels may abbreviate (e.g. "T_max"); wire format
                       uses the snake_case names. See RunConfig in
                       shared/contracts/sailor.schema.json.

Phase 2 parallelism    integer (default 128, capped to worker pool size)

LLM provider           dropdown (configured server-side)
LLM model              dropdown filtered by provider

Skip patterns          editable file-path skip list (default = built-in)
                       editable function-name skip list

Phase 3                checkbox: run concrete validation (default on)
                       ASAN_OPTIONS override field
```

### Submission Behavior

- Server validates zip, returns a run_id, redirects to `/runs/:run_id`.
- Server-side validation: zip must contain a buildable C/C++ project
  (presence of Makefile, CMakeLists.txt, configure, or `compile_commands.json`).
- If autodetection fails, the run is created in state `needs_build_config`
  and the user is prompted to supply a build command before queueing.

### Re-run from existing run

The detail page exposes "Clone this run" which copies all config to
`/runs/new` so users can adjust budgets and re-run on the same project
without re-uploading.

---

## 2. Dashboard (`/`)

Tiles for the most recent N runs plus a table of all runs.

### Per-run tile

```
┌────────────────────────────────────────────────────────────────┐
│ binutils @ b2bc71a            Status: RUNNING  74% (12,432/16,800) │
│ Started 2h ago by alice                                         │
│                                                                 │
│ Phase 1: ████████████████████████ done    19,140 → 1,260 specs  │
│ Phase 2: ████████████░░░░░░░░░░░░ 62%     780 / 1,260 specs     │
│           triggered: 41   inconclusive: 380   FP: 359           │
│ Phase 3: ████████░░░░░░░░░░░░░░░░ 22%     9 / 41 confirmed      │
│                                                                 │
│ [View]  [Pause]  [Cancel]                                       │
└────────────────────────────────────────────────────────────────┘
```

### Runs table

Columns: name, started, duration, status, # specs, # confirmed,
# unique (after dedup), token cost, actions.

Sortable, filterable by status. Bulk select for delete/archive.

### Cross-run metrics row (top of dashboard)

```
Last 30 days:
  Total runs: 14    Confirmed bugs: 287    Avg tokens/bug: 4.2M
  Avg Phase 2 latency: 2.7 min/spec    Worker utilization: 81%
```

---

## 3. Run Detail (`/runs/:run_id`)

The main observation surface during a live run. Three sections.

### 3a. Header / Live Progress

Same shape as the dashboard tile, but with live-updating counters
(via server push, see §11) and full controls:

```
Pause Run    halts task dispatch; in-flight specs complete and stop
Resume Run   re-queues paused specs
Cancel Run   sends revoke to all in-flight tasks, marks run cancelled
Re-run failed specs    re-queues every spec in error/failed state
```

### 3b. Specs Table

The core of the UI. Virtualized table (must handle 30K+ rows).

Columns:
```
#       Spec ID (rule_id + file:line short form)
CWE     extracted from rule_id
File    relative path
Func    function name (resolved from line)
Phase   1 / 2 / 3 with sub-state badge
Status  color-coded: queued, running, success, warn, error
Last    timestamp of last state change
Turn    current Phase 2 turn (e.g. "23/60") if in Phase 2
Verdict CONFIRMED / inconclusive / likely FP / rejected, blank if unfinished
```

Row interactions:
- Click → navigate to spec detail.
- Right-click context menu: re-queue, skip, copy spec JSON, download artifacts.
- Multi-select with checkboxes for bulk re-queue / skip / export.

Filters (combinable):
- by phase, status, CWE, file path glob, verdict
- "Show only specs with errors"
- "Show only specs awaiting intervention"
- free-text search across spec message/snippet

Saved filter presets (e.g. "live errors", "needs my attention").

### 3c. Aggregate Charts Strip

Compact charts updated live:

```
Phase 2 outcomes (stacked area, over time)
  bug_triggered | inconclusive | likely_FP | error

Turn distribution histogram (Phase 2)
  shows where specs are getting stuck — high count at turn 60 means
  T_max is being hit; high count at compile_fail kind suggests
  build context issues

Compile error class breakdown
  incomplete_type | conflicting_proto | redefinition | other

LLM token consumption rate (tokens/min)
```

---

## 4. Spec Detail (`/runs/:run_id/specs/:i`)

The most detailed view. Where intervention happens. Four panes.

### 4a. Spec Header

Spec JSON pretty-printed, collapsible, copyable. Shows phase/status
chips, current turn, elapsed time, token cost so far.

### 4b. Timeline (left column, scrollable)

A vertical timeline of every event for this spec, oldest at top.
Each event is a clickable card:

```
Phase 1
  ● 14:02:11   spec emitted (rule local/cpp/cwe-120-overflow)
  ● 14:02:11   filtered: passed (file matches no skip patterns)
  ● 14:02:11   enriched: 4 suspect calls, 3 pointer vars, 1 length var

Phase 2
  ● 14:03:01   queued to worker pool
  ● 14:03:04   worker celery-worker-17 picked up task
  ◐ 14:03:04   Turn 0: explore  →  read elfxx-x86.c lines 2680-2720
  ◐ 14:03:08   Turn 1: explore  →  read elf_x86_link_hash_table def
  ...
  ◐ 14:05:11   Turn 9: author   →  write driver.c (3.2K LLM tokens)
  ◐ 14:05:24   Turn 10: author  →  write slice.c (5.1K LLM tokens)
  ◑ 14:05:38   Turn 13: compile_fail
                  class: incomplete_type
                  missing: struct asection::size
                  [View diagnostic]  [View fix prompt]
  ◐ 14:05:51   Turn 14: author   →  patch slice.c (type-level stub)
  ✓ 14:06:03   Turn 15: klee_run →  outcome: not_reached
                  entered: [_late_size_sections]
                  missed:  [memcpy site, branch guard at line 2696]
  ...
  ⚑ 14:09:42   Turn 24: bug_triggered
                  .ptr.err: OOB write, copy_size=17 > 16-byte dst

Phase 3
  ● 14:09:50   queued for validation
  ◐ 14:09:54   compiling project with -fsanitize=address ...
  ✓ 14:11:23   CONFIRMED
                  heap-buffer-overflow, elfxx-x86.c:2286
                  [Download verified_bug.json]  [Download replay driver]
```

Each card expands inline to show the full payload:
- For LLM turns: the prompt + response (with tool calls highlighted)
- For compile failures: full clang stderr + the auto-suggested fix
- For KLEE runs: full klee output, klee_warning_once probe trace,
  the .ktest objects if any
- For ASan: full crash report

### 4c. Artifacts (right column, top)

A file tree of every artifact produced for this spec, downloadable
individually or as a tarball:

```
spec/
  spec.json
phase2/
  exploration/
    notes.md (LLM scratchpad / source reads)
  drafts/
    driver.v1.c, driver.v2.c, ... driver.vN.c (one per author/refine turn)
    slice.v1.c, slice.v2.c, ...
    assertions.v1.c, ...
  bitcode/
    harness.bc
  klee_runs/
    run-001/  (klee_out directory: messages.txt, *.ktest, test*.kquery)
    run-002/
    ...
  outcome.json (final Phase 2 verdict + statistics)
phase3/
  replay_driver.c
  asan_report.txt
  verified_bug.json
```

Clicking a file opens a syntax-highlighted viewer (read-only by default).
"Edit" button enables intervention (see 4d).

### 4d. Intervention Panel (right column, bottom)

> Full specification: **spec/interactive_control_spec.md §3**
> This section is an overview only. interactive_control_spec.md is
> the authoritative source. In case of conflict, it takes precedence.

#### Overview

The Intervention Panel is the UI surface for manual control over
the pipeline. It appears when:

```
- A spec is paused (Auto = OFF reached a function boundary)
- A spec has errored
- The user clicks "Take control" on a running spec
```

#### Auto/Manual Mode

Every pipeline function has an **Auto checkbox**. When Auto = ON
(default), the function runs automatically. When Auto = OFF, the
pipeline pauses before that function and shows this panel.

Auto checkboxes are configurable at run creation and can be toggled
live during an active run. See interactive_control_spec.md §3.1~3.2.

#### Interrupt Points

The panel adapts to the function that triggered the interrupt.
Each interrupt shows the relevant input files and function-specific
controls. Full details per interrupt point:

```
Phase 1:
  §3.4  CodeQL DB Build         — edit build command, use existing DB
  §3.5  Query Execution         — query selector (checklist + .ql viewer)
  §3.6  SARIF Parsing           — view/replace SARIF, structural validation
  §3.7  Fact Enrichment         — view/edit findings.json
  §3.8  Spec Generation         — view/edit fact_packs.json + skip patterns

Phase 2:
  §3.9  Source Exploration      — view/edit spec.json + turn budgets
  §3.10 VulnerabilitySpec Selection — checklist of all specs with cost estimate
  §3.11 Driver Synthesis        — view/edit driver.c (compile validated)
  §3.12 Stub Synthesis          — view/edit slice.c (CWE-416 warning blocking)
  §3.13 Compile & Diagnose      — view error, apply suggested fix inline
  §3.14 KLEE Execution          — adjust KLEE options before run
  §3.15 LLM Disable Mode        — manual harness generation without LLM

Phase 3:
  §3.16 Replay Driver Gen       — view/edit replay_driver.c (klee_* blocking)
  §3.17 ASan Compilation        — adjust ASan flags (stub-file blocking)
  §3.18 Result Classification   — override verdict and CWE
```

#### Three Base Modes (Phase 2 spec-level)

```
Mode A — Edit harness, resume               → interactive_control_spec.md §3.11
  Edit driver.c / slice.c / assertions.c.
  Edit consumes 1 turn. Loop re-enters at CompileDiagnose.

Mode B — Force a Phase 2 outcome            → interactive_control_spec.md §3.14
  Skip to Phase 3 with uploaded .ktest, or
  mark spec as inconclusive / likely false positive.

Mode C — Edit spec, re-run from Phase 2     → interactive_control_spec.md §3.9
  Edit VulnerabilitySpec JSON.
  Old Phase 2 work archived under phase2/v1/.
  Fresh Phase 2 loop starts at turn 0.
```

All interventions require a confirmation modal showing exactly what
will change. Every replaced file is archived with a timestamp suffix
and is always recoverable.

#### Input File Validation

When any input file is replaced or edited, the server runs structural
validation before accepting. Validation rules and warning levels
(ERROR / WARNING / INFO) are defined in interactive_control_spec.md §3.19.

Example warning:
```
⚠ Expected SARIF structure but detected PDF content.
  Proceeding may cause parser errors.
```

---

## 5. Worker View (`/runs/:run_id/workers`)

For diagnosing parallelism issues.

```
Workers: 128 total    Active: 119    Idle: 9    Failed: 0

[●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●○○○○]
 hover any cell to see: worker id, current spec, turn, elapsed

Throughput:
  Specs/min: 47    Avg spec duration: 2.71 min    p95: 6.8 min
  LLM tokens/min: 1.2M    KLEE-seconds/min: 38

Queue depth: 412    Estimated time to drain: 8 min 30 s
```

Per-worker drill-down shows the spec it's working on (link to spec
detail) and recent stderr output.

---

## 6. Aggregated Logs (`/runs/:run_id/logs`)

A live, filterable log stream. One line per log event from any worker.

```
Filters:
  Level:       error | warn | info | debug
  Source:      celery | phase1 | phase2 | phase3 | llm | klee | clang | asan
  Spec ID:     free-text or selected from spec detail page
  Worker:      worker id
  Time range:  last 5m / 15m / 1h / custom

Display modes:
  Tail (auto-scroll, latest at bottom)
  Frozen (paused for inspection, "Resume tailing" button)
  Grouped by spec (collapses lines per spec into one expandable row)

Each line:
  timestamp  level  source  spec_id  message
```

Search across all logs in the run. Save filter as a preset.

---

## 7. Results Browser (`/runs/:run_id` → "Results" tab)

A separate view on the same run, optimized for post-completion analysis.

### 7a. Vulnerabilities Table

Only CONFIRMED specs. Default view after run completes.

Columns: CWE, ASan type, file:line (clickable, opens source viewer),
function, witness summary (`copy_size=17`), first seen, replay status
(does replay still crash?), [download evidence package].

Group by CWE / by file / by ASan type. Deduplicate by (file, func, line).

### 7b. Source Viewer

When clicking a file:line, opens the project source at that line with
syntax highlighting. The vulnerable statement is highlighted; the
guards, allocation site, and entry function are marked with gutter
annotations. Side panel shows the spec, witness, and ASan trace.

### 7c. Evidence Package Download

Per-bug evidence package (tarball):
```
verified_bug.json
spec.json                  (Phase 1 output)
driver.c, slice.c          (final Phase 2 harness)
witness.ktest              (raw KLEE witness)
replay_driver.c            (Phase 3 driver)
asan_report.txt
README.md                  (auto-generated reproduction instructions)
```

Bulk download: "Export all confirmed bugs in this run" → one big tarball.

### 7d. Comparison View

When the same project has multiple runs (different budgets, different
LLM, different query suite):

```
Side-by-side table:
  Run A (T_max=60)  Run B (T_max=120)  Run C (DeepSeek-V3.2)
  379 confirmed      412 confirmed       298 confirmed
  Unique to A: 12    Unique to B: 41     Unique to C: 7
  Shared: 320
```

Click a cell to see the spec lists.

---

## 8. Settings (`/settings`)

```
LLM providers       add/edit/test API endpoints, store keys
                    (keys are write-only; UI shows last-4 only)

Default budgets     T_explore, T_author, T_max, T_klee, R_max
                    overrideable per run

Query suite         enable/disable individual queries, upload custom
                    .ql files, view query catalog

Worker pool         configured pool size, queue names

Notifications       webhooks (run completed, run failed, new CONFIRMED)
                    email digest schedule

Retention           how long to keep run artifacts, automatic archival
                    rules (e.g. compress .ktest after 30 days)

Users / roles       see §10
```

---

## 9. Error Handling & Recovery

### Error classes the UI must distinguish

```
Pipeline-level errors
  Phase 1 errors:
    codeql_build_failure       project doesn't build under CodeQL
    codeql_query_error         a query failed to evaluate
    no_findings                Phase 1 produced 0 specs
  Phase 2 errors:
    spec_orchestrator_crash    Sailor code threw an exception
    llm_api_error              upstream LLM API returned 5xx / rate limit
    klee_crash                 KLEE itself crashed (not a timeout)
    bitcode_link_failure       llvm-link failed (distinct from compile_fail)
  Phase 3 errors:
    asan_build_failure         project doesn't build with -fsanitize=address
    replay_crash_in_harness    crash occurred but only in harness frames
                               (this is "rejected", not "error", but UI
                                surfaces it the same way)

Worker-level errors
  task_timeout              Celery soft/hard timeout
  worker_died               worker process gone, task lost
  retry_exhausted           task hit max retries
```

### Error surfacing rules

- Every error in the timeline expands to show the full traceback /
  diagnostic, the surrounding context (last 3 events), and an
  "Open in intervention panel" button when remediation is possible.
- Spec rows in the table get a red badge with the error class name.
- The dashboard tile shows a count of erroring specs.
- A persistent banner on the run page summarizes systemic errors
  ("47 specs failing with llm_api_error — check provider status").

### Automatic vs manual remediation

```
Automatic (Sailor's own behavior, UI just shows it):
  - LLM API error → exponential backoff retry
  - KLEE timeout → not retried (per-run timeout is the budget)
  - Worker death → Celery re-queues to another worker

Manual (user must act):
  - codeql_build_failure → user provides build command, restarts Phase 1
  - asan_build_failure → user provides ASan-specific build command
  - spec stuck after R_max → user opens intervention panel
```

---

## 10. Authentication & Roles

> Full specification: **spec/interactive_control_spec.md §2**
> This section is an overview only.

The UI exposes the ability to run code from arbitrary uploaded
projects, modify harnesses, and consume LLM tokens. Access control
is non-negotiable.

```
Routes:
  /register     public — create a new account (role = viewer by default)
  /login        public — sign in
  /settings/users  admin only — promote/demote/disable users

Roles (least to most privileged):
  viewer        read-only: see runs, results, artifacts, logs
  operator      viewer + start runs, cancel runs, download artifacts
  intervener    operator + intervention panel (Auto/Manual, interrupt, edit)
  admin         intervener + settings, user management, API keys

First registered user automatically receives admin role.
All subsequent registrations default to viewer.

Registration flow, password requirements, email confirmation,
role promotion UI: → interactive_control_spec.md §2

Audit log:
  Every state-changing action (run start, cancel, intervention, settings
  change, role change) is logged with user, timestamp, target, diff.
  Viewable at /settings/audit (admin only).
```

---

## 11. Real-Time Update Mechanism

The UI is heavily real-time. The transport layer matters.

### Recommended approach

Server-sent events (SSE) or WebSocket from the backend, with per-route
subscription topics:

```
Topic                                     Pushed events
runs.all                                  run state changes (any run)
runs.{run_id}                             run aggregate counters, status
runs.{run_id}.specs                       individual spec state changes
runs.{run_id}.specs.{spec_id}             timeline events for one spec
runs.{run_id}.specs.{spec_id}.logs        log lines for one spec
runs.{run_id}.workers                     worker heartbeat, throughput
```

The UI subscribes only to the topics relevant to the current view.
Spec detail page subscribes to its one spec's timeline + logs.
Dashboard subscribes to `runs.all` only.

### Update batching

To prevent UI thrash at 30K specs, the server batches state-change
events into 250ms windows and emits a single message containing the
diff. The client merges diffs into a normalized store.

### Reconnection

On disconnect, the client requests events since its last known
sequence number to catch up without a full reload.

---

## 12. Performance Requirements

```
Spec table        must render 30,000+ rows smoothly (virtualization)
                  filter/sort latency < 100ms on 30K rows
                  scroll at 60fps

Timeline          must handle 200+ events per spec without lag
                  lazy-load event payloads (LLM prompts can be 30K+ tokens)

Logs              must tail at >100 lines/sec without dropping frames
                  filter changes apply within 200ms

Source viewer     must open 100K-line files (e.g. binutils' bigger units)
                  syntax highlighting may be progressive

Initial load      run detail page interactive within 2s for 10K-spec run
```

---

## 13. API Surface (sketch)

The UI is a client of a REST + push API. Resources:

```
GET    /api/runs
POST   /api/runs                          create from uploaded zip
GET    /api/runs/:id
POST   /api/runs/:id/pause
POST   /api/runs/:id/resume
POST   /api/runs/:id/cancel
DELETE /api/runs/:id

GET    /api/runs/:id/specs                paginated, filterable
GET    /api/runs/:id/specs/:i
POST   /api/runs/:id/specs/:i/intervene   harness edit / force outcome
POST   /api/runs/:id/specs/:i/requeue

GET    /api/runs/:id/specs/:i/artifacts
GET    /api/runs/:id/specs/:i/artifacts/:path     (raw file)
GET    /api/runs/:id/specs/:i/artifacts.tar.gz

GET    /api/runs/:id/workers
GET    /api/runs/:id/logs                 query string filters
GET    /api/runs/:id/results              confirmed bugs only
GET    /api/runs/:id/results.tar.gz       evidence bundle

GET    /api/settings
PATCH  /api/settings

SSE    /api/events                        subscribe to topics
```

Additional endpoints for Auto/Manual mode, interrupt panels,
per-phase downloads, file validation, and user registration:
→ spec/interactive_control_spec.md §4.6 (download endpoints)
→ spec/interactive_control_spec.md §5   (backend API additions)

All write endpoints require operator/intervener/admin role per §10.
Idempotency keys on POST endpoints to make retry safe.

---

## 14. Open Questions for Implementation

These should be resolved before building, not during.

1. **Artifact storage.** Where do the per-spec artifacts live? With
   30K specs × ~50 files each, this is millions of small files per run.
   Object storage (S3-compatible) with content-addressed paths is the
   obvious choice; the UI never reads them directly, only through the
   API.

2. **Harness edit semantics.** Resolved.
   Edit consumes 1 turn from T_max.
   → spec/interactive_control_spec.md §3.11

3. **Source viewer scope.** Does the UI need to render the *entire*
   project source for navigation, or only the files referenced by
   specs? The former is heavier but enables exploration; the latter
   is lighter but limits context.

4. **Multi-run comparison granularity.** Comparison view in 7d
   compares specs by (file, func, line). Should we offer a fuzzier
   match (e.g. by CWE + function only) to catch the same bug located
   at slightly different lines across builds?

5. **LLM transcript redaction.** Phase 2 prompts include excerpts of
   the project source. If projects are proprietary, the UI must
   support redacting source from transcripts before any export. Flag
   on or off per project.

6. **Live KLEE integration.** Can the UI stream KLEE's progress (paths
   explored, current depth) instead of waiting for the run to end?
   This requires KLEE writing structured progress to a fifo or socket;
   feasible but invasive.
