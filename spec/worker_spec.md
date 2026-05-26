# Sailor — Worker Specification

Cross-references:
- `spec/backend_spec.md` — domain model, state machines, task definitions (§7), event publication (§8), concurrency (§9)
- `spec/sse_contract.md` — SSE wire contract; all event emission must conform to this
- `spec/interactive_control_spec.md` — interrupt system; §4 defines `PipelineFunctionId`, `InterruptPoint`, and `AutoConfig` check
- `shared/contracts/sailor.schema.json` — canonical type definitions for all wire types
- `sailor/infra/celery_tasks.py` — Celery task entry points
- `sailor/infra/docker_runner.py` — `DockerRunner`; the only legal way to run CodeQL / KLEE / clang / ASan

---

## 1. Scope

This document specifies the complete behavior of the three Celery task workers:

- `phase1_task` — static analysis via CodeQL; emits Specs
- `phase2_task` — LLM-driven harness synthesis + symbolic execution loop
- `phase3_task` — ASan concrete validation; produces Verdicts

It covers:

1. Lifecycle (startup, lease, heartbeat, shutdown)
2. Control-flag checks (pause, cancel, interrupt) at every turn boundary
3. Per-phase execution steps and artifact writes
4. Event publication obligations after every state transition
5. Error handling and failure modes
6. Idempotency requirements
7. The `PipelineFunctionId` interrupt gate — the concrete implementation of `interactive_control_spec.md §4.3`
8. Logging obligations

This document is **not** a substitute for `backend_spec.md §7`; it is the implementation-level elaboration of those task definitions. When this document and `backend_spec.md` conflict, `backend_spec.md` is authoritative. When this document and `sse_contract.md` conflict on wire format, `sse_contract.md` wins.

---

## 2. Execution Model

```
All Phase execution runs inside Docker containers via DockerRunner.exec().

Local machine (worker process):
  Python orchestration logic
  Docker CLI calls (DockerRunner)
  State Store reads / writes
  Event Bus publications
  Celery task lifecycle management

Runner container (docker/Dockerfile.runner):
  git clone / apt install / make / cmake        (Phase 1)
  codeql database create / codeql analyze       (Phase 1)
  clang -emit-llvm / klee                       (Phase 2)
  clang -fsanitize=address / reproducer binary  (Phase 3)

NEVER invoke codeql / klee / clang / make / git on the local machine.
```

`DockerRunner.stop()` MUST be called in a `finally` block. Containers must never be left running after task completion, failure, or cooperative exit.

---

## 3. Worker Identity and Heartbeat

### 3.1 Worker ID

Each worker process generates a stable `worker_id` at startup:

```
worker_id = "<celery-hostname>-<pid>-<uuid4_short>"
```

The `worker_id` is written to the State Store on every lease acquisition and removed when the lease is dropped (task complete, cooperative exit, or crash recovery).

### 3.2 Heartbeat Cadence

| Worker state                     | Heartbeat interval |
| -------------------------------- | ------------------ |
| Idle (no spec currently leased)  | every 5 seconds    |
| Busy (spec leased, turn running) | every 30 seconds   |

The heartbeat:

1. Extends the lease: `locked_until = now + lease_duration`.
2. Writes `last_heartbeat` on the Worker row in the State Store.
3. Publishes a `worker_heartbeat` SSE message on `runs.<run_id>.workers`.

Lease duration: **5 minutes** (300 s). A worker that does not heartbeat within 5 minutes of `locked_until` has its lease considered expired. Any other worker may then acquire the lease.

### 3.3 `WorkerHeartbeat` SSE Payload

```json
{
  "worker_id": "...",
  "run_id": "...",
  "status": "idle | busy",
  "current_spec_id": "... | null",
  "last_heartbeat": "ISO-8601",
  "throughput_specs_per_min": 0.0,
  "tokens_per_min": 0,
  "klee_seconds_per_min": 0.0
}
```

Throughput figures are rolling 5-minute averages, computed locally by the worker and written through on heartbeat.

---

## 4. Turn-Boundary Control-Flag Check

Every worker that holds a spec lease MUST perform the following check **before beginning each new turn**, in the order shown. The check is synchronous and must complete before any Phase logic runs.

```
FUNCTION check_control_flags(spec_id, run_id, worker_id):

  1. Read run.status from State Store.
     If run.status == "cancelled":
       write spec.phase2_status = "errored", reason = "cancelled"
       drop lease (set worker_id = null, locked_until = null)
       publish SpecErrored SSE
       raise CooperativeExit("cancelled")

     If run.status == "paused":
       write spec.phase2_status = "queued"  (re-queued for later)
       drop lease
       publish SpecPhase2Started/queued SSE? No — emit RunStatusChanged only
       raise CooperativeExit("paused")

  2. Read spec.intervention_pending from State Store.
     If intervention_pending == true:
       load intervention payload list from spec record
       for each payload (in submission order):
         apply_intervention(payload, spec_id)    — see §8
       write spec.intervention_pending = false
       publish SpecInterventionApplied SSE
       [continue loop — do NOT raise]
```

This check fires at **every** turn boundary: before turn 0, before each explore/author/refine/compile/klee sub-turn, and after each sub-turn returns. It does NOT preempt a running sub-turn. The worst-case latency before observing a cancel/pause is one full sub-turn duration.

---

## 5. `PipelineFunctionId` Interrupt Gate

This section implements `interactive_control_spec.md §4.3` for workers.

### 5.1 Function IDs

All possible values of `PipelineFunctionId` (from `shared/contracts/sailor.schema.json`):

```
phase1_codeql_build
phase1_codeql_analyze
phase1_fact_enrichment
phase1_spec_generation
phase2_source_exploration
phase2_driver_synthesis
phase2_stub_synthesis
phase2_klee_execution
phase2_harness_refinement
phase3_asan_build
phase3_replay_execution
```

### 5.2 Gate Logic

Immediately before each named function runs, the worker executes:

```
FUNCTION interrupt_gate(function_id, spec_id, run_id, scope):
  config = read AutoConfig for run_id from State Store
  if config[function_id] == true:
    return  # auto mode — run normally

  # Manual mode — create InterruptPoint and block
  interrupt = create InterruptPoint:
    interrupt_id   = deterministic from (run_id, spec_id, function_id, turn_number)
    run_id         = run_id
    spec_id        = spec_id (null for Phase 1 gates)
    function_name  = function_id
    scope          = scope  # "run" for Phase 1, "spec" for Phase 2/3
    status         = "waiting"
    created_at     = now
    input_files    = collect_input_files(function_id, spec_id)
    option_overrides = {}

  write InterruptPoint to State Store
  publish interrupt_created SSE on runs.<run_id> and runs.<run_id>.specs
  extend lease (blocking wait must not allow expiry)

  LOOP:
    poll State Store for interrupt.status every 2 seconds
    also extend lease every 60 seconds while waiting
    check_control_flags()   — honours cancel/pause even while waiting

    if interrupt.status == "resumed":
      apply resume payload:
        for each modified input_file: write to artifact store, update spec draft version
        apply option_overrides to the function call that follows
      return  # gate passes; function runs next with modified inputs

    if interrupt.status == "skipped":
      produce default outputs for function_id (see §5.3)
      return  # gate passes; outputs from default production are used downstream

  END LOOP
```

### 5.3 Default Outputs on Skip

| `PipelineFunctionId`        | Default output when skipped                                                                          |
| --------------------------- | ---------------------------------------------------------------------------------------------------- |
| `phase1_codeql_build`       | Abort Phase 1 (build is required); transition run to `failed`, error = "phase1_build_skipped"       |
| `phase1_codeql_analyze`     | Treat as zero findings; run completes with 0 specs                                                   |
| `phase1_fact_enrichment`    | Pass findings through un-enriched (all enrichment fields null)                                       |
| `phase1_spec_generation`    | Emit Specs with LLM_INFER entrypoint and no assertion template                                       |
| `phase2_source_exploration` | Proceed directly to driver synthesis with empty call-chain                                           |
| `phase2_driver_synthesis`   | Use the last known driver draft; if none exists, emit a minimal stub driver                          |
| `phase2_stub_synthesis`     | Use the last known stub draft; if none exists, emit empty stubs                                      |
| `phase2_klee_execution`     | Treat as inconclusive KLEE result; increment `current_turn` and continue to refinement               |
| `phase2_harness_refinement` | Mark spec `inconclusive` immediately (no further refinement)                                         |
| `phase3_asan_build`         | Mark spec `phase3_status = errored`, reason = "asan_build_skipped"                                   |
| `phase3_replay_execution`   | Mark spec `phase3_verdict = rejected` (no crash observed)                                            |

---

## 6. `phase1_task`

### 6.1 Input

```
run_id: str
```

### 6.2 Steps

```
1. SETUP
   a. Read Run from State Store. If status != "queued", log a warning and exit (idempotency guard).
   b. Write run.status = "running", run.started_at = now.
   c. Publish RunStarted SSE on runs.<run_id>.
   d. Start DockerRunner (docker/Dockerfile.runner).

2. MATERIALIZE SOURCE
   a. Read project_zip_ref from Run record.
   b. Stream artifact store → local temp dir → docker cp into container working dir.

3. BUILD (gate: phase1_codeql_build)
   a. interrupt_gate("phase1_codeql_build", spec_id=null, run_id, scope="run")
   b. Detect build system (Makefile → make; CMakeLists.txt → cmake; etc.).
      If run.build_command is set, use it directly.
      If run.codeql_build_mode == "none", skip build step.
   c. DockerRunner.exec(build_command).
      On failure: run.status = "failed", error = "codeql_build_failure: <stderr snippet>"
                  publish RunFailed SSE.
                  raise and fall into finally (DockerRunner.stop()).

4. CODEQL DATABASE
   a. DockerRunner.exec("codeql database create ...").
   b. DockerRunner.exec("codeql database finalize ...").

5. ANALYZE (gate: phase1_codeql_analyze)
   a. interrupt_gate("phase1_codeql_analyze", spec_id=null, run_id, scope="run")
   b. For each query_id in run.config.phase1.query_suite:
        DockerRunner.exec("codeql database analyze ...")
        On per-query failure: log at WARN, continue with remaining queries.
   c. Collect SARIF output. Write to artifact store: runs/<run_id>/phase1/findings.sarif.
   d. Publish RunStatusChanged SSE (counter update incoming).

6. FACT ENRICHMENT (gate: phase1_fact_enrichment)
   a. interrupt_gate("phase1_fact_enrichment", spec_id=null, run_id, scope="run")
   b. For each SARIF finding:
        Apply file-path skip filter (run.config.phase1.skip_files regex list).
        Apply function-name skip filter (run.config.phase1.skip_functions).
        If filtered: write Spec row with phase1_status = "filtered_out", publish SpecFiltered SSE.
        If not filtered: run 5 regex extractors (FactEnricher) → populate enrichment fields.

7. SPEC GENERATION (gate: phase1_spec_generation)
   a. interrupt_gate("phase1_spec_generation", spec_id=null, run_id, scope="run")
   b. For each enriched finding that passed the filter:
        Select entrypoint via LLM_INFER algorithm.
        Look up assertion template by CWE.
        Compute spec_id = deterministic_id(run_id, rule_id, file, line).
        Write Spec row (phase1_status = "emitted").
        Write spec.json to artifact store: runs/<run_id>/phase1/specs/<spec_id>.json.
        Increment run.phase1_summary counters.
        Publish SpecEmitted SSE on runs.<run_id>.specs.

8. ENQUEUE PHASE 2
   a. For each emitted Spec:
        Enqueue phase2_task(spec_id), respecting run.config.phase2.parallelism.
   b. Publish RunCountersUpdated SSE.

9. CLEANUP
   finally:
     DockerRunner.stop()
     If completed normally: log Phase 1 complete.
```

### 6.3 Failure Modes

| Failure                  | Action                                                                                                   |
| ------------------------ | -------------------------------------------------------------------------------------------------------- |
| `codeql_build_failure`   | `run.status = failed`, `run.error = "codeql_build_failure: ..."`. Publish `RunFailed`. Stop container. |
| `codeql_query_error`     | Log WARN, continue with remaining queries. Do not fail the run.                                         |
| `no_findings`            | Legitimate. `run.status = completed`, counters show 0 specs. Publish `RunCompleted`.                    |
| Any uncaught exception   | `run.status = failed`, `run.error = traceback`. Publish `RunFailed`. Stop container.                    |

### 6.4 Idempotency

Phase 1 is idempotent at the run level. Re-executing `phase1_task` with the same `run_id`:
- MUST produce the same Spec rows (deterministic `spec_id` from `rule_id + file + line`).
- MUST detect prior progress via `run.status` and SARIF already present in the artifact store; resume rather than restart where possible.
- Duplicate `SpecEmitted` events are suppressed if the Spec row already exists with `phase1_status = "emitted"`.

---

## 7. `phase2_task`

### 7.1 Input

```
spec_id: str
continue_from_intervention: bool = False
```

### 7.2 Lease Acquisition

```
UPDATE Spec
  SET worker_id = <self>, locked_until = now + 300s
  WHERE id = spec_id
    AND (worker_id IS NULL OR locked_until < now)
```

If zero rows updated: another worker holds the lease. Exit without error.

### 7.3 State Rehydration

On entry (including re-delivery):
- Read `current_turn`, `turn_count_total`, `refine_count`, `phase2_status` from Spec row.
- Load the last persisted Turn row to understand where to resume.
- If `continue_from_intervention`: load intervention payload applied at the latest intervention turn.

### 7.4 Main Loop (Algorithm 1, per `paper_phase2.md`)

```
PUBLISH SpecPhase2Started SSE

WHILE current_turn < T_max AND refine_count < R_max:

  check_control_flags(spec_id, run_id, worker_id)  ← §4

  if current_turn < T_explore:
    PHASE = "exploring"
    interrupt_gate("phase2_source_exploration", spec_id, run_id, scope="spec")
    result = SourceExplorer.run(...)
    persist_turn(kind="explore", result)

  elif current_turn < T_author:
    PHASE = "authoring"
    if driver not yet synthesized:
      interrupt_gate("phase2_driver_synthesis", spec_id, run_id, scope="spec")
      driver = DriverSynthesizer.run(...)
      persist_turn(kind="author", driver)
    if stubs not yet synthesized:
      interrupt_gate("phase2_stub_synthesis", spec_id, run_id, scope="spec")
      stubs = StubSynthesizer.run(...)
      persist_turn(kind="author", stubs)

  else:
    PHASE = "refining"
    interrupt_gate("phase2_klee_execution", spec_id, run_id, scope="spec")
    klee_result = DockerRunner.run_klee(harness)
    persist_turn(kind="klee_run", klee_result)

    if klee_result.bug_triggered:
      write witness artifacts
      write spec.phase2_status = "bug_triggered", phase2_outcome = "bug_triggered"
      publish SpecPhase2Outcome SSE
      if run.config.phase3.enabled:
        enqueue phase3_task(spec_id)
      drop lease
      RETURN

    if klee_result.inconclusive or no_new_paths:
      if refine_count < R_max:
        interrupt_gate("phase2_harness_refinement", spec_id, run_id, scope="spec")
        refined = HarnessRefiner.refine(...)
        persist_turn(kind="refinement", refined)
        refine_count += 1
      else:
        write spec.phase2_status terminal = "inconclusive" or "likely_false_positive"
        publish SpecPhase2Outcome SSE
        drop lease
        RETURN

  current_turn += 1
  persist_turn_counters()
  publish TurnAppended SSE on runs.<run_id>.specs.<spec_id>

END WHILE

# Budget exhausted
write spec.phase2_status = "inconclusive", outcome = "inconclusive"
publish SpecPhase2Outcome SSE
drop lease
```

### 7.5 Turn Persistence

At every turn boundary, the worker MUST commit atomically:

```
BEGIN TRANSACTION
  UPDATE Spec SET current_turn = N, turn_count_total = M, refine_count = R,
                  phase2_status = ..., last_event_at = now
    WHERE id = spec_id AND worker_id = <self> AND locked_until > now
  INSERT Turn (turn_id, spec_id, turn_number, kind, started_at, ended_at,
               duration_ms, summary, tokens_consumed, klee_seconds)
    ON CONFLICT (turn_id) DO NOTHING
COMMIT
```

If zero rows updated on the Spec (lease stolen): log WARN, exit without error.

Turn payload (LLM prompt/response, compiler output, KLEE log) is written to the artifact store **before** the DB commit. Content-addressed: re-writing the same content is harmless.

### 7.6 Failure Modes

| Failure type                | Retry behavior                                                                                | Terminal action                                     |
| --------------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `llm_api_error` (transient) | Exponential backoff, up to 5 retries within the task                                          | After 5 exhaustions: `phase2_status = errored`      |
| `llm_unrecoverable`         | None (e.g. content filter)                                                                    | `phase2_status = errored` immediately               |
| `klee_crash`                | None (KLEE itself died, not a timeout)                                                        | `phase2_status = errored`                           |
| `bitcode_link_failure`      | None after refinement attempts exhausted                                                      | `phase2_status = errored`                           |
| `orchestrator_crash`        | Celery re-delivers task; worker rehydrates from last Turn row                                 | After repeated crashes: `phase2_status = errored`   |

All terminal transitions write `spec.phase2_error = <message + traceback>` and publish `SpecErrored` SSE.

### 7.7 Idempotency

Tasks may be re-delivered by Celery. The worker MUST be safe to re-execute:
- Rehydrates state from the last persisted Turn row.
- Turn rows have deterministic IDs from `(spec_id, turn_number)` — `INSERT ... ON CONFLICT DO NOTHING` prevents duplicates.
- Artifact writes are content-addressed or version-suffixed: re-writing the same content is a no-op.

---

## 8. Intervention Application (within `phase2_task`)

Invoked from `check_control_flags()` when `spec.intervention_pending == true`.

### 8.1 `EditHarness`

```
1. Verify base_version matches spec's current draft version for the artifact.
   If mismatch: write intervention error to spec, publish SpecInterventionAcknowledged with error flag.
   (The API already checked this at submission time; if both checked, a concurrent edit slipped through.)
2. Write new artifact at: runs/<run_id>/phase2/<spec_id>/drafts/<artifact>.v<N+1>.c
3. Update spec's draft version counter.
4. Append Turn row with kind="intervention", summary="harness edited".
5. Publish SpecInterventionApplied SSE.
6. Set loop to resume from compile step (skip ahead to klee phase).
```

### 8.2 `ForceOutcome`

```
mark_inconclusive / mark_likely_fp:
  write spec.phase2_status = terminal value
  append Turn row with kind="intervention"
  publish SpecPhase2Outcome SSE
  do NOT enqueue Phase 3
  drop lease, exit loop

skip_to_phase3:
  store provided .ktest as spec's witness artifact
  write spec.phase2_outcome = "bug_triggered"
  write spec.phase2_status = "bug_triggered"
  enqueue phase3_task(spec_id)
  append Turn row with kind="intervention"
  publish SpecPhase2Outcome SSE
  drop lease, exit loop
```

### 8.3 `EditSpec`

```
1. Archive existing Phase 2 artifacts: rename prefix to phase2/<spec_id>/v<n>/...
2. Reset spec Phase 2 fields:
     current_turn = 0, turn_count_total = 0, refine_count = 0
     phase2_status = "queued", phase2_outcome = null, phase2_error = null
3. Replace spec fields (rule_id, message, entrypoint, etc.) with values from payload.
4. Append Turn row with kind="intervention", summary="spec replaced".
5. Publish SpecInterventionApplied SSE.
6. Continue loop from turn 0 (i.e., restart the algorithm for this spec).
```

---

## 9. `phase3_task`

### 9.1 Input

```
spec_id: str
```

### 9.2 Steps

```
1. LEASE
   Acquire lease on Spec (same optimistic locking as §7.2, but for phase3).
   Write spec.phase3_status = "running".
   Publish SpecPhase3Started SSE on runs.<run_id>.specs.

2. LOAD PHASE 2 ARTIFACTS
   Read from artifact store:
     driver.c (latest version)
     slice.c (latest version)
     witness .ktest file (from klee_runs/<run_index>/)

3. BUILD ASAN TARGET (gate: phase3_asan_build)
   interrupt_gate("phase3_asan_build", spec_id, run_id, scope="spec")
   a. Re-invoke project build with -fsanitize=address flags.
      DockerRunner.build_asan_archive(project_dir, asan_options).
      On failure: spec.phase3_status = "errored", error = "asan_build_failure: ..."
                  publish SpecErrored SSE. Drop lease. Return.
   b. Artifact output: instrumented static archive (.a).

4. BUILD REPLAY DRIVER
   a. ReplayDriverGenerator: replace klee_make_symbolic() with memcpy() of witness bytes.
      Strip klee_assume / klee_assert / klee_warning_once.
   b. Compile replay driver against the instrumented .a:
        DockerRunner.compile_harness(replay_driver.c, asan_archive).
      On failure: spec.phase3_status = "errored", error = "replay_compile_failure: ..."
                  publish SpecErrored SSE. Drop lease. Return.
   c. Write replay_driver.c to artifact store: runs/<run_id>/phase3/<spec_id>/replay_driver.c

5. EXECUTE REPLAY (gate: phase3_replay_execution)
   interrupt_gate("phase3_replay_execution", spec_id, run_id, scope="spec")
   a. DockerRunner.run_asan_replay(reproducer, asan_options).
   b. Parse asan_output:
        No crash → verdict = "rejected"
        Crash with no frame in project source → verdict = "rejected"
        Crash with frame in project source:
          verdict = "confirmed"
          extract file / line / func from first project-source frame
          refine CWE per ASan crash type (paper_phase3.md mapping)

6. WRITE VERDICT
   Build Verdict row:
     verdict_id = deterministic from spec_id
     verdict = "confirmed" | "rejected"
     cwe, asan_type, file, line, func  (from ASan output)
     inputs = witness summary
     asan_report_ref = runs/<run_id>/phase3/<spec_id>/asan_report.txt
     replay_driver_ref = artifact path above
     dedup_key = hash(file, func, line)
   Write verified_bug.json to artifact store: runs/<run_id>/phase3/<spec_id>/verified_bug.json

7. UPDATE SPEC AND COUNTERS
   write spec.phase3_status = "confirmed" | "rejected"
   write spec.phase3_verdict = verdict
   Update run.counters (specs_phase3_confirmed, specs_phase3_rejected, unique_confirmed).
   Publish RunCountersUpdated SSE.
   Publish SpecPhase3Verdict SSE on runs.<run_id>.specs and runs.<run_id>.specs.<spec_id>.

8. COMPLETION CHECK
   If all specs in this run have reached terminal phase3_status:
     write run.status = "completed", run.completed_at = now
     publish RunCompleted SSE on runs.<run_id>.

9. CLEANUP
   finally:
     DockerRunner.stop()
     drop lease
```

### 9.3 Failure Modes

| Failure                  | `phase3_status` | `phase3_error`              |
| ------------------------ | --------------- | --------------------------- |
| `asan_build_failure`     | `errored`       | "asan_build_failure: ..."   |
| `replay_compile_failure` | `errored`       | "replay_compile_failure: ..." |
| `replay_runtime_failure` | `errored`       | "replay_runtime_failure: ..." |
| `replay_clean_exit`      | `rejected`      | (not an error; normal path) |
| `replay_crash_in_harness`| `rejected`      | (ASan fired in harness only) |

### 9.4 Idempotency

Re-running `phase3_task` overwrites the prior Verdict for the spec. This is safe because Verdict is keyed by `spec_id`. All artifact writes use deterministic paths; re-writing the same content is a no-op.

---

## 10. Event Publication Obligations

Workers are responsible for publishing SSE events immediately after every state transition. All events conform to `sse_contract.md`. The event bus may drop events; the State Store is the truth. Clients that miss events may resync via REST.

### 10.1 Required Publications by Phase

**Phase 1 Worker**

| Trigger                        | SSE Kind                  | Topic                     |
| ------------------------------ | ------------------------- | ------------------------- |
| Run picks up, status = running | `run_status_changed`      | `runs.<run_id>`           |
| Each Spec emitted              | `spec_state_changed`      | `runs.<run_id>.specs`     |
| Each Spec filtered             | `spec_state_changed`      | `runs.<run_id>.specs`     |
| Counter change (≤ 1/s per run) | `run_counters_updated`    | `runs.<run_id>`           |
| interrupt_gate creates point   | `interrupt_created`       | `runs.<run_id>`, `runs.<run_id>.specs` |
| Run completed normally         | `run_status_changed`      | `runs.<run_id>`           |
| Run failed                     | `run_status_changed`      | `runs.<run_id>`           |
| Heartbeat                      | `worker_heartbeat`        | `runs.<run_id>.workers`   |

**Phase 2 Worker**

| Trigger                        | SSE Kind                       | Topic                                      |
| ------------------------------ | ------------------------------ | ------------------------------------------ |
| Spec picked up                 | `spec_state_changed`           | `runs.<run_id>.specs`                      |
| New turn committed             | `turn_appended`                | `runs.<run_id>.specs.<spec_id>`            |
| Phase 2 outcome                | `spec_state_changed`           | `runs.<run_id>.specs`                      |
| Intervention applied           | `spec_intervention_applied`    | `runs.<run_id>.specs.<spec_id>`            |
| Interrupt gate creates point   | `interrupt_created`            | `runs.<run_id>`, `runs.<run_id>.specs`     |
| Interrupt resolved             | `interrupt_resolved`           | `runs.<run_id>`, `runs.<run_id>.specs`     |
| Log line                       | `log_line`                     | `runs.<run_id>.specs.<spec_id>.logs`       |
| Heartbeat                      | `worker_heartbeat`             | `runs.<run_id>.workers`                    |

**Phase 3 Worker**

| Trigger                        | SSE Kind                  | Topic                                       |
| ------------------------------ | ------------------------- | ------------------------------------------- |
| Phase 3 started                | `spec_state_changed`      | `runs.<run_id>.specs`                       |
| Verdict written                | `spec_state_changed`      | `runs.<run_id>.specs`, `runs.<run_id>.specs.<spec_id>` |
| Counter update                 | `run_counters_updated`    | `runs.<run_id>`                             |
| Run completed                  | `run_status_changed`      | `runs.<run_id>`                             |
| Interrupt gate creates point   | `interrupt_created`       | `runs.<run_id>`, `runs.<run_id>.specs`      |
| Heartbeat                      | `worker_heartbeat`        | `runs.<run_id>.workers`                     |

### 10.2 Counter Update Discipline

`run_counters_updated` MUST be emitted at most once per second per run (rate-limited by the worker). The Push Service further batches per `sse_contract.md §6`.

---

## 11. Logging

Workers write log lines through the standard `logging` module (logger name `sailor.<module>`). Every log line is simultaneously:

1. Written to the State Store's log table (for `GET /api/runs/:run_id/logs`).
2. Published as a `log_line` SSE event on the appropriate topic.

### 11.1 Log Sources Used by Workers

| Source    | Emitted by                                                |
| --------- | --------------------------------------------------------- |
| `celery`  | Task queue lifecycle (picked up, completed, failed)       |
| `phase1`  | Phase 1 stage messages (build, analyze, enrich, emit)     |
| `phase2`  | Phase 2 orchestrator messages (turn started, KLEE result) |
| `phase3`  | Phase 3 messages (ASan build, replay, verdict)            |
| `llm`     | LLM API calls (sanitized: tokens, model, latency only)    |
| `klee`    | KLEE subprocess output (streamed from container)          |
| `clang`   | Compile diagnostics from build subprocesses               |
| `asan`    | AddressSanitizer output                                   |

### 11.2 Log Shape

```json
{
  "timestamp": "ISO-8601",
  "level": "error | warn | info | debug",
  "source": "<source from §11.1>",
  "run_id": "... | null",
  "spec_id": "... | null",
  "worker_id": "...",
  "message": "...",
  "fields": {}
}
```

All logs include `worker_id`. Phase 2 and Phase 3 logs include `spec_id`.

### 11.3 Streaming Container Output

`DockerRunner.exec()` returns a stream. Workers MUST stream container output line-by-line to the log table and Event Bus in real time — not buffer and emit in bulk at the end. This is what enables the frontend's live log tail on `/runs/:run_id/logs`.

---

## 12. Artifact Write Rules

Workers writing to the artifact store MUST follow these rules (elaborating `backend_spec.md §7.4`):

1. **Content-addressed paths** for deterministic outputs (spec.json, witness .ktest). Same input → same path. Re-writes are no-ops.
2. **Version-suffixed paths** for mutable draft artifacts (driver.v<N>.c). Version counter is read from State Store, not inferred from blob listing.
3. **Atomicity**: an artifact write is either fully visible or absent. Workers write to a temp path and rename (or use the object store's PUT-then-overwrite guarantee).
4. **Never overwrite a content-addressed path** with different content. Different KLEE runs → different version-suffixed paths.
5. **All artifact writes happen before the DB commit** that references them. If the DB commit fails, the artifact is orphaned (acceptable; content-addressed cleanup sweeps collect it).

---

## 13. Concurrency and Lease Discipline

### 13.1 Spec Lease

State updates from workers are protected by the lease:

```sql
UPDATE Spec
  SET phase2_status = ?, current_turn = ?, last_event_at = now
  WHERE id = ? AND worker_id = ? AND locked_until > now
```

If zero rows updated, the worker has lost the lease and MUST NOT continue. It logs a warning and exits.

### 13.2 Lost Lease Recovery

If a worker dies mid-turn (crash, OOM, container kill), the lease expires after 5 minutes. Any Celery worker may then acquire it. The acquiring worker rehydrates from the last committed Turn row and resumes from the next turn boundary.

### 13.3 Run Cancellation Propagation

On `POST /api/runs/:run_id/cancel` from the API:
1. API writes `run.status = "cancelled"`.
2. API revokes all pending (not yet started) Celery tasks for this run.
3. In-flight workers observe `run.status == "cancelled"` at the next turn-boundary `check_control_flags()`.
4. Worker writes `spec.phase2_status = "errored"`, reason = "cancelled", drops lease.
5. Publishes `SpecErrored` SSE.
6. Specs not yet started (status = "queued") are written to `errored` by the API directly.

### 13.4 Intervention vs. Worker (concurrent)

Follows `backend_spec.md §9.3` exactly. The intervention does not preempt the worker mid-turn. The worker observes `intervention_pending` at the next turn boundary. Worst-case latency: one full sub-turn (up to 300 s for a KLEE turn).

---

## 14. Resource Limits

Workers enforce per-spec safety limits defined in `backend_spec.md §12`:

| Limit                              | Value    | Action when exceeded                                  |
| ---------------------------------- | -------- | ----------------------------------------------------- |
| `max_artifact_size_per_spec`       | 500 MB   | Transition spec to `errored`, error = "artifact_quota" |
| `max_turn_payload_size`            | 50 MB    | Truncate payload; log WARN; continue                   |
| `max_klee_output_size`             | 200 MB   | Kill KLEE, treat as `klee_crash`                       |

Workers check cumulative artifact size before each write. The check reads from the State Store's artifact-size accounting column (maintained by the artifact service), not by listing blobs.

---

## 15. What Is NOT the Worker's Responsibility

The following are handled by the API Service, not workers:

- Validating request bodies (zip size, build command format)
- Issuing JWT tokens
- Idempotency-key deduplication of HTTP requests
- Triggering export tarballs (`POST /api/runs/:run_id/exports/all-confirmed`)
- Role-based access control on any endpoint
- Serving artifact bytes to clients
- The Push Service fan-out (worker publishes to Event Bus; Push Service fans out to SSE clients)

---

## 16. Files to Create or Modify

When implementing this spec, the concrete files are:

| File                              | What to implement                                                        |
| --------------------------------- | ------------------------------------------------------------------------ |
| `sailor/infra/celery_tasks.py`    | `phase1_task`, `phase2_task`, `phase3_task` Celery task definitions      |
| `sailor/infra/docker_runner.py`   | `DockerRunner` methods used by workers (already exists; extend as needed)|
| `backend/tasks/phase1.py`         | Phase 1 business logic (steps §6.2); called from `phase1_task`          |
| `backend/tasks/phase2.py`         | Phase 2 loop (§7.4); intervention application (§8); called from `phase2_task` |
| `backend/tasks/phase3.py`         | Phase 3 execution (§9.2); called from `phase3_task`                     |
| `backend/services/event_service.py` | Event Bus publication helpers; called at every state transition         |
| `backend/services/push_service.py`  | Push Service batching (250 ms windows); fans out to SSE clients         |

No new code goes into legacy directories (`phases/`, `codeql/`, `models/`, `core/`).

---

## 17. Files Needed Before Implementation Can Begin

The following files must exist (or be verified to contain the correct content) before worker implementation starts:

| File                                      | Needed for                                                                        |
| ----------------------------------------- | --------------------------------------------------------------------------------- |
| `shared/contracts/sailor.schema.json`     | All 14 types listed in `interactive_control_spec.md §12` must be present         |
| `shared/contracts/sailor_models.py`       | Pydantic bindings auto-generated from schema; used in all worker DB writes       |
| `docker/Dockerfile.runner`                | Runner image with CodeQL + KLEE + clang + ASan; used by `DockerRunner`           |
| `docker/Dockerfile.worker`                | Celery worker image; must copy `sailor/` package without legacy dirs             |
| `backend/models/interrupt_point.py`       | `InterruptPoint` ORM model; created for Phase 2 gate logic                       |
| `backend/models/auto_config.py`           | `AutoConfig` ORM model; read by every interrupt gate                             |
| `backend/services/artifact_service.py`    | Must expose `write(path, content)` and `read(path)` with content-addressing     |
| `backend/celery_app.py`                   | Celery app instance; `sailor/infra/celery_tasks.py` registers tasks here         |

The runner image and the shared schema are the most common blockers; verify both before starting a session.
