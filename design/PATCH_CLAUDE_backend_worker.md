# PATCH_CLAUDE_backend_worker.md
# Changes to apply to design/CLAUDE_backend.md after worker spec is finalized.
# Apply these during Session 11 Step 0 or before Session 9 if implementing
# the backend and worker in the same pass.

---

## Patch 1 — Gap 2 (Database Schema): Add missing interrupt tables

In the "Tables (full list)" comment, replace:

```
  runs, specs, turns, verdicts, audit_events, users, settings,
  log_lines, idempotency_keys, export_jobs, interventions

(The interrupt-related tables — `interrupt_points`, `auto_config` — are
deferred until the interrupt contract is defined in the schema. See the
contracts README "What is NOT in this schema (yet)".)
```

With:

```
  runs, specs, turns, verdicts, audit_events, users, settings,
  log_lines, idempotency_keys, export_jobs, interventions,
  interrupt_points, auto_config

interrupt_points columns (ORM model: backend/models/interrupt_point.py):
  id               string, deterministic from (run_id, spec_id, function_name, "interrupt")
  run_id           string FK → runs
  spec_id          string FK → specs | null (Phase 1 gates have no spec)
  function_name    PipelineFunctionId string (from shared/contracts)
  scope            string "run" | "spec"
  status           string "waiting" | "resumed" | "skipped"
  resolved_by      string "user" | "system" | null
  input_files      JSONB list[{name, artifact_ref, mime_type}]
  modified_files   JSONB list[{name, artifact_ref}] | null
  option_overrides JSONB dict | null
  created_at       timestamp
  resolved_at      timestamp | null

auto_config columns (ORM model: backend/models/auto_config.py):
  run_id           string PK FK → runs
  config           JSONB: {PipelineFunctionId: bool}
  updated_at       timestamp

Default auto_config for a new run: all 11 PipelineFunctionId keys = true.
Created automatically when a run is created (POST /api/runs).
```

---

## Patch 2 — Gap 4 (Celery Queue Structure): Add Phase 2 soft/hard timeouts

Replace:

```
Soft timeout: T_max × T_klee = 60 × 300 = 18,000s per phase2_task
Hard timeout: soft + 60s
```

With:

```
Soft timeout: T_max × T_klee = 60 × 300 = 18,000s per phase2_task
Hard timeout: soft + 60s

Celery task config for phase2_task:
  acks_late=True             (re-deliver if worker dies mid-task)
  reject_on_worker_lost=True (ensure re-delivery, not silently dropped)
  max_retries=3              (worker-crash retries only; not LLM retries)
  soft_time_limit=18_000
  time_limit=18_060

Same acks_late + reject_on_worker_lost config applies to phase1_task and
phase3_task (their timeouts are shorter but the reliability guarantee is
the same).
```

---

## Patch 3 — Phase D (Celery Tasks): Correct interrupt function boundary list

Replace in "Interrupt check in phase1_task, phase2_task, phase3_task":

```
    Function boundaries supporting interrupt (spec §3.2):
      Phase 1: db_build, query_execution, sarif_parsing,
               fact_enrichment, spec_generation
      Phase 2: source_exploration, spec_selection, driver_synthesis,
               stub_synthesis, compile_diagnose, klee_execution,
               harness_refinement
      Phase 3: replay_driver_gen, asan_compilation, result_classification
```

With:

```
    Function boundaries (PipelineFunctionId values from shared/contracts):
      Phase 1: phase1_codeql_build, phase1_codeql_analyze,
               phase1_fact_enrichment, phase1_spec_generation
      Phase 2: phase2_source_exploration, phase2_driver_synthesis,
               phase2_stub_synthesis, phase2_klee_execution,
               phase2_harness_refinement
      Phase 3: phase3_asan_build, phase3_replay_execution

    Total: 11 function IDs (not 15 or 12 — earlier counts were wrong).
    The authoritative list is PipelineFunctionId in shared/contracts/sailor.schema.json.
    If that enum adds or removes values, update this comment to match.
```

---

## Patch 4 — Phase D: Correct interrupt polling interval

Replace:

```
      3. Pause task (poll interrupt_points row every 5s)
```

With:

```
      3. Pause task (poll interrupt_points row every 2s;
                     extend lease every 60s while waiting;
                     call check_control_flags() in each polling iteration
                     so cancel/pause works even while a gate is blocking)
```

---

## Patch 5 — Phase D: Add worker ID generation

After "Step D1. phase1_task (tasks/phase1.py)." add a new sub-note:

```
    Worker identity:
      worker_id is generated once at task-module import time:
        import os; from uuid import uuid4
        WORKER_ID = f"{os.environ.get('HOSTNAME','worker')}-{os.getpid()}-{uuid4().hex[:8]}"
      This string is written to specs.worker_id during lease acquisition
      and cleared on lease drop. It is included in all WorkerHeartbeat
      SSE events and in log_line rows.
```

---

## Patch 6 — Phase D: Clarify step D2 (phase2_task) heartbeat

In "Step D2. phase2_task (tasks/phase2.py)" add after "Lease heartbeat every 30s.":

```
           → Heartbeat runs as a background asyncio.Task created at the
             start of _phase2() and cancelled in the finally block.
           → On extend_lease failure (zero rows → lease stolen):
             set a stop flag; the main loop observes it and exits.
           → Idle heartbeat (no spec leased): separate 5s interval loop,
             publishes WorkerHeartbeat with status="idle".
             This loop runs for the entire lifetime of the Celery worker
             process, not just during task execution.
```

---

## Patch 7 — Constraint 8: Clarify scope

Replace:

```
8. Auto/Manual mode must not be enforced inside sailor/ pipeline code.
   sailor/ always runs to completion when called.
   Interrupt logic lives entirely in backend Celery tasks.
   sailor/ pipeline code has no knowledge of interrupt_points.
```

With:

```
8. Auto/Manual mode must not be enforced inside sailor/ pipeline code.
   sailor/ always runs to completion when called.
   Interrupt logic lives entirely in backend/tasks/_interrupt.py.
   sailor/ pipeline code has no knowledge of interrupt_points or AutoConfig.

   Concretely:
   - The interrupt gate is called BEFORE each sailor/ function, not inside it.
   - If the gate returns {skipped: True}, the task uses default outputs
     (defined in CLAUDE_worker.md Gap W7 table) and does NOT call the
     sailor/ function at all.
   - If the gate returns normally (resumed), the task calls the sailor/
     function with any option_overrides applied to its arguments.
```

---

## Patch 8 — Add Session 11 to the session list reference

In the comment at the top of CLAUDE_backend.md (or wherever sessions are listed),
add:

```
Session 11  — Worker Implementation (Celery Tasks)
```

This session builds on Session 9 (Backend). Its guide is design/CLAUDE_worker.md.
