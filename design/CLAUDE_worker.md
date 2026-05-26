# CLAUDE_worker.md — Sailor Worker (Celery Tasks) Implementation Prompt

> Claude Code reads this file during Session 11 — Worker Implementation.
> Stack: Celery 5.x + Redis (broker) + PostgreSQL (state store) + MinIO (artifacts).
> All Absolute Rules in CLAUDE.md apply.
> sailor/ pipeline package is imported here — do NOT re-implement pipeline logic.
> Session 9 (Backend) must be complete before starting this session.

---

> **Pydantic models for all wire types are in `shared/contracts/sailor_models.py`.**
> Import; never redefine. If a type is missing, add it to
> `shared/contracts/sailor.schema.json` and run `./scripts/regen_contracts.sh`.
> Backend-internal shapes (task argument dicts, lease tuples) live in
> `backend/schemas/internal.py` only.

---

## Scope

This session implements the three Celery task workers and their supporting
services. The backend API (Session 9) owns the HTTP endpoints; this
session owns the async execution that those endpoints enqueue.

```
phase1_task    backend/tasks/phase1.py   — CodeQL analysis; emits Specs
phase2_task    backend/tasks/phase2.py   — LLM + KLEE loop; produces outcomes
phase3_task    backend/tasks/phase3.py   — ASan replay; produces Verdicts
```

Supporting pieces also owned here:
- Lease management helpers in `services/spec_service.py`
- Heartbeat loop
- Interrupt gate in every task
- `run_counters_updated` throttle logic in `services/event_service.py`
- Streaming container log publication

---

## Execution Model

```
Worker process (Celery, Dockerfile.worker):
  Python orchestration only.
  Reads/writes: PostgreSQL (state store), MinIO (artifacts), Redis (events).
  Spawns: DockerRunner → runner container per phase invocation.

Runner container (Dockerfile.runner, ephemeral):
  Runs: codeql / klee / clang / make / git clone.
  ALL Phase execution happens here, NEVER on the worker process directly.

DockerRunner lifecycle (NON-NEGOTIABLE):
  runner.start()  ← synchronous (subprocess.run internally)
  runner.stop()   ← MUST be in a finally block; containers must not leak
```

DockerRunner is synchronous. In async task functions use:

```python
@celery_app.task(...)
def phase1_task(self, run_id: str) -> dict:
    return asyncio.get_event_loop().run_until_complete(_phase1(run_id))

async def _phase1(run_id: str) -> dict:
    runner = DockerRunner(cve_id=run_id, config=RunnerConfig())
    runner.start()        # synchronous — do NOT await
    try:
        result = await _run_phase1_steps(runner, run_id)
    finally:
        runner.stop()     # synchronous — do NOT await
    return result
```

---

## Key Constraints (from CLAUDE_backend.md, summarised)

1. Tasks only orchestrate: create DockerRunner, call PipelineN, persist results,
   publish events. NEVER reimplement pipeline logic.
2. All state transitions are atomic:
   `UPDATE ... WHERE status IN (...); zero-row → 409 / cooperative exit`.
3. Turns are append-only. Never UPDATE a Turn row.
4. Artifact paths are opaque to clients — always presigned URLs (302 redirects).
5. `intervention_pending` is a **list** in the DB, not a bool. Process in order.
6. LLM keys are never returned by any endpoint.
7. Auto/Manual mode (interrupt gate) lives in backend tasks only.
   `sailor/` pipeline code has NO knowledge of `interrupt_points`.
8. All error responses use `ApiError` from `shared/contracts/sailor_models.py`.

---

## Gap Resolutions (worker-specific)

### Gap W1: Worker ID

```
worker_id = f"{celery_hostname}-{os.getpid()}-{uuid4().hex[:8]}"
Generated at module load time (stable for the process lifetime).
Stored in: specs.worker_id during lease hold.
```

### Gap W2: Heartbeat Cadence

```
Idle (no spec leased):  emit WorkerHeartbeat every 5 seconds.
Busy (spec leased):     extend lease + emit WorkerHeartbeat every 30 seconds.
Lease duration:         300 seconds (5 minutes).

Implementation: use a background asyncio.Task or threading.Timer.
On task completion: cancel the heartbeat loop.
```

### Gap W3: Celery Task Configuration

```python
@celery_app.task(
    bind=True,
    name="tasks.phase2_task",
    queue="phase2",
    acks_late=True,            # re-deliver if worker crashes
    reject_on_worker_lost=True,
    max_retries=3,             # Celery-level retries (worker crash only)
    soft_time_limit=18_000,    # T_max × T_klee = 60 × 300
    time_limit=18_060,
)
```

Celery-level retries handle worker crashes only.
LLM API errors are retried INSIDE the task with exponential backoff
(base 2s, max 5 attempts, cap 60s). See Gap 3 §15.3 in CLAUDE_backend.md.

### Gap W4: Interrupt Gate Polling

```
Poll interval: every 2 seconds.
Lease extension while waiting: every 60 seconds.
Cooperative exit: check_control_flags() inside the polling loop.
```

### Gap W5: RunCounters Throttle

```
Publish run_counters_updated at most once per second per run.
Implementation: store last_published_at[run_id] in worker-local dict.
If now - last_published_at < 1.0s: skip publish, schedule a deferred
  flush with asyncio.call_later(1.0, flush_counters).
```

### Gap W6: Container Log Streaming

```
DockerRunner.exec() returns a result dict with full stderr/stdout.
For long-running steps (CodeQL analyze, KLEE, ASan), stream line-by-line:
  Use `docker logs --follow <container_id>` or capture from exec output.
  For each line: write LogLine to DB + publish log_line SSE event.
  Source tag: "klee" for KLEE output, "clang" for compile, "asan" for ASan.
```

### Gap W7: PipelineFunctionId Mapping

The `PipelineFunctionId` values used by tasks (from `shared/contracts`):

```
Phase 1: phase1_codeql_build, phase1_codeql_analyze,
          phase1_fact_enrichment, phase1_spec_generation

Phase 2: phase2_source_exploration, phase2_driver_synthesis,
          phase2_stub_synthesis, phase2_klee_execution,
          phase2_harness_refinement

Phase 3: phase3_asan_build, phase3_replay_execution
```

All 11 values must have interrupt gate checks. The interrupt gate reads
`auto_config[function_id]` from the State Store.

---

## Implementation Order

### Phase A — Shared Infrastructure

  **Step A1. Lease management (`services/spec_service.py` additions).**

  Add to the existing spec service (do not replace the whole file):

  ```python
  async def acquire_phase2_lease(
      session: AsyncSession,
      spec_id: str,
      worker_id: str,
      lease_seconds: int = 300,
  ) -> bool:
      """Optimistic locking. Returns True if lease acquired."""
      result = await session.execute(
          update(Spec)
          .where(
              Spec.id == spec_id,
              or_(Spec.worker_id.is_(None), Spec.locked_until < func.now()),
          )
          .values(worker_id=worker_id, locked_until=func.now() + timedelta(seconds=lease_seconds))
          .returning(Spec.id)
      )
      await session.commit()
      return result.scalar_one_or_none() is not None

  async def extend_lease(session, spec_id, worker_id, lease_seconds=300) -> bool:
      """Returns False if lease was stolen."""
      result = await session.execute(
          update(Spec)
          .where(Spec.id == spec_id, Spec.worker_id == worker_id)
          .values(locked_until=func.now() + timedelta(seconds=lease_seconds))
          .returning(Spec.id)
      )
      await session.commit()
      return result.scalar_one_or_none() is not None

  async def drop_lease(session, spec_id, worker_id) -> None:
      await session.execute(
          update(Spec)
          .where(Spec.id == spec_id, Spec.worker_id == worker_id)
          .values(worker_id=None, locked_until=None)
      )
      await session.commit()

  async def persist_turn(
      session, spec_id, worker_id, turn: TurnRow,
      spec_updates: dict,
  ) -> bool:
      """Atomic: update Spec counters + insert Turn. Returns False if lease lost."""
      async with session.begin():
          spec_result = await session.execute(
              update(Spec)
              .where(Spec.id == spec_id, Spec.worker_id == worker_id,
                     Spec.locked_until > func.now())
              .values(**spec_updates)
              .returning(Spec.id)
          )
          if spec_result.scalar_one_or_none() is None:
              return False  # lease stolen
          await session.execute(
              insert(Turn).values(**turn.to_dict()).prefix_with("OR IGNORE")
              # Postgres: ON CONFLICT (turn_id) DO NOTHING
          )
      return True
  ```

  **Step A2. Control-flag check function.**

  ```python
  # backend/tasks/_control.py
  from shared.contracts.sailor_models import RunStatus

  class CooperativeExit(Exception):
      def __init__(self, reason: str):
          self.reason = reason

  async def check_control_flags(
      session: AsyncSession,
      spec_id: str,
      run_id: str,
      worker_id: str,
      event_service: EventService,
  ) -> None:
      """
      Must be called before every turn and inside every interrupt-gate loop.
      Order: cancel → paused → intervention.
      Raises CooperativeExit if the worker must stop.
      """
      # 1. Run status
      run = await session.get(Run, run_id)
      if run.status == RunStatus.cancelled:
          await session.execute(
              update(Spec).where(Spec.id == spec_id, Spec.worker_id == worker_id)
              .values(phase2_status="errored", phase2_error="cancelled")
          )
          await session.commit()
          await event_service.publish_spec_state_changed(spec_id)
          raise CooperativeExit("cancelled")

      if run.status == RunStatus.paused:
          await session.execute(
              update(Spec).where(Spec.id == spec_id, Spec.worker_id == worker_id)
              .values(phase2_status="queued", worker_id=None, locked_until=None)
          )
          await session.commit()
          raise CooperativeExit("paused")

      # 2. Intervention pending (list, process in order)
      spec = await session.get(Spec, spec_id)
      if spec.intervention_pending:
          for payload in spec.intervention_pending:
              await apply_intervention(session, spec_id, worker_id, payload, event_service)
          await session.execute(
              update(Spec).where(Spec.id == spec_id)
              .values(intervention_pending=[])
          )
          await session.commit()
          await event_service.publish_spec_intervention_applied(spec_id)
  ```

  **Step A3. Interrupt gate function.**

  ```python
  # backend/tasks/_interrupt.py

  async def interrupt_gate(
      session: AsyncSession,
      function_id: str,      # PipelineFunctionId value
      run_id: str,
      spec_id: str | None,
      worker_id: str,
      event_service: EventService,
      scope: str,            # "run" | "spec"
      input_files: list[dict],
  ) -> dict:
      """
      Returns: {"option_overrides": dict, "modified_file_refs": list}
      These are applied to the function call that follows the gate.
      """
      auto_config = await session.scalar(
          select(AutoConfig).where(AutoConfig.run_id == run_id)
      )
      # auto_config is a JSON column; read the function key
      if auto_config and auto_config.config.get(function_id, True):
          return {"option_overrides": {}, "modified_file_refs": []}

      # Manual mode — create InterruptPoint
      interrupt_id = deterministic_id(run_id, spec_id or "", function_id, "interrupt")
      ip = InterruptPoint(
          id=interrupt_id,
          run_id=run_id,
          spec_id=spec_id,
          function_name=function_id,
          scope=scope,
          status="waiting",
          input_files=input_files,
          option_overrides={},
          created_at=datetime.utcnow(),
      )
      session.add(ip)
      await session.commit()
      await event_service.publish_interrupt_created(ip)

      # Block until resolved
      while True:
          await asyncio.sleep(2)
          await check_control_flags(session, spec_id or run_id, run_id,
                                    worker_id, event_service)
          # extend lease every 60s (tracked by caller's heartbeat loop)
          ip = await session.get(InterruptPoint, interrupt_id)
          if ip.status == "resumed":
              await event_service.publish_interrupt_resolved(ip)
              return {
                  "option_overrides": ip.option_overrides or {},
                  "modified_file_refs": [f["artifact_ref"] for f in (ip.modified_files or [])],
              }
          if ip.status == "skipped":
              await event_service.publish_interrupt_resolved(ip)
              return {"option_overrides": {}, "modified_file_refs": [], "skipped": True}
  ```

  **Step A4. `run_counters_updated` throttle (`services/event_service.py` addition).**

  ```python
  _last_counter_publish: dict[str, float] = {}
  _counter_flush_tasks: dict[str, asyncio.Task] = {}

  async def publish_counters_throttled(self, run_id: str, counters: RunCounters):
      now = time.monotonic()
      last = _last_counter_publish.get(run_id, 0.0)
      if now - last >= 1.0:
          _last_counter_publish[run_id] = now
          await self.publish_run_counters_updated(run_id, counters)
      else:
          # Defer at most one pending flush
          if run_id not in _counter_flush_tasks or _counter_flush_tasks[run_id].done():
              async def _flush():
                  await asyncio.sleep(1.0)
                  _last_counter_publish[run_id] = time.monotonic()
                  await self.publish_run_counters_updated(run_id, counters)
              _counter_flush_tasks[run_id] = asyncio.create_task(_flush())
  ```

---

### Phase B — `phase1_task`

  **Step B1. `backend/tasks/phase1.py`.**

  ```
  Full implementation per worker_spec.md §6.

  Key integration points:
    - DockerRunner(cve_id=run_id, config=RunnerConfig())
    - Interrupt gates (4 gates): phase1_codeql_build, phase1_codeql_analyze,
      phase1_fact_enrichment, phase1_spec_generation
    - Phase1Pipeline.run() called inside runner
    - spec_id = deterministic_id(run_id, rule_id, file, line) — use SHA-256
      of the four fields, hex-encoded, first 32 chars
    - Publish: RunStarted → SpecEmitted/SpecFiltered per finding →
      RunCountersUpdated (throttled) → enqueue phase2_task per emitted spec
    - On codeql_build_failure: run.status=failed, publish RunFailed, stop container
  ```

  Implementation outline:

  ```python
  @celery_app.task(bind=True, name="tasks.phase1_task", queue="phase1",
                   acks_late=True, reject_on_worker_lost=True, max_retries=3)
  def phase1_task(self, run_id: str) -> dict:
      return asyncio.get_event_loop().run_until_complete(_phase1(run_id))

  async def _phase1(run_id: str) -> dict:
      async with get_session() as session:
          run = await session.get(Run, run_id)
          if run.status != RunStatus.queued:
              log.warning(f"[phase1] run {run_id} status={run.status}, skipping (idempotency)")
              return {"skipped": True}

          await session.execute(
              update(Run).where(Run.id == run_id)
              .values(status=RunStatus.running, started_at=datetime.utcnow())
          )
          await session.commit()
          await event_service.publish_run_status_changed(run_id, RunStatus.running)

      runner = DockerRunner(cve_id=run_id, config=RunnerConfig())
      runner.start()
      try:
          # Step 1: materialize source (artifact store → temp dir → docker cp)
          await _materialize_source(runner, run_id)

          # Step 2: build gate
          gate_result = await interrupt_gate(
              session, "phase1_codeql_build", run_id, None, worker_id, event_service,
              scope="run", input_files=[]
          )
          if gate_result.get("skipped"):
              await _fail_run(run_id, "phase1_build_skipped")
              return {}

          # Step 3: detect build + run codeql database create
          try:
              await _build_codeql_db(runner, run_id, run.build_command, run.codeql_build_mode)
          except BuildFailure as e:
              await _fail_run(run_id, f"codeql_build_failure: {e}")
              return {}

          # Step 4: analyze gate
          gate_result = await interrupt_gate(
              session, "phase1_codeql_analyze", run_id, None, worker_id, event_service,
              scope="run", input_files=[]
          )
          sarif = {}
          if gate_result.get("skipped"):
              sarif = {"runs": [{"results": []}]}   # zero findings
          else:
              sarif = await _run_codeql_analyze(runner, run_id, run.config)
              await artifact_service.put(f"runs/{run_id}/phase1/findings.sarif",
                                         json.dumps(sarif).encode())

          # Step 5: fact enrichment gate + per-finding processing
          gate_result = await interrupt_gate(
              session, "phase1_fact_enrichment", run_id, None, worker_id, event_service,
              scope="run", input_files=[]
          )
          findings = _extract_findings(sarif, run.config)
          if gate_result.get("skipped"):
              enriched = [(f, {}) for f in findings]
          else:
              enriched = [(f, FactEnricher().enrich(f)) for f in findings]

          # Step 6: spec generation gate
          gate_result = await interrupt_gate(
              session, "phase1_spec_generation", run_id, None, worker_id, event_service,
              scope="run", input_files=[]
          )

          emitted = 0
          for finding, enrichment in enriched:
              if _is_filtered(finding, run.config):
                  await _write_filtered_spec(session, run_id, finding)
                  continue
              if gate_result.get("skipped"):
                  spec = _make_stub_spec(run_id, finding)
              else:
                  spec = _generate_spec(run_id, finding, enrichment)
              await _write_spec(session, artifact_service, spec)
              await event_service.publish_spec_state_changed(spec.id)
              emitted += 1
              await event_service.publish_counters_throttled(run_id, ...)

          # Step 7: enqueue phase2 tasks
          for spec in emitted_specs:
              phase2_task.apply_async(args=[spec.id], queue="phase2")

          await event_service.publish_run_counters_updated(run_id, ...)

      except CooperativeExit:
          pass   # lease already dropped / status already set
      except Exception as e:
          await _fail_run(run_id, str(e))
          raise
      finally:
          runner.stop()
      return {}
  ```

  **Step B2. Failure modes.**

  ```
  codeql_build_failure  → run.status=failed, error=message, publish RunFailed
  codeql_query_error    → log WARN, continue with remaining queries
  no_findings           → run.status=completed, 0 specs, publish RunCompleted
  uncaught exception    → run.status=failed, error=traceback, publish RunFailed
  ```

  **Step B3. Idempotency guard.**

  Check `run.status != "queued"` at the top of the task and return early.
  Spec IDs are deterministic (SHA-256 of `run_id + rule_id + file + line`);
  `INSERT ... ON CONFLICT DO NOTHING` prevents duplicate spec rows.

---

### Phase C — `phase2_task`

  **Step C1. `backend/tasks/phase2.py`.**

  This is the most complex task. Implement in this sub-order:
    C1a. Lease acquisition + heartbeat loop
    C1b. State rehydration from last Turn row
    C1c. Algorithm 1 main loop
    C1d. Turn persistence (atomic)
    C1e. Intervention application

  **C1a — Lease and heartbeat:**

  ```python
  @celery_app.task(bind=True, name="tasks.phase2_task", queue="phase2",
                   acks_late=True, reject_on_worker_lost=True, max_retries=3,
                   soft_time_limit=18_000, time_limit=18_060)
  def phase2_task(self, spec_id: str, continue_from_intervention: bool = False) -> dict:
      return asyncio.get_event_loop().run_until_complete(
          _phase2(spec_id, continue_from_intervention)
      )

  async def _phase2(spec_id: str, continue_from_intervention: bool) -> dict:
      async with get_session() as session:
          acquired = await spec_service.acquire_phase2_lease(
              session, spec_id, worker_id
          )
          if not acquired:
              log.warning(f"[phase2] could not acquire lease for {spec_id}")
              return {"skipped": True}

          spec = await session.get(Spec, spec_id)
          run_id = spec.run_id

      # Heartbeat loop — runs as a background task
      stop_heartbeat = asyncio.Event()
      heartbeat_task = asyncio.create_task(
          _heartbeat_loop(spec_id, run_id, worker_id, stop_heartbeat)
      )

      runner = DockerRunner(cve_id=spec_id, config=RunnerConfig())
      runner.start()
      try:
          await _phase2_loop(runner, spec_id, run_id, continue_from_intervention)
      except CooperativeExit:
          pass
      except Exception as e:
          await _mark_spec_errored(spec_id, str(e))
          raise
      finally:
          stop_heartbeat.set()
          heartbeat_task.cancel()
          runner.stop()
      return {}

  async def _heartbeat_loop(spec_id, run_id, worker_id, stop: asyncio.Event):
      while not stop.is_set():
          await asyncio.sleep(30)
          async with get_session() as session:
              ok = await spec_service.extend_lease(session, spec_id, worker_id)
              if not ok:
                  log.error(f"[phase2] lease stolen for {spec_id}, stopping")
                  stop.set()
                  return
          await event_service.publish_worker_heartbeat(run_id, worker_id, "busy", spec_id)
  ```

  **C1b — State rehydration:**

  ```python
  async def _rehydrate(session, spec_id) -> RehydratedState:
      spec = await session.get(Spec, spec_id)
      last_turn = await session.scalar(
          select(Turn).where(Turn.spec_id == spec_id)
          .order_by(Turn.turn_number.desc()).limit(1)
      )
      return RehydratedState(
          current_turn=spec.current_turn,
          turn_count_total=spec.turn_count_total,
          refine_count=spec.refine_count,
          phase2_status=spec.phase2_status,
          last_turn_kind=last_turn.kind if last_turn else None,
      )
  ```

  **C1c — Algorithm 1 main loop:**

  ```python
  async def _phase2_loop(runner, spec_id, run_id, continue_from_intervention):
      async with get_session() as session:
          state = await _rehydrate(session, spec_id)
          spec = await session.get(Spec, spec_id)
          run = await session.get(Run, run_id)
          cfg = run.config  # RunConfig

      T_explore = cfg.phase2_t_explore   # default 8
      T_author  = cfg.phase2_t_author    # default 12
      T_max     = cfg.phase2_t_max       # default 60
      R_max     = cfg.phase2_r_max       # default 15

      while state.current_turn < T_max and state.refine_count < R_max:
          async with get_session() as session:
              await check_control_flags(session, spec_id, run_id, worker_id, event_service)

          if state.current_turn < T_explore:
              await _run_explore_turn(runner, spec_id, run_id, state, event_service)

          elif state.current_turn < T_author:
              await _run_author_turns(runner, spec_id, run_id, state, cfg, event_service)

          else:
              terminal = await _run_refine_turn(runner, spec_id, run_id, state, cfg, event_service)
              if terminal:
                  return

          state.current_turn += 1

      # Budget exhausted
      await _set_spec_terminal(spec_id, "inconclusive", "inconclusive", event_service)
  ```

  Interrupt gates inside each sub-turn:

  ```python
  async def _run_explore_turn(runner, spec_id, run_id, state, event_service):
      gate = await interrupt_gate(
          session, "phase2_source_exploration", run_id, spec_id, worker_id,
          event_service, scope="spec",
          input_files=await _collect_input_files(spec_id, "source_exploration"),
      )
      if gate.get("skipped"):
          result = {"call_chain": [], "variables": []}
      else:
          pipeline = Phase2Pipeline(...)
          result = await asyncio.get_event_loop().run_in_executor(
              None, pipeline.source_explorer.run
          )
      await _persist_turn(spec_id, kind="explore", result=result, state=state)
      await event_service.publish_turn_appended(spec_id, state.current_turn)

  async def _run_author_turns(runner, spec_id, run_id, state, cfg, event_service):
      # Driver synthesis
      gate = await interrupt_gate(
          session, "phase2_driver_synthesis", run_id, spec_id, worker_id,
          event_service, scope="spec",
          input_files=await _collect_input_files(spec_id, "driver_synthesis"),
      )
      driver = await _synthesize_or_load(gate, "driver", spec_id, runner, ...)
      await _persist_turn(spec_id, kind="author", result=driver, state=state)

      # Stub synthesis
      gate = await interrupt_gate(
          session, "phase2_stub_synthesis", run_id, spec_id, worker_id,
          event_service, scope="spec",
          input_files=await _collect_input_files(spec_id, "stub_synthesis"),
      )
      stubs = await _synthesize_or_load(gate, "stubs", spec_id, runner, ...)
      await _persist_turn(spec_id, kind="author", result=stubs, state=state)

  async def _run_refine_turn(runner, spec_id, run_id, state, cfg, event_service) -> bool:
      """Returns True if a terminal state was reached."""
      gate = await interrupt_gate(
          session, "phase2_klee_execution", run_id, spec_id, worker_id,
          event_service, scope="spec",
          input_files=await _collect_input_files(spec_id, "klee_execution"),
      )
      if gate.get("skipped"):
          klee_result = {"outcome": "not_reached", "ktest_paths": []}
      else:
          klee_result = runner.run_klee(spec_id)

      await _persist_turn(spec_id, kind="klee_run", result=klee_result, state=state)
      await event_service.publish_turn_appended(spec_id, state.current_turn)

      if klee_result["outcome"] == "bug_triggered":
          await _write_witness_artifacts(spec_id, klee_result)
          await _set_spec_terminal(spec_id, "bug_triggered", "bug_triggered", event_service)
          if cfg.phase3_enabled:
              phase3_task.apply_async(args=[spec_id], queue="phase3")
          return True

      if state.refine_count < R_max:
          gate = await interrupt_gate(
              session, "phase2_harness_refinement", run_id, spec_id, worker_id,
              event_service, scope="spec",
              input_files=await _collect_input_files(spec_id, "harness_refinement"),
          )
          if gate.get("skipped"):
              await _set_spec_terminal(spec_id, "inconclusive", "inconclusive", event_service)
              return True
          refined = await _refine_harness(runner, spec_id, klee_result)
          await _persist_turn(spec_id, kind="refinement", result=refined, state=state)
          state.refine_count += 1
      else:
          await _set_spec_terminal(spec_id, "likely_false_positive",
                                   "likely_false_positive", event_service)
          return True
      return False
  ```

  **C1d — Turn persistence (atomic):**

  ```python
  async def _persist_turn(spec_id, kind, result, state):
      turn_id = deterministic_id(spec_id, str(state.current_turn), "turn")
      payload_ref = await artifact_service.put(
          f"runs/{...}/phase2/{spec_id}/turns/{state.current_turn}.json",
          json.dumps(result).encode(),
      )
      turn = Turn(
          id=turn_id,
          spec_id=spec_id,
          turn_number=state.current_turn,
          kind=kind,
          started_at=state.turn_started_at,
          ended_at=datetime.utcnow(),
          duration_ms=int((datetime.utcnow() - state.turn_started_at).total_seconds() * 1000),
          payload_ref=payload_ref,
          summary=_summarize(kind, result),
          tokens_consumed=result.get("tokens"),
          klee_seconds=result.get("klee_seconds"),
      )
      async with get_session() as session:
          ok = await spec_service.persist_turn(
              session, spec_id, worker_id, turn,
              spec_updates={"current_turn": state.current_turn,
                            "turn_count_total": state.turn_count_total + 1,
                            "refine_count": state.refine_count,
                            "last_event_at": datetime.utcnow()},
          )
      if not ok:
          raise CooperativeExit("lease_lost")
  ```

  **C1e — Intervention application:**

  See `_control.py:apply_intervention`. Implementation per `worker_spec.md §8`:

  ```python
  async def apply_intervention(session, spec_id, worker_id, payload, event_service):
      t = payload["type"]
      if t == "edit_harness":
          await _apply_edit_harness(session, spec_id, worker_id, payload)
      elif t == "force_outcome":
          await _apply_force_outcome(session, spec_id, payload, event_service)
      elif t == "edit_spec":
          await _apply_edit_spec(session, spec_id, payload)
  ```

  - `edit_harness`: write new draft version to artifact store; update draft version counter; append Turn(kind="intervention").
  - `force_outcome=mark_inconclusive/mark_likely_fp`: set terminal status; do NOT enqueue Phase 3.
  - `force_outcome=skip_to_phase3`: store .ktest as witness; set bug_triggered; enqueue phase3_task.
  - `edit_spec`: archive Phase 2 artifacts (rename prefix); reset counters to 0; replace spec fields; restart loop from turn 0.

  **Step C2. LLM error handling in phase2_task.**

  ```python
  async def _llm_call_with_retry(fn, *args, **kwargs):
      for attempt in range(5):
          try:
              return await fn(*args, **kwargs)
          except LLMAPIError as e:
              if e.unrecoverable:
                  raise
              wait = min(2 ** attempt * 2, 60)
              log.warning(f"LLM API error attempt {attempt+1}/5, retrying in {wait}s: {e}")
              await asyncio.sleep(wait)
      raise LLMExhausted("LLM retries exhausted after 5 attempts")
  ```

---

### Phase D — `phase3_task`

  **Step D1. `backend/tasks/phase3.py`.**

  ```python
  @celery_app.task(bind=True, name="tasks.phase3_task", queue="phase3",
                   acks_late=True, reject_on_worker_lost=True, max_retries=3)
  def phase3_task(self, spec_id: str) -> dict:
      return asyncio.get_event_loop().run_until_complete(_phase3(spec_id))

  async def _phase3(spec_id: str) -> dict:
      async with get_session() as session:
          acquired = await spec_service.acquire_phase3_lease(session, spec_id, worker_id)
          if not acquired:
              return {"skipped": True}
          spec = await session.get(Spec, spec_id)
          run_id = spec.run_id
          await session.execute(
              update(Spec).where(Spec.id == spec_id)
              .values(phase3_status="running")
          )
          await session.commit()
          await event_service.publish_spec_state_changed(spec_id)

      runner = DockerRunner(cve_id=spec_id, config=RunnerConfig())
      runner.start()
      try:
          await _phase3_steps(runner, spec_id, run_id)
      except CooperativeExit:
          pass
      except Exception as e:
          await _set_spec_phase3_errored(spec_id, str(e))
          raise
      finally:
          runner.stop()
          async with get_session() as session:
              await spec_service.drop_phase3_lease(session, spec_id, worker_id)
      return {}

  async def _phase3_steps(runner, spec_id, run_id):
      # Load Phase 2 artifacts
      driver_c   = await _load_artifact(f"runs/{run_id}/phase2/{spec_id}/drafts/driver.v*.c")
      slice_c    = await _load_artifact(f"runs/{run_id}/phase2/{spec_id}/drafts/slice.v*.c")
      witness_kt = await _load_witness_ktest(spec_id)

      # ASan build gate
      gate = await interrupt_gate(
          session, "phase3_asan_build", run_id, spec_id, worker_id,
          event_service, scope="spec", input_files=[],
      )
      if gate.get("skipped"):
          await _set_spec_phase3_errored(spec_id, "asan_build_skipped")
          return

      try:
          asan_archive = runner.build_asan_archive(project_dir, build_command)
      except Exception as e:
          await _set_spec_phase3_errored(spec_id, f"asan_build_failure: {e}")
          return

      # Build replay driver
      replay_c = ReplayDriverGenerator().generate(driver_c, witness_kt)
      success, diag = runner.compile_harness(replay_c, slice_c, include_paths)
      if not success:
          await _set_spec_phase3_errored(spec_id, f"replay_compile_failure: {diag}")
          return
      await artifact_service.put(
          f"runs/{run_id}/phase3/{spec_id}/replay_driver.c", replay_c.encode()
      )

      # Replay execution gate
      gate = await interrupt_gate(
          session, "phase3_replay_execution", run_id, spec_id, worker_id,
          event_service, scope="spec", input_files=[],
      )
      if gate.get("skipped"):
          verdict_value = "rejected"
          asan_output = ""
      else:
          result = runner.run_asan_replay(replay_c, asan_archive, include_paths)
          asan_output = result["asan_output"]
          verdict_value = ResultClassifier().classify(asan_output)

      # Write artifacts and Verdict
      await artifact_service.put(
          f"runs/{run_id}/phase3/{spec_id}/asan_report.txt", asan_output.encode()
      )
      verdict = _build_verdict(spec_id, verdict_value, asan_output)
      await artifact_service.put(
          f"runs/{run_id}/phase3/{spec_id}/verified_bug.json",
          verdict.verified_bug_json.encode(),
      )
      async with get_session() as session:
          session.add(verdict)
          await session.execute(
              update(Spec).where(Spec.id == spec_id)
              .values(phase3_status=verdict_value, phase3_verdict=verdict_value)
          )
          await _update_run_counters(session, run_id, verdict_value)
          await session.commit()

      await event_service.publish_spec_state_changed(spec_id)
      await event_service.publish_counters_throttled(run_id, ...)
      await _check_run_completion(run_id)
  ```

  **Step D2. Run completion check.**

  ```python
  async def _check_run_completion(run_id: str):
      """If all specs reached terminal phase3_status, complete the run."""
      async with get_session() as session:
          total = await session.scalar(
              select(func.count(Spec.id)).where(Spec.run_id == run_id)
          )
          terminal = await session.scalar(
              select(func.count(Spec.id)).where(
                  Spec.run_id == run_id,
                  Spec.phase3_status.in_(["confirmed", "rejected", "errored", "not_eligible"]),
              )
          )
          # Also count specs with terminal phase2 status that never enter phase3
          p2_terminal_no_p3 = await session.scalar(
              select(func.count(Spec.id)).where(
                  Spec.run_id == run_id,
                  Spec.phase2_status.in_(["inconclusive", "likely_false_positive",
                                          "errored"]),
              )
          )
          if terminal + p2_terminal_no_p3 >= total:
              await session.execute(
                  update(Run).where(Run.id == run_id, Run.status == RunStatus.running)
                  .values(status=RunStatus.completed, completed_at=datetime.utcnow())
              )
              await session.commit()
              await event_service.publish_run_status_changed(run_id, RunStatus.completed)
  ```

---

### Phase E — Logging and Container Streaming

  **Step E1. Log publication from container output.**

  `DockerRunner.exec()` returns full `stderr`/`stdout`. For long steps, add a
  streaming variant that yields lines from `docker logs --follow`:

  ```python
  async def _stream_and_log(runner, container_id, source, run_id, spec_id):
      proc = await asyncio.create_subprocess_exec(
          "docker", "logs", "--follow", container_id,
          stdout=asyncio.subprocess.PIPE,
          stderr=asyncio.subprocess.STDOUT,
      )
      async for raw_line in proc.stdout:
          line = raw_line.decode(errors="replace").rstrip()
          log_line = LogLine(
              timestamp=datetime.utcnow(),
              level="info",
              source=source,
              run_id=run_id,
              spec_id=spec_id,
              worker_id=worker_id,
              message=line,
              fields={},
          )
          async with get_session() as session:
              session.add(log_line)
              await session.commit()
          await event_service.publish_log_line(run_id, spec_id, log_line)
  ```

  Call `_stream_and_log` as a background task during KLEE runs and ASan builds.

  **Step E2. Log sources used.**

  | Source  | Where emitted                                          |
  | ------- | ------------------------------------------------------ |
  | `phase1`| Phase 1 stage messages                                 |
  | `phase2`| Phase 2 orchestrator messages                          |
  | `phase3`| Phase 3 messages                                       |
  | `llm`   | LLM API calls (sanitized: model, tokens, latency only) |
  | `klee`  | KLEE subprocess output                                 |
  | `clang` | Compile diagnostics                                    |
  | `asan`  | ASan output                                            |
  | `celery`| Task lifecycle (picked up, completed, failed)          |

---

### Phase F — Tests

  **Step F1. `tests/test_tasks.py`.**

  All tests mock DockerRunner and sailor/ pipeline calls. Use pytest-asyncio.

  ```
  test_phase1_idempotency         — re-running with status=running returns early
  test_phase1_build_failure       — docker runner raises BuildFailure → run.status=failed
  test_phase1_no_findings         — 0 specs → run.status=completed
  test_phase1_spec_generation     — N findings → N Spec rows with deterministic IDs

  test_phase2_lease_acquisition   — only one worker wins lease
  test_phase2_lease_stolen        — extend_lease returns False → CooperativeExit
  test_phase2_pause               — run.status=paused → spec.phase2_status=queued
  test_phase2_cancel              — run.status=cancelled → spec.phase2_status=errored
  test_phase2_intervention_edit   — intervention_pending=[edit_harness payload]
                                    → new draft written, Turn appended
  test_phase2_intervention_force  — force_outcome=mark_inconclusive → terminal
  test_phase2_intervention_spec   — edit_spec → spec reset, loop restarts
  test_phase2_bug_triggered       — KLEE returns bug_triggered → phase3_task enqueued
  test_phase2_budget_exhausted    — current_turn=T_max → inconclusive
  test_phase2_llm_retry           — LLMAPIError raised 4 times → succeeds on 5th
  test_phase2_llm_exhausted       — LLMAPIError raised 5 times → spec errored
  test_phase2_gemini_429_backoff  — 429 counted as LLM API error, same retry path

  test_phase3_confirmed           — ASan crash in project source → confirmed
  test_phase3_rejected_no_crash   — clean exit → rejected
  test_phase3_rejected_harness    — crash in harness only → rejected
  test_phase3_asan_build_failure  → errored
  test_phase3_replay_compile_fail → errored
  test_run_completion             — all specs terminal → run.status=completed

  test_interrupt_gate_auto        — auto_config[fn]=True → gate passes immediately
  test_interrupt_gate_manual_resume — status=waiting → resumed → gate returns override
  test_interrupt_gate_manual_skip   — status=skipped → gate returns {skipped: True}
  test_interrupt_gate_cancel_while_waiting — run cancelled while gate is blocking
                                             → CooperativeExit raised
  ```

---

### Phase G — Verification

  After completing each phase (A–F):

  ```
  → pytest tests/test_tasks.py -v
  → mypy backend/tasks/ backend/services/ --strict
  ```

  After all phases:

  ```
  docker compose up -d --build worker
  ```

  Verify end-to-end:

  ```
  # Submit a run via the API (use a tiny C project)
  curl -X POST http://localhost:8000/api/runs \
    -F "name=test" -F "project_zip=@tests/e2e_workspace/cwe_121/target.zip" \
    -H "Authorization: Bearer <token>"

  # Watch run status
  curl http://localhost:8000/api/runs/<run_id>

  # Watch SSE stream (events must appear; not silence)
  curl -N "http://localhost:8000/api/events?topics=runs.<run_id>&token=<jwt>"

  # Verify interrupt functionality (frontend side):
  #   1. PATCH /api/runs/<run_id>/auto-config {"phase2_klee_execution": false}
  #   2. Wait for interrupt_created SSE event
  #   3. POST /api/runs/<run_id>/interrupts/<id>/skip
  #   4. Verify interrupt_resolved SSE event arrives
  #   5. Verify spec continues processing (turn count increments)
  #   All state changes must be confirmed in the DB — not just via SSE.
  ```

---

## Session 11 Trigger

```
Read CLAUDE.md and execute Session 11.
```

---

## CONSTRAINTS (non-negotiable)

1. `sailor/` pipeline code has NO knowledge of interrupt_points.
   Interrupt gate logic lives ONLY in `backend/tasks/`.
2. All phase execution runs inside Docker via DockerRunner.
   `runner.stop()` MUST be in a `finally` block.
3. Turns are append-only. `INSERT ... ON CONFLICT DO NOTHING` only.
4. `intervention_pending` is a list. Process in submission order.
5. LLM retries (up to 5) are handled inside the task.
   Gemini 429 follows the same exponential backoff path.
6. `run_counters_updated` SSE is throttled to ≤ 1/second per run.
7. Artifact paths are never returned raw; always presigned 302 redirects.
8. Auto/Manual mode is checked only inside tasks, never in `sailor/`.
9. All interrupt gate checks must also call `check_control_flags()` in
   their polling loop — cancellation must work even while a gate blocks.
10. `DockerRunner(cve_id=run_id, ...)` for Phase 1;
    `DockerRunner(cve_id=spec_id, ...)` for Phase 2/3.
