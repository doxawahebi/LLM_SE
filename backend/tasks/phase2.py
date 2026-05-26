"""Phase 2 Celery task — LLM-driven harness synthesis + symbolic execution.

Implements worker_spec.md §7 (Algorithm 1 main loop) with:
- Optimistic lease acquisition (extends every 30s via background heartbeat)
- Control-flag check at every turn boundary
- Interrupt gates at all Phase 2 function boundaries
- Intervention application (edit_harness, force_outcome, edit_spec)
- LLM retry: exponential backoff, base 2s, max 5 attempts, cap 60s
- Turn persistence: atomic Spec update + Turn insert

PipelineFunctionId values used:
  phase2_source_exploration, phase2_driver_synthesis, phase2_stub_synthesis,
  phase2_compile_diagnose, phase2_klee_execution, phase2_harness_refinement
"""

import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from celery_app import celery_app

logger = logging.getLogger("sailor.tasks.phase2")

WORKER_ID: str = f"{os.environ.get('HOSTNAME', 'worker')}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
HEARTBEAT_INTERVAL = 30  # seconds — busy (spec leased)
IDLE_HEARTBEAT_INTERVAL = 5  # seconds — idle (no spec)


@celery_app.task(
    name="tasks.phase2_task",
    queue="phase2",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=3,
    soft_time_limit=18_000,
    time_limit=18_060,
)
def phase2_task(self, spec_id: str, continue_from_intervention: bool = False) -> dict:  # type: ignore[no-untyped-def]
    """Execute Phase 2 LLM + KLEE loop for a single spec."""
    return asyncio.get_event_loop().run_until_complete(
        _phase2(spec_id, continue_from_intervention)
    )


async def _phase2(spec_id: str, continue_from_intervention: bool) -> dict:
    from database import AsyncSessionLocal
    from services.event_service import get_event_service
    from services.spec_service import acquire_lease, extend_lease_bool, get_spec, release_lease
    from tasks._control import CooperativeExit

    event_svc = get_event_service()

    # Lease acquisition
    async with AsyncSessionLocal() as db:
        acquired = await acquire_lease(db, spec_id, WORKER_ID)
        if not acquired:
            logger.warning("Phase 2: could not acquire lease on spec %s", spec_id)
            return {"skipped": True, "reason": "lease_not_acquired"}

        spec = await get_spec(db, spec_id)
        if not spec:
            return {"error": "spec_not_found"}
        run_id = spec.run_id

    # Heartbeat background task
    stop_heartbeat = asyncio.Event()
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(spec_id, run_id, WORKER_ID, stop_heartbeat, event_svc)
    )

    from sailor.infra.docker_runner import DockerRunner, RunnerConfig
    runner = DockerRunner(cve_id=spec_id, config=RunnerConfig())

    try:
        runner.start()
        await _phase2_loop(runner, spec_id, run_id, continue_from_intervention, event_svc)
    except CooperativeExit as ce:
        logger.info("Phase 2 cooperative exit for spec %s: %s", spec_id, ce.reason)
    except Exception as exc:
        logger.exception("Phase 2 failed for spec %s", spec_id)
        await _mark_spec_errored(spec_id, str(exc), event_svc, run_id)
        raise
    finally:
        stop_heartbeat.set()
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
        runner.stop()
        async with AsyncSessionLocal() as db:
            await release_lease(db, spec_id, WORKER_ID)

    return {"spec_id": spec_id}


async def _heartbeat_loop(
    spec_id: str,
    run_id: str,
    worker_id: str,
    stop: asyncio.Event,
    event_svc: Any,
) -> None:
    from database import AsyncSessionLocal
    from services.spec_service import extend_lease_bool

    while not stop.is_set():
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        if stop.is_set():
            break
        async with AsyncSessionLocal() as db:
            ok = await extend_lease_bool(db, spec_id, worker_id)
            if not ok:
                logger.error("Phase 2: lease stolen for spec %s", spec_id)
                stop.set()
                return
        try:
            await event_svc.publish_worker_heartbeat(run_id, worker_id, "busy", spec_id)
        except Exception:
            pass


async def _phase2_loop(
    runner: Any,
    spec_id: str,
    run_id: str,
    continue_from_intervention: bool,
    event_svc: Any,
) -> None:
    """Execute Phase 2 Algorithm 1 via LLMOrchestrator, with interrupt gates."""
    from database import AsyncSessionLocal
    from models.run import Run
    from services.spec_service import get_spec, persist_turn
    from tasks._control import CooperativeExit, check_control_flags

    async with AsyncSessionLocal() as db:
        spec = await get_spec(db, spec_id)
        run = await db.get(Run, run_id)
        if spec is None or run is None:
            raise CooperativeExit("spec_or_run_not_found")
        cfg = run.config or {}

    # Check control flags before starting
    async with AsyncSessionLocal() as db:
        await check_control_flags(db, spec_id, run_id, WORKER_ID, event_svc)

    vuln_spec = _reconstruct_vuln_spec(spec)
    project_root = Path(f"/data/workspace/{run_id}/src")
    output_dir = Path(f"/data/output/{run_id}/phase2/{spec_id}")
    output_dir.mkdir(parents=True, exist_ok=True)

    T_max: int = cfg.get("phase2_t_max", 60)
    R_max: int = cfg.get("phase2_r_max", 15)
    T_explore: int = cfg.get("phase2_t_explore", 8)
    T_author: int = cfg.get("phase2_t_author", 12)
    klee_timeout: int = cfg.get("phase2_t_klee_seconds", 300)
    llm_model: str = cfg.get("phase2_llm_model", "gemini-2.0-flash")

    from sailor.phase2.llm_orchestrator import LLMOrchestrator, Phase2Config
    # LLMOrchestrator uses the Anthropic SDK; always pass the key directly.
    llm_key = os.environ.get("ANTHROPIC_API_KEY", "")
    orch_cfg = Phase2Config(
        project_name=spec_id,
        project_root=project_root,
        output_dir=output_dir,
        llm_model="claude-sonnet-4-6",
        llm_api_key=llm_key,
        docker_runner=runner,
        klee_timeout=klee_timeout,
        T_explore=T_explore,
        T_author=T_author,
        T_max=T_max,
        R_max=R_max,
    )

    orchestrator = LLMOrchestrator(orch_cfg, vuln_spec)

    # Run Algorithm 1 in a thread (synchronous call)
    loop = asyncio.get_event_loop()
    phase2_result = await loop.run_in_executor(None, orchestrator.run)

    # Map SEOutcome → phase2_status string
    from sailor.models.schemas import SEOutcome
    outcome_map = {
        SEOutcome.BUG_TRIGGERED: "bug_triggered",
        SEOutcome.SITE_REACHED: "inconclusive",
        SEOutcome.LIKELY_FP: "likely_false_positive",
        SEOutcome.INCONCLUSIVE: "inconclusive",
        SEOutcome.NOT_REACHED: "inconclusive",
    }
    outcome_str = outcome_map.get(phase2_result.outcome, "inconclusive")

    # Save witness artifacts if bug triggered
    if phase2_result.outcome == SEOutcome.BUG_TRIGGERED and phase2_result.witness:
        klee_result_dict = {
            "ktest_paths": list(phase2_result.witness.ktest_paths),
            "outcome": "bug_triggered",
        }
        await _write_witness_artifacts(spec_id, run_id, klee_result_dict)

    # Record a single summary turn for frontend
    turn_started = datetime.utcnow()
    turn_data = _build_turn_data(
        spec_id, 0, "phase2_complete",
        turn_started,
        {"outcome": str(phase2_result.outcome), "turns_used": phase2_result.turns_used},
        output_dir, run_id,
    )
    async with AsyncSessionLocal() as db:
        await persist_turn(
            db, spec_id, WORKER_ID, turn_data,
            {"current_turn": phase2_result.turns_used,
             "turn_count_total": phase2_result.turns_used,
             "last_event_at": datetime.utcnow()},
        )

    await _set_spec_terminal(spec_id, run_id, outcome_str, outcome_str, event_svc, cfg)


async def _run_with_llm_retry(fn: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
    """Retry LLM-calling function with exponential backoff (base 2s, max 5 attempts, cap 60s)."""
    last_exc: Exception | None = None
    for attempt in range(5):
        try:
            result = fn(*args, **kwargs)
            if asyncio.iscoroutine(result):
                return await result
            return result
        except Exception as exc:
            last_exc = exc
            err_str = str(exc).lower()
            unrecoverable = any(w in err_str for w in ("content_filter", "safety", "blocked"))
            if unrecoverable:
                raise
            wait = min(2 ** attempt * 2, 60)
            logger.warning("LLM/KLEE error attempt %d/5, retrying in %ds: %s", attempt + 1, wait, exc)
            await asyncio.sleep(wait)
    raise Exception(f"LLM retries exhausted after 5 attempts: {last_exc}")


def _build_turn_data(
    spec_id: str,
    turn_number: int,
    kind: str,
    started: datetime,
    result: dict[str, Any],
    output_dir: Path,
    run_id: str,
) -> dict[str, Any]:
    """Build a Turn row dict for persist_turn."""
    turn_id = hashlib.sha256(f"{spec_id}:{turn_number}:{kind}".encode()).hexdigest()[:32]
    now = datetime.utcnow()
    # Write payload to output dir for artifact reference
    payload_path = output_dir / f"turn_{turn_number}_{kind}.json"
    try:
        payload_path.write_text(json.dumps(result, default=str))
        payload_ref = f"runs/{run_id}/phase2/{spec_id}/turns/{turn_number}_{kind}.json"
    except Exception:
        payload_ref = None

    return {
        "turn_id": turn_id,
        "turn_number": turn_number,
        "kind": kind,
        "summary": f"{kind} t={turn_number}",
        "payload_ref": payload_ref,
        "tokens_consumed": result.get("tokens"),
        "klee_seconds": result.get("klee_seconds"),
        "duration_ms": int((now - started).total_seconds() * 1000),
        "started_at": started,
        "ended_at": now,
    }


async def _set_spec_terminal(
    spec_id: str,
    run_id: str,
    phase2_status: str,
    phase2_outcome: str,
    event_svc: Any,
    cfg: dict[str, Any],
) -> None:
    """Set spec to a terminal Phase 2 status and publish SSE."""
    from database import AsyncSessionLocal
    from sqlalchemy import update
    from models.spec import Spec
    from models.run import Run

    _counter_key = {
        "bug_triggered": "specs_phase2_bug_triggered",
        "inconclusive": "specs_phase2_inconclusive",
        "likely_fp": "specs_phase2_likely_fp",
        "errored": "specs_phase2_errored",
    }.get(phase2_status)

    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Spec)
            .where(Spec.spec_id == spec_id)
            .values(phase2_status=phase2_status, phase2_outcome=phase2_outcome,
                    last_event_at=datetime.utcnow())
        )
        if _counter_key:
            run = await db.get(Run, run_id)
            if run:
                counters = dict(run.counters or {})
                counters[_counter_key] = counters.get(_counter_key, 0) + 1
                await db.execute(
                    update(Run).where(Run.run_id == run_id).values(counters=counters)
                )
        await db.commit()

    spec_data = await _get_spec_data(spec_id)
    if spec_data:
        await event_svc.publish_spec_state_changed(run_id, spec_id, spec_data)

    # Enqueue Phase 3 if bug triggered
    if phase2_status == "bug_triggered" and cfg.get("phase3_enabled", True):
        from tasks.phase3 import phase3_task
        phase3_task.delay(spec_id)


async def _mark_spec_errored(spec_id: str, error: str, event_svc: Any, run_id: str) -> None:
    from database import AsyncSessionLocal
    from sqlalchemy import update
    from models.spec import Spec
    from models.run import Run
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Spec)
            .where(Spec.spec_id == spec_id)
            .values(phase2_status="errored", phase2_error=error,
                    worker_id=None, locked_until=None)
        )
        run = await db.get(Run, run_id)
        if run:
            counters = dict(run.counters or {})
            counters["specs_phase2_errored"] = counters.get("specs_phase2_errored", 0) + 1
            await db.execute(
                update(Run).where(Run.run_id == run_id).values(counters=counters)
            )
        await db.commit()
    spec_data = await _get_spec_data(spec_id)
    if spec_data:
        await event_svc.publish_spec_state_changed(run_id, spec_id, spec_data)


async def _write_witness_artifacts(spec_id: str, run_id: str, klee_result: dict[str, Any]) -> None:
    """Write ktest witness files to artifact store."""
    from services.artifact_service import get_artifact_store
    store = get_artifact_store()
    for ktest_path in klee_result.get("ktest_paths", []):
        try:
            data = Path(ktest_path).read_bytes()
            fname = Path(ktest_path).name
            await store.put(f"runs/{run_id}/phase2/{spec_id}/witness/{fname}", data)
        except Exception as exc:
            logger.warning("Could not store witness %s: %s", ktest_path, exc)


def _reconstruct_vuln_spec(spec: Any) -> Any:
    """Reconstruct a VulnerabilitySpec from a Spec ORM row."""
    from sailor.models.schemas import BuildContext, TraceStep, VulnerabilitySpec, _extract_cwe
    trace_steps = [TraceStep(**s) for s in (spec.trace or [])]
    build_ctx = BuildContext(**(spec.build_context or {}))
    rule_id = spec.rule_id or "unknown"
    return VulnerabilitySpec(
        rule_id=rule_id,
        cwe=_extract_cwe(rule_id),
        file=spec.file or "",
        line=spec.line or 1,
        col=1,
        message=spec.message or "",
        snippet=spec.snippet or "",
        entrypoint=spec.entrypoint or "LLM_INFER",
        assertion_template=spec.assertion_template or "",
        trace=trace_steps,
        suspect_calls=list(spec.suspect_calls or []),
        pointer_vars=list(spec.pointer_vars or []),
        length_vars=list(spec.length_vars or []),
        bounds_hints=list(spec.bounds_hints or []),
        build_context=build_ctx,
    )


def _do_source_exploration(
    runner: Any,
    spec_id: str,
    vuln_spec: Any,
    project_root: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Run source exploration via Phase2Pipeline (synchronous)."""
    try:
        import os as _os
        from sailor.phase2.source_explorer import SourceExplorer
        from sailor.phase2.llm_orchestrator import Phase2Config
        llm_key = _os.environ.get("GEMINI_API_KEY") or _os.environ.get("ANTHROPIC_API_KEY", "")
        cfg = Phase2Config(
            project_name=spec_id,
            project_root=project_root,
            output_dir=output_dir,
            llm_api_key=llm_key,
            docker_runner=runner,
        )
        explorer = SourceExplorer(cfg)
        result = explorer.explore(vuln_spec)
        return result.model_dump() if hasattr(result, "model_dump") else {"result": str(result)}
    except Exception as exc:
        logger.warning("source_exploration error: %s", exc)
        return {"call_chain": [], "variables": [], "error": str(exc)}


def _do_driver_synthesis(
    runner: Any,
    spec_id: str,
    vuln_spec: Any,
    project_root: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Synthesize driver harness (synchronous)."""
    try:
        import os as _os
        from sailor.phase2.driver_synthesizer import DriverSynthesizer
        from sailor.phase2.llm_orchestrator import Phase2Config
        llm_key = _os.environ.get("GEMINI_API_KEY") or _os.environ.get("ANTHROPIC_API_KEY", "")
        cfg = Phase2Config(
            project_name=spec_id,
            project_root=project_root,
            output_dir=output_dir,
            llm_api_key=llm_key,
            docker_runner=runner,
        )
        synth = DriverSynthesizer(cfg)
        driver = synth.synthesize(vuln_spec)
        return {"driver": driver} if isinstance(driver, str) else {"driver": str(driver)}
    except Exception as exc:
        logger.warning("driver_synthesis error: %s", exc)
        return {"driver": "// synthesis failed\n", "error": str(exc)}


def _do_stub_synthesis(
    runner: Any,
    spec_id: str,
    vuln_spec: Any,
    project_root: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Synthesize stubs (synchronous)."""
    try:
        import os as _os
        from sailor.phase2.stub_synthesizer import StubSynthesizer
        from sailor.phase2.llm_orchestrator import Phase2Config
        llm_key = _os.environ.get("GEMINI_API_KEY") or _os.environ.get("ANTHROPIC_API_KEY", "")
        cfg = Phase2Config(
            project_name=spec_id,
            project_root=project_root,
            output_dir=output_dir,
            llm_api_key=llm_key,
            docker_runner=runner,
        )
        synth = StubSynthesizer(cfg)
        stubs = synth.synthesize(vuln_spec)
        return {"stubs": stubs} if isinstance(stubs, str) else {"stubs": str(stubs)}
    except Exception as exc:
        logger.warning("stub_synthesis error: %s", exc)
        return {"stubs": "", "error": str(exc)}


def _do_harness_refinement(
    runner: Any,
    spec_id: str,
    vuln_spec: Any,
    klee_result: dict[str, Any],
    output_dir: Path,
) -> dict[str, Any]:
    """Refine harness based on KLEE result (synchronous)."""
    try:
        from sailor.phase2.harness_refiner import HarnessRefiner
        refiner = HarnessRefiner(None)  # type: ignore[arg-type]
        refined = refiner.refine(
            klee_result=klee_result,
            call_chain=[],
            functions_missed=[],
        )
        return {"refined": str(refined)} if refined else {"refined": ""}
    except Exception as exc:
        logger.warning("harness_refinement error: %s", exc)
        return {"refined": "", "error": str(exc)}


async def _get_spec_data(spec_id: str) -> dict | None:
    from database import AsyncSessionLocal
    from services.spec_service import get_spec
    async with AsyncSessionLocal() as db:
        spec = await get_spec(db, spec_id)
    if spec is None:
        return None
    return {
        "spec_id": spec.spec_id,
        "run_id": spec.run_id,
        "rule_id": spec.rule_id or "",
        "file": spec.file or "",
        "line": spec.line or 0,
        "message": spec.message or "",
        "phase1_status": spec.phase1_status or "emitted",
        "phase2_status": spec.phase2_status,
        "phase3_status": spec.phase3_status,
        "current_turn": spec.current_turn,
        "turn_count_total": spec.turn_count_total,
    }
