"""Phase 3 Celery task — ASan concrete validation; produces Verdicts.

Implements worker_spec.md §9 with interrupt gates at:
  phase3_replay_driver_generation, phase3_asan_compilation, phase3_result_classification
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

logger = logging.getLogger("sailor.tasks.phase3")

WORKER_ID: str = f"{os.environ.get('HOSTNAME', 'worker')}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


@celery_app.task(
    name="tasks.phase3_task",
    queue="phase3",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=3,
)
def phase3_task(self, spec_id: str) -> dict:  # type: ignore[no-untyped-def]
    """Execute Phase 3 ASan replay validation for a spec."""
    return asyncio.get_event_loop().run_until_complete(_phase3(spec_id))


async def _phase3(spec_id: str) -> dict:
    from database import AsyncSessionLocal
    from services.artifact_service import get_artifact_store
    from services.event_service import get_event_service
    from services.spec_service import acquire_phase3_lease, drop_phase3_lease, get_spec
    from tasks._control import CooperativeExit

    event_svc = get_event_service()

    # Retry with backoff if lease is not available (Phase 2 may not have released yet)
    for _attempt in range(10):
        async with AsyncSessionLocal() as db:
            acquired = await acquire_phase3_lease(db, spec_id, WORKER_ID)
        if acquired:
            break
        logger.info("Phase 3: lease not available for spec %s, retrying in 3s (attempt %d)", spec_id, _attempt + 1)
        await asyncio.sleep(3)
    else:
        logger.warning("Phase 3: could not acquire lease on spec %s after retries", spec_id)
        return {"skipped": True, "reason": "lease_not_acquired"}

    async with AsyncSessionLocal() as db:
        acquired = True  # already acquired above

        spec = await get_spec(db, spec_id)
        if not spec:
            return {"error": "spec_not_found"}
        run_id = spec.run_id

        from sqlalchemy import update
        from models.spec import Spec
        await db.execute(
            update(Spec).where(Spec.spec_id == spec_id).values(phase3_status="running")
        )
        await db.commit()

    spec_data = await _get_spec_data(spec_id)
    if spec_data:
        await event_svc.publish_spec_state_changed(run_id, spec_id, spec_data)

    from sailor.infra.docker_runner import DockerRunner, RunnerConfig
    runner = DockerRunner(cve_id=spec_id, config=RunnerConfig())

    try:
        runner.start()
        await _phase3_steps(runner, spec_id, run_id, event_svc)
    except CooperativeExit as ce:
        logger.info("Phase 3 cooperative exit for spec %s: %s", spec_id, ce.reason)
    except Exception as exc:
        logger.exception("Phase 3 failed for spec %s", spec_id)
        await _set_phase3_errored(spec_id, run_id, str(exc), event_svc)
        raise
    finally:
        runner.stop()
        async with AsyncSessionLocal() as db:
            await drop_phase3_lease(db, spec_id, WORKER_ID)

    return {"spec_id": spec_id}


async def _phase3_steps(runner: Any, spec_id: str, run_id: str, event_svc: Any) -> None:
    from services.artifact_service import get_artifact_store
    from tasks._interrupt import interrupt_gate

    store = get_artifact_store()

    # ── Load Phase 2 artifacts ─────────────────────────────────────────────
    driver_c = await _load_latest_draft(store, run_id, spec_id, "driver")
    slice_c = await _load_latest_draft(store, run_id, spec_id, "slice")
    witness_ktest = await _load_witness(store, run_id, spec_id)

    project_root = Path(f"/data/workspace/{run_id}/src")
    output_dir = Path(f"/data/output/{run_id}/phase3")
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Gate: phase3_replay_driver_generation ─────────────────────────────
    gate = await interrupt_gate(
        session=None,
        function_id="phase3_replay_driver_generation",
        run_id=run_id,
        spec_id=spec_id,
        worker_id=WORKER_ID,
        event_service=event_svc,
        scope="spec",
        input_files=[],
    )

    if gate.get("skipped"):
        replay_driver_c: str = "// skipped\n"
    else:
        if driver_c and witness_ktest:
            import tempfile
            from sailor.phase3.replay_driver_gen import ReplayDriverGenerator
            from sailor.models.schemas import HarnessArtifacts, SEOutcome, WitnessInput
            with tempfile.TemporaryDirectory() as _tmpdir:
                _tmp = Path(_tmpdir)
                (_tmp / "test000001.ktest").write_bytes(witness_ktest)
                _witness_in = WitnessInput(
                    spec_id=spec_id,
                    ktest_paths=[str(_tmp / "test000001.ktest")],
                    outcome=SEOutcome.BUG_TRIGGERED,
                    harness=HarnessArtifacts(
                        driver_c=driver_c,
                        slice_c=slice_c or "",
                        compile_cmd="",
                        link_cmd="",
                    ),
                    turns_used=0,
                    refine_count=0,
                )
                replay_driver_c = ReplayDriverGenerator(
                    witness=_witness_in, output_dir=_tmp
                ).generate().read_text()
        else:
            replay_driver_c = driver_c or "// no driver\n"

    # Write replay_driver.c to artifact store
    replay_driver_path = f"runs/{run_id}/phase3/{spec_id}/replay_driver.c"
    await store.put(replay_driver_path, replay_driver_c.encode())

    # ── Gate: phase3_asan_compilation ─────────────────────────────────────
    gate = await interrupt_gate(
        session=None,
        function_id="phase3_asan_compilation",
        run_id=run_id,
        spec_id=spec_id,
        worker_id=WORKER_ID,
        event_service=event_svc,
        scope="spec",
        input_files=[],
    )

    if gate.get("skipped"):
        await _set_phase3_errored(spec_id, run_id, "asan_build_skipped", event_svc)
        return

    # Inline compilation via run_asan_replay(project_dir=...) embeds all
    # project .c files in one TU — no separate archive build needed.
    asan_archive = ""
    include_paths: list[str] = []

    # ── Gate: phase3_result_classification ────────────────────────────────
    gate = await interrupt_gate(
        session=None,
        function_id="phase3_result_classification",
        run_id=run_id,
        spec_id=spec_id,
        worker_id=WORKER_ID,
        event_service=event_svc,
        scope="spec",
        input_files=[],
    )

    if gate.get("skipped"):
        verdict_value = "rejected"
        asan_output = ""
    else:
        try:
            result = runner.run_asan_replay(
                replay_driver_c, asan_archive or "", include_paths,
                project_dir=f"/workspace/{run_id}/src",
            )
            asan_output = result.get("asan_output", "")
        except Exception as replay_err:
            await _set_phase3_errored(spec_id, run_id, f"replay_runtime_failure: {replay_err}", event_svc)
            return

        crashed = result.get("crashed", False) or result.get("exit_code", 0) != 0
        verdict_value = "confirmed" if (crashed and "ERROR: AddressSanitizer" in asan_output) else "rejected"

    # ── Write artifacts and verdict ────────────────────────────────────────
    asan_report_path = f"runs/{run_id}/phase3/{spec_id}/asan_report.txt"
    await store.put(asan_report_path, asan_output.encode())

    verdict_dict = _build_verdict_dict(spec_id, verdict_value, asan_output)
    verified_bug_path = f"runs/{run_id}/phase3/{spec_id}/verified_bug.json"
    await store.put(verified_bug_path, json.dumps(verdict_dict).encode())

    # ── Persist verdict and update spec ────────────────────────────────────
    await _persist_verdict_and_update(spec_id, run_id, verdict_value, verdict_dict, event_svc)

    # ── Completion check ───────────────────────────────────────────────────
    await _check_run_completion(run_id, event_svc)


def _build_verdict_dict(spec_id: str, verdict_value: str, asan_output: str) -> dict[str, Any]:
    """Extract crash info from ASan output and build verdict dict."""
    import re
    file_loc = line_loc = func_name = cwe = asan_type = None

    # Extract crash type from ASan output
    m = re.search(r"ERROR: AddressSanitizer: (\S+)", asan_output)
    if m:
        asan_type = m.group(1)
        cwe_map = {
            "heap-buffer-overflow": "CWE-122",
            "stack-buffer-overflow": "CWE-121",
            "heap-use-after-free": "CWE-416",
            "double-free": "CWE-415",
        }
        cwe = cwe_map.get(asan_type.lower())

    # Extract crash location (first frame in project source)
    for line in asan_output.splitlines():
        fm = re.search(r"#\d+\s+0x[0-9a-f]+ in (\S+) ([^:]+):(\d+)", line)
        if fm:
            func_name = fm.group(1)
            file_loc = fm.group(2)
            try:
                line_loc = int(fm.group(3))
            except ValueError:
                line_loc = None
            break

    dedup_key: str | None = None
    if file_loc and func_name:
        k = f"{file_loc}{func_name}{line_loc or ''}"
        dedup_key = hashlib.sha256(k.encode()).hexdigest()[:32]

    return {
        "spec_id": spec_id,
        "verdict": verdict_value,
        "cwe": cwe,
        "asan_type": asan_type,
        "file": file_loc,
        "line": line_loc,
        "func": func_name,
        "dedup_key": dedup_key,
    }


async def _persist_verdict_and_update(
    spec_id: str,
    run_id: str,
    verdict_value: str,
    verdict_dict: dict[str, Any],
    event_svc: Any,
) -> None:
    from database import AsyncSessionLocal
    from models.spec import Spec
    from models.verdict import Verdict
    from models.run import Run
    from sqlalchemy import select, update

    async with AsyncSessionLocal() as db:
        # Insert Verdict
        v = Verdict(
            verdict_id=str(uuid.uuid4()),
            spec_id=spec_id,
            verdict=verdict_value,
            cwe=verdict_dict.get("cwe"),
            asan_type=verdict_dict.get("asan_type"),
            file=verdict_dict.get("file"),
            line=verdict_dict.get("line"),
            func=verdict_dict.get("func"),
            dedup_key=verdict_dict.get("dedup_key"),
            verified_bug_json=verdict_dict,
        )
        db.add(v)

        # Update Spec
        await db.execute(
            update(Spec)
            .where(Spec.spec_id == spec_id)
            .values(phase3_status=verdict_value, phase3_verdict=verdict_value,
                    last_event_at=datetime.utcnow(), worker_id=None, locked_until=None)
        )

        # Update run counters
        run = await db.get(Run, run_id)
        if run:
            counters = dict(run.counters or {})
            if verdict_value == "confirmed":
                counters["specs_phase3_confirmed"] = counters.get("specs_phase3_confirmed", 0) + 1
                dedup_key = verdict_dict.get("dedup_key")
                if dedup_key:
                    counters["unique_confirmed"] = counters.get("unique_confirmed", 0) + 1
            elif verdict_value == "rejected":
                counters["specs_phase3_rejected"] = counters.get("specs_phase3_rejected", 0) + 1
            await db.execute(
                update(Run).where(Run.run_id == run_id).values(counters=counters)
            )

        await db.commit()

    spec_data = await _get_spec_data(spec_id)
    if spec_data:
        await event_svc.publish_spec_state_changed(run_id, spec_id, spec_data)

    async with AsyncSessionLocal() as db:
        run = await db.get(Run, run_id)
        if run:
            counters = dict(run.counters or {})
    await event_svc.publish_counters_throttled(run_id, counters)


async def _check_run_completion(run_id: str, event_svc: Any) -> None:
    """Complete the run if all specs reached a terminal state."""
    from database import AsyncSessionLocal
    from models.run import Run
    from models.spec import Spec
    from sqlalchemy import func, select, update

    async with AsyncSessionLocal() as db:
        total = (await db.scalar(
            select(func.count(Spec.spec_id)).where(Spec.run_id == run_id)
        )) or 0
        p3_terminal = (await db.scalar(
            select(func.count(Spec.spec_id)).where(
                Spec.run_id == run_id,
                Spec.phase3_status.in_(["confirmed", "rejected", "errored", "not_eligible"]),
            )
        )) or 0
        p2_terminal_no_p3 = (await db.scalar(
            select(func.count(Spec.spec_id)).where(
                Spec.run_id == run_id,
                Spec.phase2_status.in_(["inconclusive", "likely_false_positive", "errored"]),
            )
        )) or 0

        if total > 0 and (p3_terminal + p2_terminal_no_p3) >= total:
            res = await db.execute(
                update(Run)
                .where(Run.run_id == run_id, Run.status == "running")
                .values(status="completed", completed_at=datetime.utcnow())
                .returning(Run.run_id)
            )
            await db.commit()
            if res.scalar_one_or_none():
                await event_svc.publish_run_status_changed(run_id, "completed")


async def _set_phase3_errored(spec_id: str, run_id: str, error: str, event_svc: Any) -> None:
    from database import AsyncSessionLocal
    from sqlalchemy import update
    from models.spec import Spec
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Spec).where(Spec.spec_id == spec_id)
            .values(phase3_status="errored", phase3_error=error,
                    worker_id=None, locked_until=None)
        )
        await db.commit()
    spec_data = await _get_spec_data(spec_id)
    if spec_data:
        await event_svc.publish_spec_state_changed(run_id, spec_id, spec_data)


async def _load_latest_draft(store: Any, run_id: str, spec_id: str, artifact: str) -> str | None:
    """Load the latest version of a Phase 2 draft artifact."""
    try:
        for version in range(20, 0, -1):
            path = f"runs/{run_id}/phase2/{spec_id}/drafts/{artifact}.v{version}.c"
            if await store.exists(path):
                data = await store.get(path)
                return data.decode()
        # fallback: Phase 2 DockerRunner writes harness to workspace volume
        workspace_path = Path(f"/data/workspace/{spec_id}/harness/{artifact}.c")
        if workspace_path.exists():
            return workspace_path.read_text()
        # fallback: try output dir
        output_path = Path(f"/data/output/{run_id}/phase2/{artifact}.c")
        if output_path.exists():
            return output_path.read_text()
    except Exception as exc:
        logger.debug("Could not load draft %s for spec %s: %s", artifact, spec_id, exc)
    return None


async def _load_witness(store: Any, run_id: str, spec_id: str) -> bytes | None:
    """Load the ktest witness file for a spec."""
    try:
        path = f"runs/{run_id}/phase2/{spec_id}/witness/test000001.ktest"
        if await store.exists(path):
            return await store.get(path)
        # Check e2e workspace fixtures
        fixture_paths = [
            f"/workspace/{run_id}/src/fixtures/witness.ktest",
        ]
        for fp in fixture_paths:
            p = Path(fp)
            if p.exists():
                return p.read_bytes()
    except Exception as exc:
        logger.debug("Could not load witness for spec %s: %s", spec_id, exc)
    return None


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
