"""Phase 2 Celery task — orchestrates Phase2Pipeline with lease heartbeat."""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from celery_app import celery_app

logger = logging.getLogger("sailor.tasks.phase2")

HEARTBEAT_INTERVAL = 30  # seconds


@celery_app.task(name="tasks.phase2.run", queue="phase2", bind=True, max_retries=3)
def phase2_task(self, spec_id: str, continue_from_intervention: bool = False) -> dict:  # type: ignore[no-untyped-def]
    return asyncio.get_event_loop().run_until_complete(
        _run_phase2(spec_id, continue_from_intervention)
    )


async def _run_phase2(spec_id: str, continue_from_intervention: bool) -> dict:
    from database import AsyncSessionLocal
    from services.spec_service import acquire_lease, extend_lease, get_spec, release_lease

    worker_id = str(uuid.uuid4())

    async with AsyncSessionLocal() as db:
        acquired = await acquire_lease(db, spec_id, worker_id)
        if not acquired:
            logger.warning("Could not acquire lease on spec %s", spec_id)
            return {"error": "lease_not_acquired"}

    try:
        # Start heartbeat
        heartbeat_task = asyncio.create_task(_heartbeat(spec_id, worker_id))

        try:
            from sailor.infra.docker_runner import DockerRunner, RunnerConfig
            from sailor.phase2.pipeline import Phase2Config, Phase2Pipeline

            runner = DockerRunner(cve_id=spec_id, config=RunnerConfig())
            runner.start()
            try:
                async with AsyncSessionLocal() as db:
                    spec = await get_spec(db, spec_id)
                if not spec:
                    return {"error": "spec not found"}

                config = Phase2Config(
                    spec_id=spec_id,
                    continue_from_intervention=continue_from_intervention,
                )
                pipeline = Phase2Pipeline(config, runner=runner)

                # Turn-boundary callback for control-flag checks
                async def on_turn(turn_info: dict) -> str | None:
                    """Return 'pause', 'cancel', or None."""
                    async with AsyncSessionLocal() as db:
                        from models.run import Run
                        from models.spec import Spec
                        from sqlalchemy import select

                        spec_row = await db.execute(
                            select(Spec).where(Spec.spec_id == spec_id)
                        )
                        spec_obj = spec_row.scalar_one_or_none()
                        if not spec_obj:
                            return "cancel"

                        run_row = await db.execute(
                            select(Run).where(Run.run_id == spec_obj.run_id)
                        )
                        run_obj = run_row.scalar_one_or_none()
                        if not run_obj:
                            return "cancel"

                        if run_obj.status == "cancelled":
                            return "cancel"
                        if run_obj.status == "paused":
                            return "pause"

                        if spec_obj.intervention_pending:
                            from services.spec_service import pop_intervention
                            iv = await pop_intervention(db, spec_id)
                            if iv:
                                return f"intervention:{iv.payload}"

                    return None

                result = await pipeline.run(on_turn_boundary=on_turn)

            finally:
                runner.stop()

        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

        # Persist terminal state
        async with AsyncSessionLocal() as db:
            from sqlalchemy import update
            from models.spec import Spec

            outcome = result.get("outcome", "errored")
            values = {
                "phase2_status": outcome,
                "phase2_outcome": outcome if outcome in ("bug_triggered", "inconclusive", "likely_false_positive", "errored") else None,
                "worker_id": None,
                "locked_until": None,
            }
            await db.execute(update(Spec).where(Spec.spec_id == spec_id).values(**values))
            await db.commit()

            # If bug_triggered and phase3 enabled → enqueue phase3_task
            if outcome == "bug_triggered":
                phase3_task.delay(spec_id)

        return {"spec_id": spec_id, "outcome": outcome}

    except Exception as exc:
        logger.exception("Phase 2 failed for spec %s", spec_id)
        async with AsyncSessionLocal() as db:
            from sqlalchemy import update
            from models.spec import Spec

            await db.execute(
                update(Spec).where(Spec.spec_id == spec_id)
                .values(phase2_status="errored", phase2_error=str(exc), worker_id=None, locked_until=None)
            )
            await db.commit()
        raise

    finally:
        async with AsyncSessionLocal() as db:
            await release_lease(db, spec_id, worker_id)


async def _heartbeat(spec_id: str, worker_id: str) -> None:
    from database import AsyncSessionLocal
    from services.spec_service import extend_lease

    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        async with AsyncSessionLocal() as db:
            await extend_lease(db, spec_id, worker_id)


# Import phase3_task here to avoid circular import
from tasks.phase3 import phase3_task  # noqa: E402
