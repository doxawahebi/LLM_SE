"""Phase 1 Celery task — orchestrates Phase1Pipeline inside Docker."""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from celery_app import celery_app

logger = logging.getLogger("sailor.tasks.phase1")


@celery_app.task(name="tasks.phase1.run", queue="phase1", bind=True, max_retries=3)
def phase1_task(self, run_id: str) -> dict:  # type: ignore[no-untyped-def]
    """Execute Phase 1 pipeline for a run."""
    return asyncio.get_event_loop().run_until_complete(_run_phase1(run_id))


async def _run_phase1(run_id: str) -> dict:
    from database import AsyncSessionLocal
    from services.run_service import get_run, transition_run

    async with AsyncSessionLocal() as db:
        run = await get_run(db, run_id)
        if not run:
            logger.error("Run %s not found", run_id)
            return {"error": "run not found"}

        await transition_run(db, run_id, "running", ["queued"])

    try:
        from sailor.infra.docker_runner import DockerRunner, RunnerConfig
        from sailor.phase1.pipeline import Phase1Config, Phase1Pipeline

        runner = DockerRunner(cve_id=run_id, config=RunnerConfig())
        runner.start()
        try:
            config = Phase1Config(
                run_id=run_id,
                query_suite=run.config.get("phase1_query_suite", []),
                skip_files=run.config.get("phase1_skip_files", []),
                skip_functions=run.config.get("phase1_skip_functions", []),
            )
            pipeline = Phase1Pipeline(config, runner=runner)
            result = await pipeline.run()
        finally:
            runner.stop()

        # Persist specs from Phase 1 result
        async with AsyncSessionLocal() as db:
            from services.run_service import transition_run
            await transition_run(db, run_id, "completed", ["running"],
                                 extra={"phase1_summary": result.get("summary", {})})

        return {"run_id": run_id, "status": "completed"}

    except Exception as exc:
        logger.exception("Phase 1 failed for run %s", run_id)
        async with AsyncSessionLocal() as db:
            from services.run_service import transition_run
            await transition_run(db, run_id, "failed", ["running"],
                                 extra={"error": str(exc)})
        raise
