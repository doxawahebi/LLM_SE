"""Phase 3 Celery task — ASan concrete validation."""

import asyncio
import hashlib
import logging
import uuid

from celery_app import celery_app

logger = logging.getLogger("sailor.tasks.phase3")


@celery_app.task(name="tasks.phase3.run", queue="phase3", bind=True, max_retries=3)
def phase3_task(self, spec_id: str) -> dict:  # type: ignore[no-untyped-def]
    return asyncio.get_event_loop().run_until_complete(_run_phase3(spec_id))


async def _run_phase3(spec_id: str) -> dict:
    from database import AsyncSessionLocal
    from services.spec_service import acquire_lease, get_spec, release_lease

    worker_id = str(uuid.uuid4())

    async with AsyncSessionLocal() as db:
        acquired = await acquire_lease(db, spec_id, worker_id)
        if not acquired:
            logger.warning("Could not acquire lease for phase3 on spec %s", spec_id)
            return {"error": "lease_not_acquired"}

    try:
        from sailor.infra.docker_runner import DockerRunner, RunnerConfig
        from sailor.phase3.pipeline import Phase3Config, Phase3Pipeline

        runner = DockerRunner(cve_id=spec_id, config=RunnerConfig())
        runner.start()
        try:
            config = Phase3Config(spec_id=spec_id)
            pipeline = Phase3Pipeline(config, runner=runner)
            result = await pipeline.run()
        finally:
            runner.stop()

        verdict = result.get("verdict", "rejected")
        dedup_key: str | None = None

        if verdict == "confirmed":
            key_str = f"{result.get('file','')}{result.get('func','')}{result.get('line','')}"
            dedup_key = hashlib.sha256(key_str.encode()).hexdigest()[:16]

        # Persist Verdict row
        async with AsyncSessionLocal() as db:
            from sqlalchemy import update
            from models.spec import Spec
            from models.verdict import Verdict

            v = Verdict(
                verdict_id=str(uuid.uuid4()),
                spec_id=spec_id,
                verdict=verdict,
                cwe=result.get("cwe"),
                asan_type=result.get("asan_type"),
                file=result.get("file"),
                line=result.get("line"),
                func=result.get("func"),
                inputs=result.get("inputs"),
                verified_bug_json=result.get("verified_bug_json"),
                dedup_key=dedup_key,
            )
            db.add(v)
            await db.execute(
                update(Spec)
                .where(Spec.spec_id == spec_id)
                .values(
                    phase3_status=verdict,
                    phase3_verdict=verdict,
                    worker_id=None,
                    locked_until=None,
                )
            )
            await db.commit()

        return {"spec_id": spec_id, "verdict": verdict}

    except Exception as exc:
        logger.exception("Phase 3 failed for spec %s", spec_id)
        async with AsyncSessionLocal() as db:
            from sqlalchemy import update
            from models.spec import Spec

            await db.execute(
                update(Spec).where(Spec.spec_id == spec_id)
                .values(phase3_status="errored", phase3_error=str(exc), worker_id=None, locked_until=None)
            )
            await db.commit()
        raise

    finally:
        async with AsyncSessionLocal() as db:
            await release_lease(db, spec_id, worker_id)
