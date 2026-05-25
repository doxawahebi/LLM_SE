"""Export task — assembles evidence tarballs."""

import asyncio
import io
import logging
import tarfile

from celery_app import celery_app

logger = logging.getLogger("sailor.tasks.exports")


@celery_app.task(name="tasks.exports.run", queue="exports", bind=True)
def export_task(self, job_id: str) -> dict:  # type: ignore[no-untyped-def]
    return asyncio.get_event_loop().run_until_complete(_run_export(job_id))


async def _run_export(job_id: str) -> dict:
    from database import AsyncSessionLocal
    from services.artifact_service import get_artifact_store
    from services.export_service import complete_export_job, fail_export_job, get_export_job

    async with AsyncSessionLocal() as db:
        job = await get_export_job(db, job_id)
        if not job:
            return {"error": "job not found"}

        store = get_artifact_store()
        prefix = f"runs/{job.run_id}/" if job.run_id else ""

        try:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                items = await store.list_prefix(prefix)
                for item in items:
                    data = await store.get(item.path)
                    info = tarfile.TarInfo(name=item.path)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))

            buf.seek(0)
            output_path = f"runs/{job.run_id}/exports/{job_id}.tar.gz"
            await store.put(output_path, buf.read())
            await complete_export_job(db, job_id, output_path)
            return {"job_id": job_id, "artifact_ref": output_path}

        except Exception as exc:
            logger.exception("Export job %s failed", job_id)
            await fail_export_job(db, job_id, str(exc))
            raise
