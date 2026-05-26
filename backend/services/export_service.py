"""Export job service."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models.log_line import ExportJob


async def create_export_job(
    db: AsyncSession,
    run_id: str | None,
    spec_ids: list[str] | None,
    export_type: str,
) -> ExportJob:
    job = ExportJob(
        job_id=str(uuid.uuid4()),
        run_id=run_id,
        spec_ids=spec_ids,
        export_type=export_type,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    return job


async def get_export_job(db: AsyncSession, job_id: str) -> ExportJob | None:
    result = await db.execute(select(ExportJob).where(ExportJob.job_id == job_id))
    return result.scalar_one_or_none()


async def complete_export_job(db: AsyncSession, job_id: str, artifact_ref: str) -> None:
    await db.execute(
        update(ExportJob)
        .where(ExportJob.job_id == job_id)
        .values(status="completed", artifact_ref=artifact_ref, completed_at=datetime.now(timezone.utc))
    )
    await db.commit()


async def fail_export_job(db: AsyncSession, job_id: str, error: str) -> None:
    await db.execute(
        update(ExportJob)
        .where(ExportJob.job_id == job_id)
        .values(status="failed", error=error, completed_at=datetime.now(timezone.utc))
    )
    await db.commit()
