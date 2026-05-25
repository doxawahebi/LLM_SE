"""Run service — CRUD and state transitions."""

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models.run import Run
from schemas.run import RunConfig


VALID_TRANSITIONS: dict[str, list[str]] = {
    "created": ["needs_build_config", "queued"],
    "needs_build_config": ["queued"],
    "queued": ["running"],
    "running": ["paused", "completed", "failed", "cancelled"],
    "paused": ["running", "cancelled"],
}


async def create_run(
    db: AsyncSession,
    name: str,
    build_command: str = "",
    codeql_build_mode: str = "autodetect",
    config: RunConfig | None = None,
    created_by: str | None = None,
    project_zip_ref: str | None = None,
) -> Run:
    run = Run(
        run_id=str(uuid.uuid4()),
        name=name,
        build_command=build_command or None,
        codeql_build_mode=codeql_build_mode,
        config=config.model_dump() if config else {},
        counters=_empty_counters(),
        created_by=created_by,
        project_zip_ref=project_zip_ref,
        status="created",
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return run


def _empty_counters() -> dict:
    return {
        "specs_total": 0,
        "specs_filtered_out": 0,
        "specs_emitted": 0,
        "specs_phase2_queued": 0,
        "specs_phase2_running": 0,
        "specs_phase2_bug_triggered": 0,
        "specs_phase2_inconclusive": 0,
        "specs_phase2_likely_fp": 0,
        "specs_phase2_errored": 0,
        "specs_phase3_queued": 0,
        "specs_phase3_confirmed": 0,
        "specs_phase3_rejected": 0,
        "unique_confirmed": 0,
        "total_llm_tokens": 0,
        "total_klee_seconds": 0,
    }


async def transition_run(
    db: AsyncSession,
    run_id: str,
    new_status: str,
    from_statuses: list[str],
    extra: dict | None = None,
) -> Run | None:
    """Atomic state transition — returns None if transition rejected."""
    values: dict = {"status": new_status}
    if extra:
        values.update(extra)
    if new_status == "running" and "started_at" not in values:
        values["started_at"] = datetime.utcnow()
    if new_status in ("completed", "failed", "cancelled"):
        values["completed_at"] = datetime.utcnow()

    result = await db.execute(
        update(Run)
        .where(Run.run_id == run_id, Run.status.in_(from_statuses))
        .values(**values)
        .returning(Run)
    )
    await db.commit()
    row = result.fetchone()
    return row[0] if row else None


async def get_run(db: AsyncSession, run_id: str) -> Run | None:
    result = await db.execute(select(Run).where(Run.run_id == run_id))
    return result.scalar_one_or_none()


async def list_runs(
    db: AsyncSession,
    status: str | None = None,
    page: int = 1,
    page_size: int = 20,
) -> list[Run]:
    q = select(Run)
    if status:
        q = q.where(Run.status == status)
    q = q.order_by(Run.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    return list(result.scalars().all())
