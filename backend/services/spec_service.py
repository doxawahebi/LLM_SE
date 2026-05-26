"""Spec service — CRUD and lease management."""

import json
import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from models.spec import Intervention, Spec

LEASE_DURATION = timedelta(minutes=5)


async def get_spec(db: AsyncSession, spec_id: str) -> Spec | None:
    result = await db.execute(select(Spec).where(Spec.spec_id == spec_id))
    return result.scalar_one_or_none()


async def list_specs(
    db: AsyncSession,
    run_id: str,
    phase2_status: str | None = None,
    phase3_status: str | None = None,
    phase1_status: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> list[Spec]:
    q = select(Spec).where(Spec.run_id == run_id)
    if phase2_status:
        q = q.where(Spec.phase2_status == phase2_status)
    if phase3_status:
        q = q.where(Spec.phase3_status == phase3_status)
    if phase1_status:
        q = q.where(Spec.phase1_status == phase1_status)
    if search:
        q = q.where(Spec.message.ilike(f"%{search}%"))
    q = q.order_by(Spec.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    return list(result.scalars().all())


async def acquire_lease(db: AsyncSession, spec_id: str, worker_id: str) -> bool:
    now = datetime.utcnow()
    result = await db.execute(
        update(Spec)
        .where(
            Spec.spec_id == spec_id,
            (Spec.worker_id.is_(None)) | (Spec.locked_until < now),
        )
        .values(worker_id=worker_id, locked_until=now + LEASE_DURATION)
    )
    await db.commit()
    return result.rowcount > 0


async def extend_lease(db: AsyncSession, spec_id: str, worker_id: str) -> None:
    now = datetime.utcnow()
    await db.execute(
        update(Spec)
        .where(Spec.spec_id == spec_id, Spec.worker_id == worker_id)
        .values(locked_until=now + LEASE_DURATION)
    )
    await db.commit()


async def release_lease(db: AsyncSession, spec_id: str, worker_id: str) -> None:
    await db.execute(
        update(Spec)
        .where(Spec.spec_id == spec_id, Spec.worker_id == worker_id)
        .values(worker_id=None, locked_until=None)
    )
    await db.commit()


async def extend_lease_bool(db: AsyncSession, spec_id: str, worker_id: str) -> bool:
    """Extend lease; returns False if lease was stolen (zero rows updated)."""
    now = datetime.utcnow()
    result = await db.execute(
        update(Spec)
        .where(Spec.spec_id == spec_id, Spec.worker_id == worker_id)
        .values(locked_until=now + LEASE_DURATION)
        .returning(Spec.spec_id)
    )
    await db.commit()
    return result.scalar_one_or_none() is not None


async def acquire_phase3_lease(db: AsyncSession, spec_id: str, worker_id: str) -> bool:
    """Acquire Phase 3 lease; returns True if acquired."""
    now = datetime.utcnow()
    result = await db.execute(
        update(Spec)
        .where(
            Spec.spec_id == spec_id,
            (Spec.worker_id.is_(None)) | (Spec.locked_until < now),
        )
        .values(worker_id=worker_id, locked_until=now + LEASE_DURATION)
        .returning(Spec.spec_id)
    )
    await db.commit()
    return result.scalar_one_or_none() is not None


async def drop_phase3_lease(db: AsyncSession, spec_id: str, worker_id: str) -> None:
    """Drop Phase 3 lease."""
    await release_lease(db, spec_id, worker_id)


async def persist_turn(
    db: AsyncSession,
    spec_id: str,
    worker_id: str,
    turn_data: dict[str, Any],
    spec_updates: dict[str, Any],
) -> bool:
    """Atomically update Spec counters and insert a Turn row.

    Returns False if the lease was stolen (zero-row Spec update).
    turn_data must contain all Turn columns except spec_id.
    """
    from models.turn import Turn

    async with db.begin():
        spec_result = await db.execute(
            update(Spec)
            .where(
                Spec.spec_id == spec_id,
                Spec.worker_id == worker_id,
                Spec.locked_until > datetime.utcnow(),
            )
            .values(**spec_updates)
            .returning(Spec.spec_id)
        )
        if spec_result.scalar_one_or_none() is None:
            return False  # lease stolen

        # Insert Turn; ON CONFLICT DO NOTHING for idempotency
        stmt = (
            insert(Turn)
            .values(spec_id=spec_id, **turn_data)
            .on_conflict_do_nothing(index_elements=["turn_id"])
        )
        await db.execute(stmt)

    return True


async def add_intervention(
    db: AsyncSession,
    spec_id: str,
    payload: dict,
    submitted_by: str | None = None,
) -> Intervention:
    intervention = Intervention(
        intervention_id=str(uuid.uuid4()),
        spec_id=spec_id,
        payload=payload,
        submitted_by=submitted_by,
    )
    db.add(intervention)
    await db.execute(
        update(Spec)
        .where(Spec.spec_id == spec_id)
        .values(intervention_pending=True)
    )
    await db.commit()
    return intervention


async def pop_intervention(db: AsyncSession, spec_id: str) -> Intervention | None:
    result = await db.execute(
        select(Intervention)
        .where(Intervention.spec_id == spec_id, Intervention.applied == False)  # noqa: E712
        .order_by(Intervention.created_at)
        .limit(1)
    )
    iv = result.scalar_one_or_none()
    if iv:
        await db.execute(
            update(Intervention)
            .where(Intervention.intervention_id == iv.intervention_id)
            .values(applied=True)
        )
        # Check if more pending
        remaining = await db.execute(
            select(Intervention).where(
                Intervention.spec_id == spec_id, Intervention.applied == False  # noqa: E712
            )
        )
        if not remaining.scalar_one_or_none():
            await db.execute(
                update(Spec).where(Spec.spec_id == spec_id).values(intervention_pending=False)
            )
        await db.commit()
    return iv
