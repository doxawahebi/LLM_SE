"""Worker status endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import require_role
from models.spec import Spec
from models.user import User

router = APIRouter(prefix="/api/runs/{run_id}", tags=["workers"])


@router.get("/workers")
async def list_workers(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[dict]:
    # Derive active workers from specs with non-null worker_id
    result = await db.execute(
        select(Spec.worker_id, func.count(Spec.spec_id).label("spec_count"))
        .where(Spec.run_id == run_id, Spec.worker_id.is_not(None))
        .group_by(Spec.worker_id)
    )
    rows = result.all()
    return [
        {
            "worker_id": row.worker_id,
            "status": "busy",
            "spec_count": row.spec_count,
        }
        for row in rows
    ]


@router.get("/workers/{worker_id}")
async def get_worker(
    run_id: str,
    worker_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> dict:
    result = await db.execute(
        select(Spec).where(Spec.run_id == run_id, Spec.worker_id == worker_id).limit(10)
    )
    specs = result.scalars().all()
    return {
        "worker_id": worker_id,
        "run_id": run_id,
        "current_specs": [s.spec_id for s in specs],
    }


@router.get("/workers/throughput")
async def worker_throughput(
    run_id: str,
    window: str = "5m",
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> dict:
    # Placeholder — real implementation would query time-series metrics
    return {"run_id": run_id, "window": window, "series": []}
