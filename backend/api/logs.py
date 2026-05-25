"""Log retrieval endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import require_role
from models.log_line import LogLine
from models.user import User

router = APIRouter(prefix="/api/runs/{run_id}", tags=["logs"])


@router.get("/logs")
async def get_logs(
    run_id: str,
    level: str | None = None,
    source: str | None = None,
    spec_id: str | None = None,
    worker_id: str | None = None,
    since: str | None = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[dict]:
    q = select(LogLine).where(LogLine.run_id == run_id)
    if level:
        q = q.where(LogLine.level == level)
    if source:
        q = q.where(LogLine.source == source)
    if spec_id:
        q = q.where(LogLine.spec_id == spec_id)
    if worker_id:
        q = q.where(LogLine.worker_id == worker_id)
    if since:
        q = q.where(LogLine.log_id > since)  # cursor pagination by ID
    q = q.order_by(LogLine.created_at).limit(min(limit, 1000))
    result = await db.execute(q)
    lines = result.scalars().all()
    return [
        {
            "log_id": ll.log_id,
            "run_id": ll.run_id,
            "spec_id": ll.spec_id,
            "worker_id": ll.worker_id,
            "level": ll.level,
            "source": ll.source,
            "message": ll.message,
            "fields": ll.fields,
            "trace_id": ll.trace_id,
            "created_at": ll.created_at.isoformat(),
        }
        for ll in lines
    ]
