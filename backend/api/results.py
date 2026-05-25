"""Results, compare, and bulk export endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import require_role
from models.user import User
from models.verdict import Verdict
from schemas.verdict import CompareResult, VerdictDetail, VerdictSummary
from services.export_service import create_export_job
from services.run_service import get_run

router = APIRouter(prefix="/api/runs/{run_id}", tags=["results"])


@router.get("/results", response_model=list[VerdictDetail])
async def get_results(
    run_id: str,
    deduplicate: bool = True,
    group_by: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[VerdictDetail]:
    run = await get_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    from models.spec import Spec

    q = (
        select(Verdict)
        .join(Spec, Verdict.spec_id == Spec.spec_id)
        .where(Spec.run_id == run_id, Verdict.verdict == "confirmed")
    )
    result = await db.execute(q)
    verdicts = result.scalars().all()

    if deduplicate:
        seen: set[str] = set()
        deduped = []
        for v in verdicts:
            key = v.dedup_key or v.verdict_id
            if key not in seen:
                seen.add(key)
                deduped.append(v)
        verdicts = deduped

    return [VerdictDetail.model_validate(v) for v in verdicts]


@router.get("/results/compare")
async def compare_results(
    run_id: str,
    other: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> CompareResult:
    from models.spec import Spec

    def _get_verdicts(rid: str):  # type: ignore[return]
        return (
            select(Verdict)
            .join(Spec, Verdict.spec_id == Spec.spec_id)
            .where(Spec.run_id == rid, Verdict.verdict == "confirmed")
        )

    a_result = await db.execute(_get_verdicts(run_id))
    b_result = await db.execute(_get_verdicts(other))

    a_verdicts = {v.dedup_key or v.verdict_id: v for v in a_result.scalars().all()}
    b_verdicts = {v.dedup_key or v.verdict_id: v for v in b_result.scalars().all()}

    a_keys = set(a_verdicts.keys())
    b_keys = set(b_verdicts.keys())

    return CompareResult(
        in_a_only=[VerdictSummary.model_validate(a_verdicts[k]) for k in a_keys - b_keys],
        in_b_only=[VerdictSummary.model_validate(b_verdicts[k]) for k in b_keys - a_keys],
        shared=[VerdictSummary.model_validate(a_verdicts[k]) for k in a_keys & b_keys],
    )


@router.post("/exports/all-confirmed")
async def export_all_confirmed(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> dict:
    job = await create_export_job(db, run_id=run_id, spec_ids=None, export_type="all_confirmed")
    # TODO: enqueue export_task(job.job_id)
    return {"job_id": job.job_id, "status": "pending"}
