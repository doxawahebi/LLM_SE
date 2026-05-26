"""Spec operations — /api/runs/:id/specs/*."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import require_role
from models.spec import Intervention, Spec
from models.turn import Turn
from models.user import User
from schemas.intervention import EditHarness, EditSpec, ForceOutcome, InterventionPayload
from schemas.spec import BulkRequeueRequest, BulkSkipRequest, RequeueRequest, SkipRequest, SpecDetail, SpecSummary
from schemas.turn import TurnDetail, TurnSummary
from services.audit_service import log_audit
from services.spec_service import add_intervention, get_spec, list_specs

router = APIRouter(prefix="/api/runs/{run_id}", tags=["specs"])


@router.get("/specs", response_model=list[SpecSummary])
async def list_specs_endpoint(
    run_id: str,
    phase2_status: str | None = None,
    phase3_status: str | None = None,
    phase1_status: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[SpecSummary]:
    if page_size > 500:
        page_size = 500
    specs = await list_specs(
        db, run_id=run_id,
        phase2_status=phase2_status,
        phase3_status=phase3_status,
        phase1_status=phase1_status,
        search=search,
        page=page,
        page_size=page_size,
    )
    return [
        SpecSummary(
            spec_id=s.spec_id,
            run_id=s.run_id,
            rule_id=s.rule_id,
            file=s.file,
            line=s.line,
            message=s.message,
            phase1_status=s.phase1_status,
            phase2_status=s.phase2_status,
            phase3_status=s.phase3_status,
            current_turn=s.current_turn,
            turn_count_total=s.turn_count_total,
            phase2_outcome=s.phase2_outcome,
            phase3_verdict=s.phase3_verdict,
            intervention_pending=s.intervention_pending,
            last_event_at=s.last_event_at,
        )
        for s in specs
    ]


@router.get("/specs/{spec_id}", response_model=SpecDetail)
async def get_spec_endpoint(
    run_id: str,
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> SpecDetail:
    spec = await get_spec(db, spec_id)
    if not spec or spec.run_id != run_id:
        raise HTTPException(status_code=404, detail="Spec not found")
    return SpecDetail.model_validate(spec)


@router.get("/specs/{spec_id}/turns", response_model=list[TurnSummary])
async def list_turns(
    run_id: str,
    spec_id: str,
    since_turn: int = 0,
    kind: str | None = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[TurnSummary]:
    q = select(Turn).where(Turn.spec_id == spec_id, Turn.turn_number > since_turn)
    if kind:
        q = q.where(Turn.kind == kind)
    q = q.order_by(Turn.turn_number).limit(limit)
    result = await db.execute(q)
    turns = result.scalars().all()
    return [TurnSummary.model_validate(t) for t in turns]


@router.get("/specs/{spec_id}/turns/{turn_id}", response_model=TurnDetail)
async def get_turn(
    run_id: str,
    spec_id: str,
    turn_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> TurnDetail:
    result = await db.execute(select(Turn).where(Turn.turn_id == turn_id, Turn.spec_id == spec_id))
    turn = result.scalar_one_or_none()
    if not turn:
        raise HTTPException(status_code=404, detail="Turn not found")
    return TurnDetail.model_validate(turn)


@router.post("/specs/{spec_id}/requeue")
async def requeue_spec(
    run_id: str,
    spec_id: str,
    body: RequeueRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> dict:
    spec = await get_spec(db, spec_id)
    if not spec or spec.run_id != run_id:
        raise HTTPException(status_code=404, detail="Spec not found")
    terminal_statuses = ["bug_triggered", "inconclusive", "likely_false_positive", "errored"]
    if spec.phase2_status not in terminal_statuses:
        raise HTTPException(status_code=409, detail="Spec must be in a terminal phase2 status")
    values: dict = {"phase2_status": "queued"}
    if body.reset_turn:
        values.update({"current_turn": 0, "turn_count_total": 0, "refine_count": 0, "phase2_outcome": None, "phase2_error": None})
    await db.execute(update(Spec).where(Spec.spec_id == spec_id).values(**values))
    await db.commit()
    await log_audit(db, "spec_requeue", actor=user.user_id, target=f"spec:{spec_id}")
    from tasks.phase2 import phase2_task
    phase2_task.delay(spec_id)
    return {"spec_id": spec_id, "status": "queued"}


@router.post("/specs/{spec_id}/skip")
async def skip_spec(
    run_id: str,
    spec_id: str,
    body: SkipRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> dict:
    spec = await get_spec(db, spec_id)
    if not spec or spec.run_id != run_id:
        raise HTTPException(status_code=404, detail="Spec not found")
    await db.execute(
        update(Spec).where(Spec.spec_id == spec_id)
        .values(phase2_status="errored", phase2_error=f"skipped: {body.reason}")
    )
    await db.commit()
    await log_audit(db, "spec_skip", actor=user.user_id, target=f"spec:{spec_id}")
    return {"spec_id": spec_id, "status": "errored"}


@router.post("/specs/bulk-requeue")
async def bulk_requeue(
    run_id: str,
    body: BulkRequeueRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> dict:
    await db.execute(
        update(Spec)
        .where(Spec.spec_id.in_(body.spec_ids), Spec.run_id == run_id)
        .values(phase2_status="queued")
    )
    await db.commit()
    from tasks.phase2 import phase2_task
    for sid in body.spec_ids:
        phase2_task.delay(sid)
    return {"requeued": len(body.spec_ids)}


@router.post("/specs/bulk-skip")
async def bulk_skip(
    run_id: str,
    body: BulkSkipRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> dict:
    await db.execute(
        update(Spec)
        .where(Spec.spec_id.in_(body.spec_ids), Spec.run_id == run_id)
        .values(phase2_status="errored", phase2_error=f"skipped: {body.reason}")
    )
    await db.commit()
    return {"skipped": len(body.spec_ids)}


@router.post("/specs/{spec_id}/intervene")
async def intervene(
    run_id: str,
    spec_id: str,
    body: InterventionPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("intervener")),
) -> dict:
    spec = await get_spec(db, spec_id)
    if not spec or spec.run_id != run_id:
        raise HTTPException(status_code=404, detail="Spec not found")

    payload_dict = body.model_dump()

    if isinstance(body, EditHarness):
        # Optimistic concurrency check — base_version vs current artifact version
        # Version is tracked via turn count for the artifact type
        current_version = spec.turn_count_total
        if body.base_version != current_version:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"current_version": current_version, "message": "Concurrent edit detected"},
            )

    await add_intervention(db, spec_id, payload_dict, submitted_by=user.user_id)
    await log_audit(db, "spec_intervene", actor=user.user_id, target=f"spec:{spec_id}")
    return {"spec_id": spec_id, "intervention_pending": True}
