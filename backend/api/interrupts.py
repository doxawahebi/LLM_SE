"""Interrupt panel state endpoints — /api/runs/:run_id/interrupts/*."""

import uuid
from datetime import datetime, timezone


def _utcnow() -> datetime:
    """Return current UTC time as naive datetime (DB stores TIMESTAMP WITHOUT TIME ZONE)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import get_current_user, require_role
from models.interrupt_point import InterruptPoint
from models.run import Run
from models.user import User
from services.artifact_service import get_artifact_store
from services.event_service import get_event_service
from services.validation_service import get_validator_service
from shared.contracts.sailor_models import (
    FileValidationResult,
    InterruptCreatedPayload,
    InterruptInputFile,
    InterruptPoint as InterruptPointSchema,
    InterruptResolvedPayload,
    InterruptResumeRequest,
    InterruptScope,
    InterruptSkipRequest,
    InterruptStatus,
    PipelineFunctionId,
    SSEMessageInterruptResolved,
)

router = APIRouter(prefix="/api/runs", tags=["interrupts"])


# ── helpers ─────────────────────────────────────────────────────────────────


def _row_to_schema(row: InterruptPoint, include_input_files: bool = False) -> InterruptPointSchema:
    input_files = None
    if include_input_files and row.input_files:
        input_files = [InterruptInputFile(**f) for f in row.input_files]
    return InterruptPointSchema(
        interrupt_id=row.interrupt_id,
        run_id=row.run_id,
        spec_id=row.spec_id,
        function_name=PipelineFunctionId(row.function_name),
        scope=InterruptScope(row.scope),
        turn=row.turn,
        status=InterruptStatus(row.status),
        created_at=row.created_at.replace(tzinfo=timezone.utc) if row.created_at.tzinfo is None else row.created_at,
        resolved_at=row.resolved_at.replace(tzinfo=timezone.utc) if row.resolved_at and row.resolved_at.tzinfo is None else row.resolved_at,
        resolved_by=row.resolved_by,
        input_files=input_files,
        option_overrides=row.option_overrides or None,
    )


async def _publish_resolved(run_id: str, row: InterruptPoint, resolved_by_user_id: str | None, resolution: str) -> None:
    event_service = get_event_service()
    msg = SSEMessageInterruptResolved(
        topic=f"runs.{run_id}",
        sequence=0,
        timestamp=datetime.now(timezone.utc),
        kind="interrupt_resolved",
        payload=InterruptResolvedPayload(
            interrupt_id=row.interrupt_id,
            run_id=run_id,
            spec_id=row.spec_id,
            resolution=resolution,  # type: ignore[arg-type]
            resolved_by=resolved_by_user_id,
        ),
    )
    await event_service.publish_message(msg)


# ── list / detail ────────────────────────────────────────────────────────────


@router.get("/{run_id}/interrupts")
async def list_interrupts(
    run_id: str,
    status: str = Query(default="waiting"),
    function_name: str | None = Query(default=None),
    spec_id: str | None = Query(default=None),
    scope: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[InterruptPointSchema]:
    run_result = await db.execute(select(Run).where(Run.run_id == run_id))
    if not run_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail={"code": "run_not_found", "message": "Run not found"})

    stmt = select(InterruptPoint).where(
        InterruptPoint.run_id == run_id,
        InterruptPoint.status == status,
    ).order_by(InterruptPoint.created_at)

    if function_name is not None:
        stmt = stmt.where(InterruptPoint.function_name == function_name)
    if spec_id is not None:
        stmt = stmt.where(InterruptPoint.spec_id == spec_id)
    if scope is not None:
        stmt = stmt.where(InterruptPoint.scope == scope)

    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [_row_to_schema(r) for r in rows]


@router.get("/{run_id}/interrupts/{interrupt_id}", response_model=InterruptPointSchema)
async def get_interrupt(
    run_id: str,
    interrupt_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> InterruptPointSchema:
    result = await db.execute(
        select(InterruptPoint).where(
            InterruptPoint.interrupt_id == interrupt_id,
            InterruptPoint.run_id == run_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail={"code": "interrupt_not_found", "message": "Interrupt not found"})
    # Include input_files with populated presigned URLs for detail view
    return _row_to_schema(row, include_input_files=True)


# ── file upload ──────────────────────────────────────────────────────────────


class FileUploadResponse(BaseModel):
    artifact_ref: str
    validation: FileValidationResult


@router.post("/{run_id}/interrupts/{interrupt_id}/files", response_model=FileUploadResponse)
async def upload_interrupt_file(
    run_id: str,
    interrupt_id: str,
    file: UploadFile = File(...),
    name: str = Form(...),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("intervener")),
) -> FileUploadResponse:
    """Upload a replacement file for an interrupt.

    Returns artifact_ref (use in subsequent /resume call) and FileValidationResult.
    HTTP 200 even when validation.severity='error' — caller decides whether to proceed.
    """
    result = await db.execute(
        select(InterruptPoint).where(
            InterruptPoint.interrupt_id == interrupt_id,
            InterruptPoint.run_id == run_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail={"code": "interrupt_not_found", "message": "Interrupt not found"})
    if row.status != "waiting":
        raise HTTPException(status_code=409, detail={"code": "interrupt_not_waiting", "message": f"Interrupt is already {row.status}"})

    content = await file.read()

    # Validate file content
    validator = get_validator_service()
    validation = validator.validate(name, content)

    # Upload to artifact store
    artifact_ref = f"runs/{run_id}/interrupts/{interrupt_id}/files/{uuid.uuid4().hex[:8]}_{name}"
    store = get_artifact_store()
    await store.put(artifact_ref, content)

    # Track valid artifact refs on the interrupt row
    current_refs: list[str] = list(row.uploaded_artifact_refs or [])
    current_refs.append(artifact_ref)
    await db.execute(
        update(InterruptPoint)
        .where(InterruptPoint.interrupt_id == interrupt_id)
        .values(uploaded_artifact_refs=current_refs)
    )
    await db.commit()

    return FileUploadResponse(artifact_ref=artifact_ref, validation=validation)


# ── resume ───────────────────────────────────────────────────────────────────


class ResumeResponse(BaseModel):
    interrupt: InterruptPointSchema


@router.post("/{run_id}/interrupts/{interrupt_id}/resume", response_model=ResumeResponse)
async def resume_interrupt(
    run_id: str,
    interrupt_id: str,
    body: InterruptResumeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("intervener")),
) -> ResumeResponse:
    result = await db.execute(
        select(InterruptPoint).where(
            InterruptPoint.interrupt_id == interrupt_id,
            InterruptPoint.run_id == run_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail={"code": "interrupt_not_found", "message": "Interrupt not found"})
    if row.status != "waiting":
        raise HTTPException(status_code=409, detail={"code": "version_mismatch", "message": f"Interrupt is already {row.status}"})

    # Validate apply_to_all_matching constraint
    if body.apply_to_all_matching and body.modified_files:
        raise HTTPException(
            status_code=422,
            detail={"code": "bulk_modify_with_files", "message": "apply_to_all_matching=true requires modified_files to be empty"},
        )

    # Validate artifact_refs came from prior /files uploads for this interrupt
    valid_refs: set[str] = set(row.uploaded_artifact_refs or [])
    if body.modified_files:
        for mf in body.modified_files:
            if mf.artifact_ref not in valid_refs:
                raise HTTPException(
                    status_code=422,
                    detail={"code": "unknown_artifact_ref", "message": f"artifact_ref '{mf.artifact_ref}' was not uploaded for this interrupt"},
                )
        # Re-validate files before resuming
        store = get_artifact_store()
        validator = get_validator_service()
        for mf in body.modified_files:
            content = await store.get(mf.artifact_ref)
            vr = validator.validate(mf.name, content)
            if vr.severity == "error":
                raise HTTPException(
                    status_code=422,
                    detail={"code": "validation_failed", "message": f"File '{mf.name}' failed validation: {vr.message}", "detail": vr.model_dump()},
                )

    now = _utcnow()
    resume_files = [mf.model_dump() for mf in (body.modified_files or [])]
    resume_overrides = body.option_overrides or {}

    # Handle apply_to_all_matching: resolve all waiting interrupts with same function_name
    if body.apply_to_all_matching:
        matching_stmt = select(InterruptPoint).where(
            InterruptPoint.run_id == run_id,
            InterruptPoint.function_name == row.function_name,
            InterruptPoint.status == "waiting",
        )
        matching_result = await db.execute(matching_stmt)
        matching_rows = matching_result.scalars().all()
        for mrow in matching_rows:
            await db.execute(
                update(InterruptPoint)
                .where(InterruptPoint.interrupt_id == mrow.interrupt_id)
                .values(
                    status="resumed",
                    resolved_at=now,
                    resolved_by=current_user.user_id,
                    resume_files=[],
                    resume_overrides=resume_overrides,
                )
            )
            await _publish_resolved(run_id, mrow, current_user.user_id, "resumed")
        await db.commit()
        # Return this interrupt's updated state
        await db.refresh(row)
        return ResumeResponse(interrupt=_row_to_schema(row, include_input_files=True))

    # Single resume
    if body.re_enable_auto:
        # Toggle AutoConfig for this function back to true
        from models.auto_config import AutoConfig as AutoConfigModel
        ac_result = await db.execute(select(AutoConfigModel).where(AutoConfigModel.run_id == run_id))
        ac = ac_result.scalar_one_or_none()
        if ac:
            updated = dict(ac.config)
            updated[row.function_name] = True
            ac.config = updated

    await db.execute(
        update(InterruptPoint)
        .where(InterruptPoint.interrupt_id == interrupt_id)
        .values(
            status="resumed",
            resolved_at=now,
            resolved_by=current_user.user_id,
            resume_files=resume_files,
            resume_overrides=resume_overrides,
        )
    )
    await db.commit()
    await db.refresh(row)

    await _publish_resolved(run_id, row, current_user.user_id, "resumed")

    return ResumeResponse(interrupt=_row_to_schema(row, include_input_files=True))


# ── skip ─────────────────────────────────────────────────────────────────────


class SkipResponse(BaseModel):
    interrupt: InterruptPointSchema


@router.post("/{run_id}/interrupts/{interrupt_id}/skip", response_model=SkipResponse)
async def skip_interrupt(
    run_id: str,
    interrupt_id: str,
    body: InterruptSkipRequest = InterruptSkipRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("intervener")),
) -> SkipResponse:
    result = await db.execute(
        select(InterruptPoint).where(
            InterruptPoint.interrupt_id == interrupt_id,
            InterruptPoint.run_id == run_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail={"code": "interrupt_not_found", "message": "Interrupt not found"})
    if row.status != "waiting":
        raise HTTPException(status_code=409, detail={"code": "interrupt_not_waiting", "message": f"Interrupt is already {row.status}"})

    now = _utcnow()

    if body.apply_to_all_matching:
        matching_stmt = select(InterruptPoint).where(
            InterruptPoint.run_id == run_id,
            InterruptPoint.function_name == row.function_name,
            InterruptPoint.status == "waiting",
        )
        matching_result = await db.execute(matching_stmt)
        for mrow in matching_result.scalars().all():
            await db.execute(
                update(InterruptPoint)
                .where(InterruptPoint.interrupt_id == mrow.interrupt_id)
                .values(status="skipped", resolved_at=now, resolved_by=current_user.user_id)
            )
            await _publish_resolved(run_id, mrow, current_user.user_id, "skipped")
        await db.commit()
        await db.refresh(row)
        return SkipResponse(interrupt=_row_to_schema(row, include_input_files=True))

    await db.execute(
        update(InterruptPoint)
        .where(InterruptPoint.interrupt_id == interrupt_id)
        .values(status="skipped", resolved_at=now, resolved_by=current_user.user_id)
    )
    await db.commit()
    await db.refresh(row)

    await _publish_resolved(run_id, row, current_user.user_id, "skipped")

    return SkipResponse(interrupt=_row_to_schema(row, include_input_files=True))
