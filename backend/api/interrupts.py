"""Interrupt panel state endpoints — /api/runs/:run_id/interrupts/*."""

import base64
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import require_role
from models.interrupt_point import InterruptPoint
from models.run import Run
from models.user import User
from services.artifact_service import get_artifact_store

router = APIRouter(prefix="/api/runs", tags=["interrupts"])


class ModifiedFile(BaseModel):
    name: str
    content_base64: str


class ResumeRequest(BaseModel):
    modified_files: list[ModifiedFile] = []
    option_overrides: dict = {}


@router.get("/{run_id}/interrupts")
async def list_interrupts(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[dict]:
    run_result = await db.execute(select(Run).where(Run.run_id == run_id))
    if not run_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Run not found")

    result = await db.execute(
        select(InterruptPoint)
        .where(InterruptPoint.run_id == run_id, InterruptPoint.status == "waiting")
        .order_by(InterruptPoint.created_at)
    )
    points = result.scalars().all()
    return [_interrupt_summary(p) for p in points]


@router.get("/{run_id}/interrupts/{interrupt_id}")
async def get_interrupt(
    run_id: str,
    interrupt_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> dict:
    result = await db.execute(
        select(InterruptPoint).where(
            InterruptPoint.interrupt_id == interrupt_id,
            InterruptPoint.run_id == run_id,
        )
    )
    point = result.scalar_one_or_none()
    if not point:
        raise HTTPException(status_code=404, detail="Interrupt not found")

    store = get_artifact_store()
    files_with_urls = []
    for f in (point.modified_files or []):
        artifact_path = f.get("artifact_path", "")
        presigned = ""
        if artifact_path:
            try:
                presigned = await store.presign_get(artifact_path)
            except Exception:
                pass
        files_with_urls.append({**f, "presigned_url": presigned})

    return {
        **_interrupt_summary(point),
        "modified_files": files_with_urls,
        "option_overrides": point.option_overrides or {},
    }


@router.post("/{run_id}/interrupts/{interrupt_id}/resume", status_code=200)
async def resume_interrupt(
    run_id: str,
    interrupt_id: str,
    body: ResumeRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("intervener")),
) -> dict:
    result = await db.execute(
        select(InterruptPoint).where(
            InterruptPoint.interrupt_id == interrupt_id,
            InterruptPoint.run_id == run_id,
        )
    )
    point = result.scalar_one_or_none()
    if not point:
        raise HTTPException(status_code=404, detail="Interrupt not found")
    if point.status != "waiting":
        raise HTTPException(status_code=409, detail=f"Interrupt is already {point.status}")

    # Write modified files to artifact store
    store = get_artifact_store()
    stored_files = []
    for mf in body.modified_files:
        content = base64.b64decode(mf.content_base64)
        artifact_path = f"runs/{run_id}/interrupts/{interrupt_id}/{mf.name}"
        await store.put(artifact_path, content)
        stored_files.append({"name": mf.name, "artifact_path": artifact_path})

    await db.execute(
        update(InterruptPoint)
        .where(InterruptPoint.interrupt_id == interrupt_id)
        .values(
            status="resumed",
            resumed_at=datetime.utcnow(),
            modified_files=stored_files,
            option_overrides=body.option_overrides,
        )
    )
    await db.commit()
    return {"interrupt_id": interrupt_id, "status": "resumed"}


@router.post("/{run_id}/interrupts/{interrupt_id}/skip", status_code=200)
async def skip_interrupt(
    run_id: str,
    interrupt_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("intervener")),
) -> dict:
    result = await db.execute(
        select(InterruptPoint).where(
            InterruptPoint.interrupt_id == interrupt_id,
            InterruptPoint.run_id == run_id,
        )
    )
    point = result.scalar_one_or_none()
    if not point:
        raise HTTPException(status_code=404, detail="Interrupt not found")
    if point.status != "waiting":
        raise HTTPException(status_code=409, detail=f"Interrupt is already {point.status}")

    await db.execute(
        update(InterruptPoint)
        .where(InterruptPoint.interrupt_id == interrupt_id)
        .values(status="skipped")
    )
    await db.commit()
    return {"interrupt_id": interrupt_id, "status": "skipped"}


def _interrupt_summary(point: InterruptPoint) -> dict:
    return {
        "interrupt_id": point.interrupt_id,
        "run_id": point.run_id,
        "spec_id": point.spec_id,
        "function_name": point.function_name,
        "phase": point.phase,
        "turn": point.turn,
        "status": point.status,
        "created_at": point.created_at.isoformat() if point.created_at else None,
        "resumed_at": point.resumed_at.isoformat() if point.resumed_at else None,
    }
