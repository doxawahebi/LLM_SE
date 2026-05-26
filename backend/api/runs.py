"""Run operations — /api/runs/*."""

import io
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import require_role
from models.user import User
from schemas.run import BuildConfigRequest, CloneRequest, RunConfig, RunCreateResponse, RunDetail, RunSummary
from services.artifact_service import get_artifact_store
from services.audit_service import log_audit
from services.run_service import create_run, get_run, list_runs, transition_run
from tasks.phase1 import phase1_task

router = APIRouter(prefix="/api/runs", tags=["runs"])


@router.post("", response_model=RunCreateResponse)
async def create_run_endpoint(
    name: str = Form(...),
    build_command: str = Form(""),
    codeql_build_mode: str = Form("autodetect"),
    project_zip: UploadFile | None = File(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> RunCreateResponse:
    run_id = str(uuid.uuid4())
    zip_ref: str | None = None

    if project_zip:
        data = await project_zip.read()
        path = f"runs/{run_id}/project.zip"
        store = get_artifact_store()
        await store.put(path, data)
        zip_ref = path

    run = await create_run(
        db,
        name=name,
        build_command=build_command,
        codeql_build_mode=codeql_build_mode,
        config=RunConfig(),
        created_by=user.user_id,
        project_zip_ref=zip_ref,
    )

    # Transition to queued if we have a zip
    if zip_ref:
        await transition_run(db, run.run_id, "queued", ["created"])
        phase1_task.delay(run.run_id)

    await log_audit(db, "run_create", actor=user.user_id, target=f"run:{run.run_id}")
    return RunCreateResponse(run_id=run.run_id, status="queued" if zip_ref else "created")


@router.get("", response_model=list[RunSummary])
async def list_runs_endpoint(
    status_filter: str | None = None,
    page: int = 1,
    page_size: int = 20,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[RunSummary]:
    runs = await list_runs(db, status=status_filter, page=page, page_size=page_size)
    return [
        RunSummary(
            run_id=r.run_id,
            name=r.name,
            status=r.status,
            counters=r.counters or {},
            created_at=r.created_at,
            created_by=r.created_by,
        )
        for r in runs
    ]


@router.get("/{run_id}", response_model=RunDetail)
async def get_run_endpoint(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> RunDetail:
    run = await get_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return RunDetail(
        run_id=run.run_id,
        name=run.name,
        status=run.status,
        counters=run.counters or {},
        created_at=run.created_at,
        created_by=run.created_by,
        project_zip_ref=run.project_zip_ref,
        build_command=run.build_command,
        codeql_build_mode=run.codeql_build_mode,
        config=run.config or {},
        phase1_summary=run.phase1_summary,
        error=run.error,
        started_at=run.started_at,
        completed_at=run.completed_at,
    )


@router.post("/{run_id}/build_config")
async def set_build_config(
    run_id: str,
    body: BuildConfigRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> dict:
    updated = await transition_run(
        db, run_id, "queued", ["needs_build_config"],
        extra={"build_command": body.build_command}
    )
    if not updated:
        run = await get_run(db, run_id)
        raise HTTPException(status_code=409, detail=f"Run status is {run.status if run else 'unknown'}")
    phase1_task.delay(run_id)
    return {"run_id": run_id, "status": "queued"}


@router.post("/{run_id}/pause")
async def pause_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> dict:
    updated = await transition_run(db, run_id, "paused", ["running"])
    if not updated:
        run = await get_run(db, run_id)
        raise HTTPException(status_code=409, detail=f"Cannot pause run in status {run.status if run else 'unknown'}")
    await log_audit(db, "run_pause", actor=user.user_id, target=f"run:{run_id}")
    return {"run_id": run_id, "status": "paused"}


@router.post("/{run_id}/resume")
async def resume_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> dict:
    updated = await transition_run(db, run_id, "running", ["paused"])
    if not updated:
        run = await get_run(db, run_id)
        raise HTTPException(status_code=409, detail=f"Cannot resume run in status {run.status if run else 'unknown'}")
    await log_audit(db, "run_resume", actor=user.user_id, target=f"run:{run_id}")
    # TODO: re-enqueue queued phase2 specs
    return {"run_id": run_id, "status": "running"}


@router.post("/{run_id}/cancel")
async def cancel_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> dict:
    updated = await transition_run(db, run_id, "cancelled", ["running", "paused", "queued"])
    if not updated:
        run = await get_run(db, run_id)
        raise HTTPException(status_code=409, detail=f"Cannot cancel run in status {run.status if run else 'unknown'}")
    await log_audit(db, "run_cancel", actor=user.user_id, target=f"run:{run_id}")
    return {"run_id": run_id, "status": "cancelled"}


@router.post("/{run_id}/clone")
async def clone_run(
    run_id: str,
    body: CloneRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> RunCreateResponse:
    original = await get_run(db, run_id)
    if not original:
        raise HTTPException(status_code=404, detail="Run not found")
    new_run = await create_run(
        db,
        name=f"{original.name} (clone)",
        build_command=original.build_command or "",
        codeql_build_mode=original.codeql_build_mode,
        config=body.config or RunConfig(),
        created_by=user.user_id,
        project_zip_ref=original.project_zip_ref,
    )
    if original.project_zip_ref:
        await transition_run(db, new_run.run_id, "queued", ["created"])
    return RunCreateResponse(run_id=new_run.run_id, status=new_run.status)


@router.delete("/{run_id}")
async def delete_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("operator")),
) -> dict:
    # Soft delete — archive
    updated = await transition_run(db, run_id, "archived", ["completed", "failed", "cancelled"])
    if not updated:
        raise HTTPException(status_code=409, detail="Can only archive completed/failed/cancelled runs")
    return {"run_id": run_id, "status": "archived"}
