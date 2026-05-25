"""Artifact download and export endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import require_role
from models.user import User
from services.artifact_service import get_artifact_store
from services.export_service import create_export_job, get_export_job
from services.spec_service import get_spec

router = APIRouter(prefix="/api/runs/{run_id}/specs/{spec_id}", tags=["artifacts"])
jobs_router = APIRouter(prefix="/api/jobs", tags=["jobs"])


@router.get("/artifacts")
async def list_artifacts(
    run_id: str,
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[dict]:
    spec = await get_spec(db, spec_id)
    if not spec or spec.run_id != run_id:
        raise HTTPException(status_code=404, detail="Spec not found")
    prefix = spec.artifacts_root or f"runs/{run_id}/phase2/{spec_id}/"
    store = get_artifact_store()
    items = await store.list_prefix(prefix)
    return [
        {
            "path": item.path,
            "size": item.size,
            "mime_type": item.mime_type,
            "created_at": item.created_at.isoformat(),
        }
        for item in items
    ]


@router.get("/artifacts/{path:path}")
async def get_artifact(
    run_id: str,
    spec_id: str,
    path: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> RedirectResponse:
    spec = await get_spec(db, spec_id)
    if not spec or spec.run_id != run_id:
        raise HTTPException(status_code=403, detail="Access denied")
    full_path = f"runs/{run_id}/{path}" if not path.startswith("runs/") else path
    store = get_artifact_store()
    if not await store.exists(full_path):
        raise HTTPException(status_code=404, detail="Artifact not found")
    url = await store.presign_get(full_path)
    return RedirectResponse(url=url)


@router.post("/artifacts.tar.gz")
async def export_spec_artifacts(
    run_id: str,
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> dict:
    job = await create_export_job(db, run_id=run_id, spec_ids=[spec_id], export_type="spec_evidence")
    # TODO: enqueue export_task(job.job_id)
    return {"job_id": job.job_id, "status": "pending"}


@jobs_router.get("/{job_id}")
async def get_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> dict:
    job = await get_export_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "job_id": job.job_id,
        "status": job.status,
        "artifact_ref": job.artifact_ref,
        "error": job.error,
    }
