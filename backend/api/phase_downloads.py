"""Phase-level download endpoints — HTTP 302 presigned redirect (300s TTL)."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import require_role
from models.run import Run
from models.spec import Spec
from models.user import User
from services.artifact_service import get_artifact_store

router = APIRouter(prefix="/api/runs", tags=["phase-downloads"])

PRESIGN_TTL = 300


async def _presign(path: str) -> str:
    store = get_artifact_store()
    return await store.presign_get(path, expires=PRESIGN_TTL)


async def _require_run(db: AsyncSession, run_id: str) -> Run:
    result = await db.execute(select(Run).where(Run.run_id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


async def _require_spec(db: AsyncSession, run_id: str, spec_id: str) -> Spec:
    result = await db.execute(
        select(Spec).where(Spec.spec_id == spec_id, Spec.run_id == run_id)
    )
    spec = result.scalar_one_or_none()
    if not spec:
        raise HTTPException(status_code=404, detail="Spec not found")
    return spec


# ── Phase 1 (run-level) ───────────────────────────────────────────────────────

@router.get("/{run_id}/phase1/artifacts")
async def list_phase1_artifacts(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[dict]:
    await _require_run(db, run_id)
    store = get_artifact_store()
    prefix = f"runs/{run_id}/phase1/"
    items = await store.list_prefix(prefix)
    return [{"path": m.path, "size": m.size, "mime_type": m.mime_type} for m in items]


@router.get("/{run_id}/phase1/artifacts/{filename}")
async def download_phase1_artifact(
    run_id: str,
    filename: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> RedirectResponse:
    await _require_run(db, run_id)
    path = f"runs/{run_id}/phase1/{filename}"
    url = await _presign(path)
    return RedirectResponse(url=url, status_code=302)


@router.get("/{run_id}/phase1/artifacts.tar.gz")
async def download_phase1_tarball(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> RedirectResponse:
    await _require_run(db, run_id)
    path = f"runs/{run_id}/exports/phase1_outputs.tar.gz"
    url = await _presign(path)
    return RedirectResponse(url=url, status_code=302)


# ── Phase 2 (spec-level) ──────────────────────────────────────────────────────

@router.get("/{run_id}/specs/{spec_id}/phase2/artifacts")
async def list_phase2_artifacts(
    run_id: str,
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[dict]:
    await _require_spec(db, run_id, spec_id)
    store = get_artifact_store()
    prefix = f"runs/{run_id}/phase2/{spec_id}/"
    items = await store.list_prefix(prefix)
    return [{"path": m.path, "size": m.size, "mime_type": m.mime_type} for m in items]


@router.get("/{run_id}/specs/{spec_id}/phase2/artifacts/{filename}")
async def download_phase2_artifact(
    run_id: str,
    spec_id: str,
    filename: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> RedirectResponse:
    await _require_spec(db, run_id, spec_id)
    path = f"runs/{run_id}/phase2/{spec_id}/{filename}"
    url = await _presign(path)
    return RedirectResponse(url=url, status_code=302)


@router.get("/{run_id}/specs/{spec_id}/phase2/artifacts.tar.gz")
async def download_phase2_tarball(
    run_id: str,
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> RedirectResponse:
    await _require_spec(db, run_id, spec_id)
    path = f"runs/{run_id}/exports/phase2_{spec_id}.tar.gz"
    url = await _presign(path)
    return RedirectResponse(url=url, status_code=302)


# ── Phase 3 (spec-level) ──────────────────────────────────────────────────────

@router.get("/{run_id}/specs/{spec_id}/phase3/artifacts")
async def list_phase3_artifacts(
    run_id: str,
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> list[dict]:
    await _require_spec(db, run_id, spec_id)
    store = get_artifact_store()
    prefix = f"runs/{run_id}/phase3/{spec_id}/"
    items = await store.list_prefix(prefix)
    return [{"path": m.path, "size": m.size, "mime_type": m.mime_type} for m in items]


@router.get("/{run_id}/specs/{spec_id}/phase3/artifacts/{filename}")
async def download_phase3_artifact(
    run_id: str,
    spec_id: str,
    filename: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> RedirectResponse:
    await _require_spec(db, run_id, spec_id)
    path = f"runs/{run_id}/phase3/{spec_id}/{filename}"
    url = await _presign(path)
    return RedirectResponse(url=url, status_code=302)


@router.get("/{run_id}/specs/{spec_id}/phase3/artifacts.tar.gz")
async def download_phase3_tarball(
    run_id: str,
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> RedirectResponse:
    await _require_spec(db, run_id, spec_id)
    path = f"runs/{run_id}/exports/phase3_{spec_id}.tar.gz"
    url = await _presign(path)
    return RedirectResponse(url=url, status_code=302)


# ── Evidence packages ─────────────────────────────────────────────────────────

@router.get("/{run_id}/specs/{spec_id}/evidence.tar.gz")
async def download_evidence_package(
    run_id: str,
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> RedirectResponse:
    await _require_spec(db, run_id, spec_id)
    path = f"runs/{run_id}/exports/evidence-{spec_id}.tar.gz"
    url = await _presign(path)
    return RedirectResponse(url=url, status_code=302)


@router.get("/{run_id}/results/evidence-all.tar.gz")
async def download_all_evidence(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> RedirectResponse:
    await _require_run(db, run_id)
    path = f"runs/{run_id}/exports/all-confirmed.tar.gz"
    url = await _presign(path)
    return RedirectResponse(url=url, status_code=302)
