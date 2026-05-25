"""Auto/Manual mode configuration endpoints — /api/runs/:run_id/auto-config."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import require_role
from models.auto_config import DEFAULT_AUTO_CONFIG, AutoConfig
from models.run import Run
from models.user import User

router = APIRouter(prefix="/api/runs", tags=["auto-config"])


async def _get_or_create_auto_config(db: AsyncSession, run_id: str) -> AutoConfig:
    result = await db.execute(select(AutoConfig).where(AutoConfig.run_id == run_id))
    cfg = result.scalar_one_or_none()
    if not cfg:
        cfg = AutoConfig(run_id=run_id, config=dict(DEFAULT_AUTO_CONFIG))
        db.add(cfg)
        await db.commit()
        await db.refresh(cfg)
    return cfg


@router.get("/{run_id}/auto-config")
async def get_auto_config(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> dict:
    run_result = await db.execute(select(Run).where(Run.run_id == run_id))
    if not run_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Run not found")
    cfg = await _get_or_create_auto_config(db, run_id)
    merged = {**DEFAULT_AUTO_CONFIG, **cfg.config}
    return {
        "run_id": run_id,
        "phase1": {k.removeprefix("phase1."): v for k, v in merged.items() if k.startswith("phase1.")},
        "phase2": {k.removeprefix("phase2."): v for k, v in merged.items() if k.startswith("phase2.")},
        "phase3": {k.removeprefix("phase3."): v for k, v in merged.items() if k.startswith("phase3.")},
    }


@router.patch("/{run_id}/auto-config")
async def patch_auto_config(
    run_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("operator")),
) -> dict:
    run_result = await db.execute(select(Run).where(Run.run_id == run_id))
    if not run_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Run not found")

    valid_keys = set(DEFAULT_AUTO_CONFIG.keys())
    for key in body:
        if key not in valid_keys:
            raise HTTPException(status_code=400, detail=f"Unknown auto-config key: {key}")
        if not isinstance(body[key], bool):
            raise HTTPException(status_code=400, detail=f"Value for {key} must be a boolean")

    cfg = await _get_or_create_auto_config(db, run_id)
    updated = {**cfg.config, **body}
    cfg.config = updated
    await db.commit()
    await db.refresh(cfg)

    merged = {**DEFAULT_AUTO_CONFIG, **cfg.config}
    return {
        "run_id": run_id,
        "phase1": {k.removeprefix("phase1."): v for k, v in merged.items() if k.startswith("phase1.")},
        "phase2": {k.removeprefix("phase2."): v for k, v in merged.items() if k.startswith("phase2.")},
        "phase3": {k.removeprefix("phase3."): v for k, v in merged.items() if k.startswith("phase3.")},
    }
