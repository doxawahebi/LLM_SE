"""Auto/Manual mode configuration endpoints — /api/runs/:run_id/auto-config."""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import get_current_user, require_role
from models.auto_config import AutoConfig, VALID_FUNCTION_IDS
from models.run import Run
from models.user import User
from services.event_service import get_event_service
from shared.contracts.sailor_models import (
    AutoConfig as AutoConfigSchema,
    AutoConfigChangedPayload,
    AutoConfigPatch,
    SSEMessageAutoConfigChanged,
)

router = APIRouter(prefix="/api/runs", tags=["auto-config"])


async def _get_or_create_auto_config(db: AsyncSession, run_id: str) -> AutoConfig:
    result = await db.execute(select(AutoConfig).where(AutoConfig.run_id == run_id))
    cfg = result.scalar_one_or_none()
    if not cfg:
        cfg = AutoConfig(run_id=run_id, config={})
        db.add(cfg)
        await db.commit()
        await db.refresh(cfg)
    return cfg


def _row_to_schema(cfg: AutoConfig) -> AutoConfigSchema:
    """Convert ORM row to AutoConfig schema (only explicitly-set keys)."""
    return AutoConfigSchema(**cfg.config)


@router.get("/{run_id}/auto-config", response_model=AutoConfigSchema)
async def get_auto_config(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("viewer")),
) -> AutoConfigSchema:
    run_result = await db.execute(select(Run).where(Run.run_id == run_id))
    if not run_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail={"code": "run_not_found", "message": "Run not found"})
    cfg = await _get_or_create_auto_config(db, run_id)
    return _row_to_schema(cfg)


@router.patch("/{run_id}/auto-config", response_model=AutoConfigSchema)
async def patch_auto_config(
    run_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("operator")),
) -> AutoConfigSchema:
    run_result = await db.execute(select(Run).where(Run.run_id == run_id))
    if not run_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail={"code": "run_not_found", "message": "Run not found"})

    try:
        raw: dict = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail={"code": "invalid_body", "message": "Request body must be JSON"})

    # Reject any key containing a dot per spec
    for key in raw:
        if "." in str(key):
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_function_name", "message": f"Key '{key}' contains a dot; use flat snake_case PipelineFunctionId values (e.g. 'phase2_klee_execution')"},
            )

    # Validate against AutoConfigPatch (Pydantic rejects unknown keys via extra="forbid")
    try:
        patch = AutoConfigPatch(**raw)
    except Exception as exc:
        raise HTTPException(status_code=422, detail={"code": "invalid_function_name", "message": str(exc)})

    cfg = await _get_or_create_auto_config(db, run_id)
    # Merge: only store explicitly-set keys
    updated = dict(cfg.config)
    for field, value in patch.model_dump(exclude_none=True).items():
        if value is not None:
            updated[field] = value
    cfg.config = updated
    await db.commit()
    await db.refresh(cfg)

    result_schema = _row_to_schema(cfg)

    # Publish SSEMessageAutoConfigChanged
    event_service = get_event_service()
    msg = SSEMessageAutoConfigChanged(
        topic=f"runs.{run_id}",
        sequence=0,  # overwritten by event_service
        timestamp=datetime.now(timezone.utc),
        kind="auto_config_changed",
        payload=AutoConfigChangedPayload(
            run_id=run_id,
            auto_config=result_schema,
            changed_by=current_user.user_id,
        ),
    )
    await event_service.publish_message(msg)

    return result_schema
