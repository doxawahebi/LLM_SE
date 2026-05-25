"""Settings and audit log endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import require_role
from models.audit import AuditEvent
from models.user import User
from schemas.settings import SettingsData, SettingsPatch

router = APIRouter(prefix="/api/settings", tags=["settings"])


async def _get_or_create_settings(db: AsyncSession) -> dict:
    result = await db.execute(text("SELECT data FROM settings ORDER BY id LIMIT 1"))
    row = result.fetchone()
    if row:
        return row[0] or {}
    await db.execute(text("INSERT INTO settings (data) VALUES ('{}')"))
    await db.commit()
    return {}


@router.get("", response_model=SettingsData)
async def get_settings(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> SettingsData:
    data = await _get_or_create_settings(db)
    return SettingsData(**{k: v for k, v in data.items() if k in SettingsData.model_fields})


@router.patch("")
async def update_settings(
    body: SettingsPatch,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> SettingsData:
    data = await _get_or_create_settings(db)
    patch = body.model_dump(exclude_none=True)

    # Handle secret keys — store only last-4
    for key_field in ("anthropic_api_key", "gemini_api_key"):
        if key_field in patch:
            val = patch.pop(key_field)
            data[f"{key_field}_last4"] = val[-4:] if val else ""

    data.update(patch)
    await db.execute(
        text("UPDATE settings SET data = :data::jsonb WHERE id = (SELECT id FROM settings ORDER BY id LIMIT 1)"),
        {"data": __import__("json").dumps(data)},
    )
    await db.commit()
    return SettingsData(**{k: v for k, v in data.items() if k in SettingsData.model_fields})


@router.get("/audit")
async def get_audit_log(
    actor: str | None = None,
    action: str | None = None,
    target: str | None = None,
    page: int = 1,
    page_size: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> list[dict]:
    q = select(AuditEvent)
    if actor:
        q = q.where(AuditEvent.actor == actor)
    if action:
        q = q.where(AuditEvent.action == action)
    if target:
        q = q.where(AuditEvent.target == target)
    q = q.order_by(AuditEvent.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    events = result.scalars().all()
    return [
        {
            "event_id": e.event_id,
            "actor": e.actor,
            "action": e.action,
            "target": e.target,
            "diff": e.diff,
            "created_at": e.created_at.isoformat(),
        }
        for e in events
    ]
