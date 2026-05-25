"""Audit event writer."""

import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from models.audit import AuditEvent


async def log_audit(
    db: AsyncSession,
    action: str,
    actor: str | None = None,
    target: str | None = None,
    diff: dict | None = None,
) -> None:
    event = AuditEvent(
        event_id=str(uuid.uuid4()),
        actor=actor,
        action=action,
        target=target,
        diff=diff,
    )
    db.add(event)
    await db.commit()
