"""SSE endpoint — /api/events."""

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from services.auth_service import decode_token, get_user_by_id
from services.event_service import get_event_service
from services.push_service import PushConnection, get_push_service

logger = logging.getLogger("sailor.sse")

router = APIRouter(prefix="/api", tags=["events"])


async def _resolve_token(token: str, db: AsyncSession) -> str | None:
    """Validate JWT from query param and return user_id or None."""
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        user = await get_user_by_id(db, user_id) if user_id else None
        return user.user_id if user else None
    except (JWTError, Exception):
        return None


@router.get("/events")
async def sse_endpoint(
    request: Request,
    topics: str = Query(..., description="Comma-separated topic list"),
    token: str = Query(..., description="JWT bearer token"),
    last_event_id: str | None = Query(None, alias="Last-Event-ID"),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    user_id = await _resolve_token(token, db)
    if not user_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid token")

    topic_list = [t.strip() for t in topics.split(",") if t.strip()]
    push_service = get_push_service()
    event_service = get_event_service()

    conn = PushConnection(topic_list)

    # Replay missed events if Last-Event-ID provided
    if last_event_id:
        try:
            since_seq = int(last_event_id)
            for topic in topic_list:
                missed = await event_service.get_replay_buffer(topic, since_seq)
                if missed:
                    for evt in missed:
                        conn.enqueue(json.dumps(evt))
                else:
                    # Buffer gap — send resync_required
                    resync = json.dumps({
                        "topic": topic,
                        "sequence": 0,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "kind": "resync_required",
                        "payload": {},
                    })
                    conn.enqueue(resync)
        except (ValueError, Exception):
            pass

    push_service.add_connection(conn)

    async def event_generator():  # type: ignore[return]
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(conn.queue.get(), timeout=30.0)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive comment
                    yield ": keepalive\n\n"
        finally:
            push_service.remove_connection(conn)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
