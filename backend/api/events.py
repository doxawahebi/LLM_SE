"""SSE endpoint — GET /api/events."""

import asyncio
import json
import logging
import re

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from services.auth_service import decode_token, get_user_by_id
from services.event_service import get_event_service
from services.push_service import PushConnection, get_push_service
from shared.contracts.sailor_models import ApiError

logger = logging.getLogger("sailor.sse")

router = APIRouter(prefix="/api", tags=["events"])

# Valid SSE topic pattern (matches SSETopicPattern in schema)
_TOPIC_RE = re.compile(
    r"^runs\.(all|[A-Za-z0-9_-]+(\.(specs|workers|logs)(\.[A-Za-z0-9_-]+(\.logs)?)?)?)$"
)

MAX_TOPICS = 32


def _to_sse_frame(msg_str: str) -> str:
    """Format a JSON message string as an SSE frame with id:, event:, data: lines."""
    try:
        msg = json.loads(msg_str)
        seq = msg.get("sequence", 0)
        kind = msg.get("kind", "message")
        # SSE wire format per sse_contract.md §2.2
        return f"id: {seq}\nevent: {kind}\ndata: {msg_str}\n\n"
    except Exception:
        return f"data: {msg_str}\n\n"


async def _resolve_token(token: str, db: AsyncSession) -> tuple[str | None, str | None]:
    """Validate JWT; return (user_id, role) or (None, None) on failure."""
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        role = payload.get("role", "viewer")
        user = await get_user_by_id(db, user_id) if user_id else None
        if user:
            return user.user_id, user.role
        return None, None
    except (JWTError, Exception):
        return None, None


def _validate_topics(topics: list[str]) -> list[str]:
    """Validate topic patterns; return list or raise HTTPException."""
    from fastapi import HTTPException
    invalid = [t for t in topics if not _TOPIC_RE.match(t)]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_topic", "message": f"Invalid topic(s): {invalid}"},
        )
    return topics


@router.get("/events")
async def sse_endpoint(
    request: Request,
    topics: str = Query(..., description="Comma-separated topic list"),
    token: str = Query(..., description="JWT bearer token"),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    # Auth — must check before opening stream; failures return ApiError JSON
    user_id, user_role = await _resolve_token(token, db)
    if not user_id:
        return JSONResponse(
            status_code=401,
            content=ApiError(code="invalid_token", message="Missing or invalid token").model_dump(),
        )

    topic_list = [t.strip() for t in topics.split(",") if t.strip()]

    if len(topic_list) > MAX_TOPICS:
        return JSONResponse(
            status_code=400,
            content=ApiError(code="too_many_topics", message=f"Maximum {MAX_TOPICS} topics per connection").model_dump(),
        )

    # Validate topic patterns
    for topic in topic_list:
        if not _TOPIC_RE.match(topic):
            return JSONResponse(
                status_code=400,
                content=ApiError(code="invalid_topic", message=f"Invalid topic pattern: '{topic}'").model_dump(),
            )

    # Topic access control: runs.all is admin/operator only
    for topic in topic_list:
        if topic == "runs.all" and user_role not in ("admin", "operator"):
            return JSONResponse(
                status_code=403,
                content=ApiError(code="topic_forbidden", message=f"Topic '{topic}' requires operator or admin role").model_dump(),
            )

    push_service = get_push_service()
    event_service = get_event_service()

    conn = PushConnection(topic_list)

    # Reconnect replay via Last-Event-ID header
    last_event_id_header = request.headers.get("last-event-id") or request.headers.get("Last-Event-ID")
    if last_event_id_header:
        try:
            since_seq = int(last_event_id_header)
        except (ValueError, TypeError):
            since_seq = 0

        for topic in topic_list:
            current_seq = await event_service.get_current_seq(topic)
            buffered = await event_service.get_replay_buffer(topic, since_seq)

            if buffered:
                first_seq = buffered[0].get("sequence", 0)
                if first_seq > since_seq + 1:
                    # Gap in buffer — send resync_required
                    resync_msg = json.dumps({
                        "topic": topic,
                        "sequence": current_seq + 1,
                        "timestamp": _now_iso(),
                        "kind": "resync_required",
                        "payload": {"reason": "buffer_overflow", "last_known_sequence": since_seq},
                    }, separators=(",", ":"))
                    conn.enqueue(resync_msg)
                else:
                    for evt in buffered:
                        conn.enqueue(json.dumps(evt, separators=(",", ":")))
            elif since_seq > 0 and current_seq > since_seq:
                # Buffer empty but we missed events → resync
                resync_msg = json.dumps({
                    "topic": topic,
                    "sequence": current_seq,
                    "timestamp": _now_iso(),
                    "kind": "resync_required",
                    "payload": {"reason": "buffer_overflow", "last_known_sequence": since_seq},
                }, separators=(",", ":"))
                conn.enqueue(resync_msg)

    push_service.add_connection(conn)

    async def event_generator():  # type: ignore[return]
        try:
            keep_alive_counter = 0
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg_str = await asyncio.wait_for(conn.queue.get(), timeout=15.0)
                    yield _to_sse_frame(msg_str)
                    keep_alive_counter = 0
                except asyncio.TimeoutError:
                    # Every 15 seconds emit SSE comment keep-alive per spec §2.3
                    yield ": keep-alive\n\n"
                    keep_alive_counter += 1
        finally:
            push_service.remove_connection(conn)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
