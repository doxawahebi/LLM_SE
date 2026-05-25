"""Idempotency-Key middleware — caches POST responses in Redis."""

import json
from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from config import settings

IDEMPOTENCY_TTL = 86400  # 24 hours


class IdempotencyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._redis = aioredis.from_url(settings.redis_url, decode_responses=True)

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        if request.method != "POST":
            return await call_next(request)
        idem_key = request.headers.get("Idempotency-Key")
        if not idem_key:
            return await call_next(request)

        # Try to extract user identity from token (best-effort)
        user_id = "anon"
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            try:
                from services.auth_service import decode_token

                payload = decode_token(auth[7:])
                user_id = payload.get("sub", "anon")
            except Exception:
                pass

        cache_key = f"sailor:idem:{user_id}:{request.url.path}:{idem_key}"
        cached = await self._redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            return JSONResponse(content=data["body"], status_code=data["status_code"])

        response = await call_next(request)

        if 200 <= response.status_code < 300:
            # Reconstruct body bytes
            body_bytes = b""
            async for chunk in response.body_iterator:
                body_bytes += chunk
            try:
                body_json = json.loads(body_bytes)
                await self._redis.setex(
                    cache_key,
                    IDEMPOTENCY_TTL,
                    json.dumps({"body": body_json, "status_code": response.status_code}),
                )
            except Exception:
                pass
            return Response(
                content=body_bytes,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )
        return response
