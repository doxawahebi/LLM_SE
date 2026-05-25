"""Health and metrics endpoints."""

import time

from fastapi import APIRouter
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

from config import settings

router = APIRouter()

# Prometheus metrics
api_requests_total = Counter("sailor_api_requests_total", "Total API requests", ["method", "path", "status"])
api_request_duration = Histogram("sailor_api_request_duration_seconds", "API request duration", ["method", "path"])
runs_total = Counter("sailor_runs_total", "Runs by status", ["status"])
specs_total = Counter("sailor_specs_total", "Specs by phase and status", ["phase", "status"])
llm_tokens_total = Counter("sailor_llm_tokens_total", "LLM tokens used", ["provider", "model"])
klee_seconds_total = Counter("sailor_klee_seconds_total", "KLEE CPU seconds")


@router.get("/api/health")
async def health() -> dict:
    components: dict[str, str] = {}
    # DB
    try:
        from database import engine
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        components["state_store"] = "ok"
    except Exception:
        components["state_store"] = "down"

    # Redis
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
        components["event_bus"] = "ok"
        components["task_queue"] = "ok"
    except Exception:
        components["event_bus"] = "down"
        components["task_queue"] = "down"

    # MinIO
    try:
        import boto3
        client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            region_name="us-east-1",
        )
        client.list_buckets()
        components["artifact_store"] = "ok"
    except Exception:
        components["artifact_store"] = "down"

    overall = "ok" if all(v == "ok" for v in components.values()) else "degraded"
    return {"status": overall, "components": components}


@router.get("/api/metrics")
async def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
