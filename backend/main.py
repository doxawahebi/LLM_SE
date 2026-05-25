"""Sailor backend — FastAPI application factory with lifespan."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api import artifacts, auth, auto_config, events, health, interrupts, logs, phase_downloads, results, runs, settings, specs, validate, workers
from middleware.idempotency import IdempotencyMiddleware
from middleware.tracing import TracingMiddleware
from services.event_service import get_event_service
from services.push_service import get_push_service

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sailor.api")


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    # Startup
    event_service = get_event_service()
    await event_service.connect()

    push_service = get_push_service()
    await push_service.start()

    logger.info("Sailor API started")
    yield

    # Shutdown
    await event_service.close()
    await push_service.stop()
    logger.info("Sailor API shutdown")


app = FastAPI(title="Sailor API", version="1.0.0", lifespan=lifespan)

# Middleware (order matters — outermost runs first)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(TracingMiddleware)
app.add_middleware(IdempotencyMiddleware)

# Routers
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(auth.users_router)
app.include_router(runs.router)
app.include_router(specs.router)
app.include_router(artifacts.router)
app.include_router(artifacts.jobs_router)
app.include_router(results.router)
app.include_router(logs.router)
app.include_router(workers.router)
app.include_router(settings.router)
app.include_router(events.router)
app.include_router(auto_config.router)
app.include_router(interrupts.router)
app.include_router(validate.router)
app.include_router(phase_downloads.router)
