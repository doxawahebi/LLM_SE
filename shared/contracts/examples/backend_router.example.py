"""
Example integration of shared contracts on the backend side.

This file shows how a FastAPI router and a Celery task use the generated
Pydantic models. Copy patterns from here when implementing
backend/api/*.py and backend/tasks/*.py.

DO NOT redefine the shared types anywhere else — always import.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import TypeAdapter

# All wire-facing types come from the generated module.
from shared.contracts.sailor_models import (
    ApiError,
    EditHarnessRequest,
    EditSpecRequest,
    ForceOutcomeRequest,
    Phase2Status,
    Run,
    RunCounters,
    RunStatus,
    SSEMessageRunStatusChanged,
    SSEMessageSpecStateChanged,
    Spec,
)


# ─── 1. FastAPI route using shared response_model ──────────────────────
#
# The response_model ensures the response is validated against the
# shared contract; any extra fields are stripped, missing required
# fields raise an error before the response is sent.

router = APIRouter(prefix="/api/runs", tags=["runs"])


@router.get("/{run_id}", response_model=Run)
async def get_run(run_id: str) -> Run:
    """
    Fetch a single run. The response_model=Run binding guarantees the
    response matches the schema exactly — no drift possible.
    """
    # Pretend to fetch from DB
    raise NotImplementedError("query run_service.get_run(run_id)")


# ─── 2. Discriminated-union request body ───────────────────────────────
#
# FastAPI + Pydantic understands the `type` discriminator on the request
# body. Frontend sends `{"type": "edit_harness", ...}` and Pydantic picks
# the right variant; an invalid `type` returns 422 before the handler
# runs.

InterventionRequestBody = Annotated[
    EditHarnessRequest | ForceOutcomeRequest | EditSpecRequest,
    "Discriminated union on `type`",
]


@router.post("/{run_id}/specs/{spec_id}/intervene")
async def intervene(
    run_id: str,
    spec_id: str,
    body: InterventionRequestBody,
) -> dict[str, str]:
    """
    Dispatch by `body.type`. Pydantic guarantees `body` is one of the
    three variants; the `match` is exhaustive at the type level.
    """
    if isinstance(body, EditHarnessRequest):
        # body.artifact is "driver" | "slice" | "assertions"
        # body.contents is the UTF-8 file contents
        # body.base_version is for optimistic concurrency
        return {"applied": "edit_harness", "artifact": body.artifact}

    if isinstance(body, ForceOutcomeRequest):
        if body.outcome == "skip_to_phase3" and not body.witness_ktest_ref:
            raise _api_error(
                status.HTTP_400_BAD_REQUEST,
                code="missing_witness",
                message="witness_ktest_ref is required when outcome=skip_to_phase3",
            )
        return {"applied": "force_outcome", "outcome": body.outcome}

    if isinstance(body, EditSpecRequest):
        return {"applied": "edit_spec"}

    # Pydantic prevents this, but the type checker wants exhaustiveness.
    raise AssertionError("unreachable: discriminated union exhausted")


# ─── 3. Constructing an SSE message (publisher side) ───────────────────
#
# Workers publish via concrete message classes — never raw dicts —
# so Pydantic validates the payload shape at publish time. A malformed
# event raises before it touches the bus.

def publish_run_status_changed(
    publisher,  # whatever your Redis Pub/Sub client is
    topic: str,
    sequence: int,
    run_id: str,
    new_status: RunStatus,
    previous_status: RunStatus,
) -> None:
    msg = SSEMessageRunStatusChanged(
        topic=topic,
        sequence=sequence,
        timestamp=datetime.now(timezone.utc).isoformat(),
        kind="run_status_changed",
        payload={
            "run_id": run_id,
            "status": new_status,
            "previous_status": previous_status,
        },
    )
    publisher.publish(topic, msg.model_dump_json())


def publish_spec_state_changed(publisher, topic: str, sequence: int, spec: Spec) -> None:
    """
    The payload carries a FULL Spec snapshot (not a patch).
    Workers MUST emit the post-transition state, not a delta.
    """
    msg = SSEMessageSpecStateChanged(
        topic=topic,
        sequence=sequence,
        timestamp=datetime.now(timezone.utc).isoformat(),
        kind="spec_state_changed",
        payload={"spec": spec.model_dump()},
    )
    publisher.publish(topic, msg.model_dump_json())


# ─── 4. Parsing incoming SSE messages (consumer side) ──────────────────
#
# Push Service consumes from Redis Pub/Sub and re-validates before
# forwarding to clients. Using a TypeAdapter over the union gives
# us proper discriminated-union parsing.

_sse_adapter: TypeAdapter = TypeAdapter(
    SSEMessageRunStatusChanged
    | SSEMessageSpecStateChanged
    # ... add the other 6 variants when fully wired
)


def parse_sse_message(raw_json: str):
    """
    Returns one of the concrete SSEMessage* types, or raises ValidationError.
    """
    return _sse_adapter.validate_json(raw_json)


# ─── 5. Uniform error handler ──────────────────────────────────────────


def _api_error(http_status: int, *, code: str, message: str, detail: object | None = None):
    """
    Construct an HTTPException whose detail matches the ApiError schema.
    Use this everywhere instead of raw `raise HTTPException(400)`.
    """
    return HTTPException(
        status_code=http_status,
        detail={"code": code, "message": message, "detail": detail},
    )


async def api_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """
    Register this on the FastAPI app:
        app.add_exception_handler(HTTPException, api_error_handler)
    """
    if isinstance(exc.detail, dict):
        body = ApiError(
            code=exc.detail.get("code", "unknown"),
            message=exc.detail.get("message", "An error occurred"),
            detail=exc.detail.get("detail"),
            trace_id=getattr(request.state, "trace_id", None),
        )
    else:
        # Fallback for raw HTTPExceptions someone forgot to convert
        body = ApiError(
            code="unknown",
            message=str(exc.detail),
            trace_id=getattr(request.state, "trace_id", None),
        )
    return JSONResponse(status_code=exc.status_code, content=body.model_dump(mode="json"))


# ─── 6. Counters update example ────────────────────────────────────────
#
# RunCounters has the new authoritative field names (specs_total, etc.).
# Workers MUST use these names; SQL JSONB writes also use these names.

def make_initial_counters() -> RunCounters:
    return RunCounters(
        specs_total=0,
        specs_filtered_out=0,
        specs_emitted=0,
        specs_phase2_queued=0,
        specs_phase2_running=0,
        specs_phase2_bug_triggered=0,
        specs_phase2_inconclusive=0,
        specs_phase2_likely_fp=0,
        specs_phase2_errored=0,
        specs_phase3_queued=0,
        specs_phase3_confirmed=0,
        specs_phase3_rejected=0,
        specs_phase3_errored=0,
        unique_confirmed=0,
        total_llm_tokens=0,
        total_klee_seconds=0,
    )
