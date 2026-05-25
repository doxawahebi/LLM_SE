"""Trace ID middleware — propagates per-request trace_id."""

import uuid
from contextvars import ContextVar

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

trace_id_var: ContextVar[str] = ContextVar("trace_id", default="")


class TracingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        trace_id = request.headers.get("X-Trace-ID", str(uuid.uuid4()))
        token = trace_id_var.set(trace_id)
        try:
            response = await call_next(request)
            response.headers["X-Trace-ID"] = trace_id
            return response
        finally:
            trace_id_var.reset(token)


def get_trace_id() -> str:
    return trace_id_var.get()
