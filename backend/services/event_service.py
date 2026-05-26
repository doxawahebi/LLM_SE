"""Event service — publishes SSEMessage* models to Redis Pub/Sub."""

import asyncio
import json
import logging
import time
from datetime import datetime
from functools import lru_cache
from typing import Any

import redis.asyncio as aioredis
from pydantic import BaseModel

from config import settings

logger = logging.getLogger("sailor.event_service")

# Per-run throttle state for run_counters_updated (≤ 1/s per run)
_counter_throttle: dict[str, float] = {}
_counter_flush_tasks: dict[str, asyncio.Task] = {}

# Sorted-set TTL (seconds) — 2× the 60s replay window for safety
_BUF_TTL = 120


class EventService:
    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._redis: aioredis.Redis | None = None

    async def connect(self) -> None:
        self._redis = aioredis.from_url(self._redis_url, decode_responses=True)

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()

    async def _next_seq(self, topic: str) -> int:
        """Atomic per-topic sequence counter in Redis."""
        if not self._redis:
            return 0
        val = await self._redis.incr(f"sailor:seq:{topic}")
        return int(val)

    async def publish_message(self, msg: BaseModel) -> None:
        """Publish a concrete SSEMessage* Pydantic model.

        Publishers MUST pass a typed model (SSEMessageRunStatusChanged, etc.)
        so Pydantic validation runs at publish time, not at deserialize time.
        The sequence field is overwritten by the atomic Redis counter.
        """
        if not self._redis:
            return
        topic: str = getattr(msg, "topic")  # all SSEMessage* have .topic
        seq = await self._next_seq(topic)

        # Build final JSON with correct sequence
        msg_dict: dict[str, Any] = json.loads(msg.model_dump_json())
        msg_dict["sequence"] = seq
        # Single-line JSON (no embedded newlines) per SSE wire format §2.2
        msg_str = json.dumps(msg_dict, separators=(",", ":"))

        # Publish to Redis Pub/Sub
        await self._redis.publish(f"sailor:{topic}", msg_str)

        # Replay buffer: sorted set scored by sequence
        buf_key = f"sailor:buf:{topic}"
        await self._redis.zadd(buf_key, {msg_str: seq})
        # Trim entries that are too old (keep last 10 000 sequences as a safety cap)
        if seq > 10000:
            await self._redis.zremrangebyscore(buf_key, "-inf", seq - 10000)
        await self._redis.expire(buf_key, _BUF_TTL)

    async def publish_counter_update(self, run_id: str, counters_payload: BaseModel) -> None:
        """Throttled publish of run_counters_updated (≤ 1/s per run)."""
        now = time.monotonic()
        last = _counter_throttle.get(run_id, 0.0)
        if now - last < 1.0:
            return
        _counter_throttle[run_id] = now
        await self.publish_message(counters_payload)

    async def publish_counters_throttled(self, run_id: str, counters: dict[str, Any]) -> None:
        """Publish run_counters_updated at most once per second per run.

        Schedules a deferred flush if suppressed, so the last counter state
        is always eventually published.
        """
        now = time.monotonic()
        last = _counter_throttle.get(run_id, 0.0)
        if now - last >= 1.0:
            _counter_throttle[run_id] = now
            await self._do_publish_counters(run_id, counters)
        else:
            # Deferred flush — at most one pending task per run
            existing = _counter_flush_tasks.get(run_id)
            if existing is None or existing.done():
                async def _flush(r: str = run_id, c: dict = dict(counters)) -> None:
                    await asyncio.sleep(1.0)
                    _counter_throttle[r] = time.monotonic()
                    await self._do_publish_counters(r, c)
                _counter_flush_tasks[run_id] = asyncio.create_task(_flush())

    async def _do_publish_counters(self, run_id: str, counters: dict[str, Any]) -> None:
        """Actually publish run_counters_updated."""
        try:
            from shared.contracts.sailor_models import (
                RunCountersUpdatedPayload,
                SSEMessageRunCountersUpdated,
                RunCounters,
            )
            # Fill all required fields with 0 defaults; caller may provide a partial dict
            rc_fields = {k: 0 for k in RunCounters.model_fields}
            rc_fields.update(counters or {})
            rc = RunCounters(**rc_fields)
            payload = RunCountersUpdatedPayload(run_id=run_id, counters=rc)
            msg = SSEMessageRunCountersUpdated(
                topic=f"runs.{run_id}",
                sequence=0,
                timestamp=datetime.utcnow().isoformat() + "Z",
                kind="run_counters_updated",
                payload=payload,
            )
            await self.publish_message(msg)
        except Exception as exc:
            logger.debug("publish_counters failed: %s", exc)

    async def publish_run_status_changed(
        self, run_id: str, status: str, previous_status: str | None = None
    ) -> None:
        """Publish run_status_changed SSE."""
        try:
            from shared.contracts.sailor_models import (
                RunStatus,
                RunStatusChangedPayload,
                SSEMessageRunStatusChanged,
            )
            payload = RunStatusChangedPayload(
                run_id=run_id,
                status=RunStatus(status),
                previous_status=RunStatus(previous_status) if previous_status else None,
            )
            msg = SSEMessageRunStatusChanged(
                topic=f"runs.{run_id}",
                sequence=0,
                timestamp=datetime.utcnow().isoformat() + "Z",
                kind="run_status_changed",
                payload=payload,
            )
            await self.publish_message(msg)
        except Exception as exc:
            logger.debug("publish_run_status_changed failed: %s", exc)

    async def publish_spec_state_changed(
        self, run_id: str, spec_id: str, spec_data: dict[str, Any] | None = None
    ) -> None:
        """Publish spec_state_changed SSE to both run-level and spec-level topics."""
        try:
            from shared.contracts.sailor_models import (
                Spec as SpecModel,
                SpecStateChangedPayload,
                SSEMessageSpecStateChanged,
            )
            if spec_data is None:
                return
            spec_model = SpecModel(**spec_data)
            payload = SpecStateChangedPayload(spec=spec_model)
            now = datetime.utcnow().isoformat() + "Z"
            for topic in [f"runs.{run_id}.specs", f"runs.{run_id}.specs.{spec_id}"]:
                msg = SSEMessageSpecStateChanged(
                    topic=topic,
                    sequence=0,
                    timestamp=now,
                    kind="spec_state_changed",
                    payload=payload,
                )
                await self.publish_message(msg)
        except Exception as exc:
            logger.debug("publish_spec_state_changed failed: %s", exc)

    async def publish_turn_appended(
        self, run_id: str, spec_id: str, turn_number: int, turn_id: str
    ) -> None:
        """Publish turn_appended SSE."""
        try:
            from shared.contracts.sailor_models import (
                SSEMessageTurnAppended,
                TurnAppendedPayload,
            )
            payload = TurnAppendedPayload(spec_id=spec_id, turn_number=turn_number, turn_id=turn_id)
            msg = SSEMessageTurnAppended(
                topic=f"runs.{run_id}.specs.{spec_id}",
                sequence=0,
                timestamp=datetime.utcnow().isoformat() + "Z",
                kind="turn_appended",
                payload=payload,
            )
            await self.publish_message(msg)
        except Exception as exc:
            logger.debug("publish_turn_appended failed: %s", exc)

    async def publish_worker_heartbeat(
        self,
        run_id: str,
        worker_id: str,
        status: str,
        current_spec_id: str | None = None,
    ) -> None:
        """Publish worker_heartbeat SSE."""
        try:
            from shared.contracts.sailor_models import (
                SSEMessageWorkerHeartbeat,
                WorkerHeartbeatPayload,
            )
            payload = WorkerHeartbeatPayload(
                worker_id=worker_id,
                run_id=run_id,
                status=status,
                current_spec_id=current_spec_id,
                last_heartbeat=datetime.utcnow().isoformat() + "Z",
                throughput_specs_per_min=0.0,
                tokens_per_min=0,
                klee_seconds_per_min=0.0,
            )
            msg = SSEMessageWorkerHeartbeat(
                topic=f"runs.{run_id}.workers",
                sequence=0,
                timestamp=datetime.utcnow().isoformat() + "Z",
                kind="worker_heartbeat",
                payload=payload,
            )
            await self.publish_message(msg)
        except Exception as exc:
            logger.debug("publish_worker_heartbeat failed: %s", exc)

    async def publish_log_line(
        self,
        run_id: str,
        spec_id: str | None,
        source: str,
        level: str,
        message: str,
        worker_id: str,
        fields: dict[str, Any] | None = None,
    ) -> None:
        """Publish log_line SSE."""
        try:
            from shared.contracts.sailor_models import (
                LogLinePayload,
                SSEMessageLogLine,
            )
            topic = f"runs.{run_id}.specs.{spec_id}.logs" if spec_id else f"runs.{run_id}"
            payload = LogLinePayload(
                timestamp=datetime.utcnow().isoformat() + "Z",
                level=level,
                source=source,
                run_id=run_id,
                spec_id=spec_id,
                worker_id=worker_id,
                message=message,
                fields=fields or {},
            )
            msg = SSEMessageLogLine(
                topic=topic,
                sequence=0,
                timestamp=datetime.utcnow().isoformat() + "Z",
                kind="log_line",
                payload=payload,
            )
            await self.publish_message(msg)
        except Exception as exc:
            logger.debug("publish_log_line failed: %s", exc)

    async def get_replay_buffer(self, topic: str, since_seq: int) -> list[dict[str, Any]]:
        """Return all events with sequence > since_seq from the sorted-set buffer."""
        if not self._redis:
            return []
        buf_key = f"sailor:buf:{topic}"
        # ZRANGEBYSCORE: sequences strictly greater than since_seq
        raw: list[str] = await self._redis.zrangebyscore(buf_key, since_seq + 1, "+inf")
        return [json.loads(r) for r in raw]

    async def get_current_seq(self, topic: str) -> int:
        """Return the current sequence counter for a topic."""
        if not self._redis:
            return 0
        val = await self._redis.get(f"sailor:seq:{topic}")
        return int(val) if val else 0


@lru_cache(maxsize=1)
def get_event_service() -> EventService:
    return EventService(settings.redis_url)
