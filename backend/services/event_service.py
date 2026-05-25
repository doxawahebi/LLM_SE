"""Event service — publishes to Redis Pub/Sub."""

import asyncio
import json
import time
from datetime import datetime, timezone
from functools import lru_cache

import redis.asyncio as aioredis

from config import settings

# Per-run throttle state for RunCountersUpdated (≤ 1/s per run)
_counter_throttle: dict[str, float] = {}


class EventService:
    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._redis: aioredis.Redis | None = None
        # In-memory sequence counters per topic (could be Redis INCR in prod)
        self._sequences: dict[str, int] = {}

    async def connect(self) -> None:
        self._redis = aioredis.from_url(self._redis_url, decode_responses=True)

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()

    def _next_seq(self, topic: str) -> int:
        self._sequences[topic] = self._sequences.get(topic, 0) + 1
        return self._sequences[topic]

    async def publish(self, topic: str, kind: str, payload: dict) -> None:
        if not self._redis:
            return
        seq = self._next_seq(topic)
        msg = {
            "topic": topic,
            "sequence": seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "payload": payload,
        }
        msg_str = json.dumps(msg)
        await self._redis.publish(f"sailor:{topic}", msg_str)
        # Keep 60-second replay buffer: LPUSH + expire
        buf_key = f"sailor:buf:{topic}"
        await self._redis.lpush(buf_key, msg_str)
        await self._redis.ltrim(buf_key, 0, 999)  # cap at 1000 events
        await self._redis.expire(buf_key, 60)

    async def publish_counter_update(self, run_id: str, counters: dict) -> None:
        """Throttled to ≤ 1 per second per run."""
        now = time.monotonic()
        last = _counter_throttle.get(run_id, 0.0)
        if now - last < 1.0:
            return
        _counter_throttle[run_id] = now
        await self.publish(f"runs.{run_id}", "counter_diff", {"counters": counters})

    async def get_replay_buffer(self, topic: str, since_seq: int) -> list[dict]:
        """Return events since_seq from Redis buffer."""
        if not self._redis:
            return []
        buf_key = f"sailor:buf:{topic}"
        raw = await self._redis.lrange(buf_key, 0, -1)
        events = [json.loads(r) for r in reversed(raw)]
        return [e for e in events if e.get("sequence", 0) > since_seq]


@lru_cache(maxsize=1)
def get_event_service() -> EventService:
    return EventService(settings.redis_url)
