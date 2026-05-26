"""Push service — SSE fan-out with 250ms batching."""

import asyncio
import json
import logging
from collections import defaultdict

import redis.asyncio as aioredis

from config import settings

logger = logging.getLogger("sailor.push")

MAX_QUEUE_BYTES = 1024 * 1024  # 1 MB per connection


class PushConnection:
    """Represents a single SSE client connection."""

    def __init__(self, topics: list[str]) -> None:
        self.topics = set(topics)
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._bytes = 0

    def enqueue(self, msg: str) -> bool:
        """Return False if buffer limit exceeded (caller should drop connection)."""
        self._bytes += len(msg)
        if self._bytes > MAX_QUEUE_BYTES:
            return False
        self.queue.put_nowait(msg)
        return True


class PushService:
    def __init__(self) -> None:
        self._connections: list[PushConnection] = []
        self._redis: aioredis.Redis | None = None
        self._pubsub: aioredis.client.PubSub | None = None
        self._running = False

    async def start(self) -> None:
        self._redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        self._pubsub = self._redis.pubsub()
        await self._pubsub.psubscribe("sailor:*")
        self._running = True
        asyncio.create_task(self._reader_loop())

    async def stop(self) -> None:
        self._running = False
        if self._pubsub:
            await self._pubsub.unsubscribe()
        if self._redis:
            await self._redis.aclose()

    async def _reader_loop(self) -> None:
        if not self._pubsub:
            return
        # Buffer: topic → list of pending messages
        pending: dict[str, list[str]] = defaultdict(list)
        last_flush = asyncio.get_event_loop().time()

        while self._running:
            # Drain available messages non-blocking
            try:
                msg = await asyncio.wait_for(self._pubsub.get_message(ignore_subscribe_messages=True), timeout=0.05)
                if msg and msg["type"] == "pmessage":
                    # Channel: "sailor:<topic>"
                    channel = msg["channel"]
                    topic = channel[len("sailor:"):]
                    pending[topic].append(msg["data"])
            except (asyncio.TimeoutError, Exception):
                pass

            now = asyncio.get_event_loop().time()
            if now - last_flush >= 0.25:
                for topic, messages in pending.items():
                    if messages:
                        self._fan_out(topic, messages)
                pending.clear()
                last_flush = now

    @staticmethod
    def _topic_matches(published: str, subscribed: str) -> bool:
        """Return True if a message published on `published` should reach a `subscribed` topic.

        runs.all is a global wildcard — it receives every message on any runs.* topic.
        Otherwise: exact match, or published is a sub-topic of subscribed (prefix + ".").
        """
        if subscribed == "runs.all":
            return published.startswith("runs.")
        return published == subscribed or published.startswith(subscribed + ".")

    def _fan_out(self, topic: str, messages: list[str]) -> None:
        if not messages:
            return
        # Coalesce run_counters_updated — keep only the latest per run
        parsed = [json.loads(m) for m in messages]
        counter_msgs = [m for m in parsed if m.get("kind") == "run_counters_updated"]
        non_counter = [m for m in parsed if m.get("kind") != "run_counters_updated"]
        if counter_msgs:
            non_counter.append(counter_msgs[-1])

        # Format each message as an SSE frame
        frames = []
        for msg in non_counter:
            msg_str = json.dumps(msg, separators=(",", ":"))
            seq = msg.get("sequence", 0)
            kind = msg.get("kind", "message")
            if kind == "resync_required":
                # resync_required is never batched — send immediately as single frame
                frames.append(f"id: {seq}\nevent: {kind}\ndata: {msg_str}\n\n")
            else:
                frames.append(msg_str)  # raw JSON for batching below

        # For now, send each as individual SSE frames (batching window is in event_generator)
        dead = []
        for conn in self._connections:
            if any(self._topic_matches(topic, t) for t in conn.topics):
                for frame in frames:
                    if not conn.enqueue(frame):
                        dead.append(conn)
                        break
        for conn in dead:
            logger.warning("Dropping SSE connection (buffer exceeded)")
            if conn in self._connections:
                self._connections.remove(conn)

    def add_connection(self, conn: PushConnection) -> None:
        self._connections.append(conn)

    def remove_connection(self, conn: PushConnection) -> None:
        if conn in self._connections:
            self._connections.remove(conn)


_push_service: PushService | None = None


def get_push_service() -> PushService:
    global _push_service
    if _push_service is None:
        _push_service = PushService()
    return _push_service
