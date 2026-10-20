"""Message queue backends used for config/profile push.

When an administrator updates a vdom profile, the service enqueues a
`config_update` notification per affected endpoint (keyed by client_id). The
endpoint drains its queue on keepalive/refresh and then fetches the new config.

`Queue` is the port; `InMemoryQueue` (default/tests) and `RedisQueue`
(production, redis-py) implement it and share one contract test suite.
"""

from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Queue(Protocol):
    def push(self, topic: str, message: dict[str, Any]) -> None: ...
    def pull(self, topic: str) -> list[dict[str, Any]]: ...  # drain all pending


class InMemoryQueue:
    """FIFO per-topic queue held in process memory."""

    def __init__(self) -> None:
        self._topics: dict[str, list[dict[str, Any]]] = {}

    def push(self, topic: str, message: dict[str, Any]) -> None:
        self._topics.setdefault(topic, []).append(message)

    def pull(self, topic: str) -> list[dict[str, Any]]:
        return self._topics.pop(topic, [])


class RedisQueue:
    """Redis-backed per-topic FIFO queue (one list key per topic).

    Messages are JSON-encoded. `pull` drains atomically (LRANGE + DEL in a
    transaction) so a concurrent reader never sees a half-consumed topic.
    """

    def __init__(self, url: str = "redis://localhost:6379/0", *, prefix: str = "queue:") -> None:
        import redis  # lazy import keeps the dependency optional

        self._redis = redis.Redis.from_url(url, decode_responses=True)
        self._prefix = prefix

    def _key(self, topic: str) -> str:
        return f"{self._prefix}{topic}"

    def push(self, topic: str, message: dict[str, Any]) -> None:
        self._redis.rpush(self._key(topic), json.dumps(message))

    def pull(self, topic: str) -> list[dict[str, Any]]:
        key = self._key(topic)
        pipe = self._redis.pipeline()
        pipe.lrange(key, 0, -1)
        pipe.delete(key)
        raw, _ = pipe.execute()
        return [json.loads(item) for item in raw]

    def close(self) -> None:
        self._redis.close()
