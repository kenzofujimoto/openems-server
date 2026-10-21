"""Replay protection for one-time SAML assertions.

Each consumed assertion ID is remembered until its expiry; a second use within
that window is rejected. `InMemoryReplayCache` is the default; `RedisReplayCache`
uses `SET key 1 NX EX ttl`, whose atomic set-if-absent is a natural fit and works
across multiple server processes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


@runtime_checkable
class ReplayCache(Protocol):
    def check_and_remember(self, key: str, expires_at: datetime) -> bool:
        """Return True if `key` is new (now remembered); False if already seen."""
        ...


class InMemoryReplayCache:
    def __init__(self) -> None:
        self._seen: dict[str, datetime] = {}

    def check_and_remember(self, key: str, expires_at: datetime) -> bool:
        now = datetime.now(timezone.utc)
        # prune expired entries so the map does not grow without bound
        self._seen = {k: v for k, v in self._seen.items() if v > now}
        if key in self._seen:
            return False
        self._seen[key] = expires_at
        return True


class RedisReplayCache:
    def __init__(self, url: str = "redis://localhost:6379/0", *, prefix: str = "saml-replay:") -> None:
        import redis

        self._redis = redis.Redis.from_url(url, decode_responses=True)
        self._prefix = prefix

    def check_and_remember(self, key: str, expires_at: datetime) -> bool:
        now = datetime.now(timezone.utc)
        ttl = max(1, int((expires_at - now).total_seconds()))
        # SET NX returns True only if the key did not exist -> first use.
        return bool(self._redis.set(f"{self._prefix}{key}", "1", nx=True, ex=ttl))
