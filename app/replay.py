"""Atomic one-time SAML assertion and AuthnRequest stores."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from threading import Lock
from typing import Protocol, runtime_checkable


@runtime_checkable
class ReplayCache(Protocol):
    def check_and_remember(self, key: str, expires_at: datetime) -> bool: ...


class InMemoryReplayCache:
    def __init__(self) -> None:
        self._seen: dict[str, datetime] = {}
        self._lock = Lock()

    def check_and_remember(self, key: str, expires_at: datetime) -> bool:
        now = datetime.now(UTC)
        with self._lock:
            self._seen = {k: v for k, v in self._seen.items() if v > now}
            if key in self._seen or expires_at <= now:
                return False
            self._seen[key] = expires_at
            return True


class RedisReplayCache:
    def __init__(
        self, url: str = "redis://localhost:6379/0", *, prefix: str = "saml-replay:"
    ) -> None:
        import redis

        self._redis = redis.Redis.from_url(url, decode_responses=True)
        self._prefix = prefix

    def check_and_remember(self, key: str, expires_at: datetime) -> bool:
        ttl = math.ceil((expires_at - datetime.now(UTC)).total_seconds())
        if ttl <= 0:
            return False
        return bool(self._redis.set(f"{self._prefix}{key}", "1", nx=True, ex=ttl))


class PendingRequestStore(Protocol):
    def put(
        self,
        request_id: str,
        prefix: str,
        relay_state: str | None,
        expires_at: datetime,
    ) -> None: ...
    def consume(
        self, request_id: str, prefix: str, relay_state: str | None
    ) -> bool: ...


class InMemoryPendingRequestStore:
    def __init__(self) -> None:
        self._pending: dict[str, tuple[str, str | None, datetime]] = {}
        self._lock = Lock()

    def put(
        self,
        request_id: str,
        prefix: str,
        relay_state: str | None,
        expires_at: datetime,
    ) -> None:
        with self._lock:
            now = datetime.now(UTC)
            self._pending = {k: v for k, v in self._pending.items() if v[2] > now}
            self._pending[request_id] = (prefix, relay_state, expires_at)

    def consume(self, request_id: str, prefix: str, relay_state: str | None) -> bool:
        with self._lock:
            pending = self._pending.get(request_id)
            if pending is None:
                return False
            if pending[2] <= datetime.now(UTC):
                del self._pending[request_id]
                return False
            if pending[:2] != (prefix, relay_state):
                return False
            del self._pending[request_id]
            return True


class RedisPendingRequestStore:
    """Compare-and-delete prevents consuming another tenant's/state's request."""

    _CONSUME = """
    if redis.call('GET', KEYS[1]) == ARGV[1] then
        redis.call('DEL', KEYS[1])
        return 1
    end
    return 0
    """

    def __init__(
        self, url: str = "redis://localhost:6379/0", *, prefix: str = "saml-pending:"
    ) -> None:
        import redis

        self._redis = redis.Redis.from_url(url, decode_responses=True)
        self._prefix = prefix

    @staticmethod
    def _value(prefix: str, relay_state: str | None) -> str:
        return json.dumps([prefix, relay_state], separators=(",", ":"))

    def put(
        self,
        request_id: str,
        prefix: str,
        relay_state: str | None,
        expires_at: datetime,
    ) -> None:
        ttl = math.ceil((expires_at - datetime.now(UTC)).total_seconds())
        if ttl <= 0:
            raise ValueError("Pending request expiry must be in the future")
        if not self._redis.set(
            self._prefix + request_id, self._value(prefix, relay_state), nx=True, ex=ttl
        ):
            raise ValueError("Duplicate pending SAML request ID")

    def consume(self, request_id: str, prefix: str, relay_state: str | None) -> bool:
        return bool(
            self._redis.eval(
                self._CONSUME,
                1,
                self._prefix + request_id,
                self._value(prefix, relay_state),
            )
        )
