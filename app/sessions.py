"""Revocable admin sessions and bounded, atomic login throttling stores."""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from threading import RLock
from typing import Protocol


@dataclass(frozen=True, slots=True)
class AdminSession:
    sid: str
    username: str
    role: str
    credential_fingerprint: str
    csrf_token: str
    created_at: int
    expires_at: int


class SessionStore(Protocol):
    def put(self, session: AdminSession) -> None: ...
    def get(self, sid: str) -> AdminSession | None: ...
    def revoke(self, sid: str) -> bool: ...
    def consume_login_attempt(
        self, key: str, *, now: float, window_seconds: int, max_attempts: int
    ) -> int: ...
    def reset_login(self, key: str) -> None: ...


class InMemorySessionStore:
    """Thread-safe local store; capacities fail closed instead of evicting live state."""

    def __init__(
        self, *, max_sessions: int = 10_000, max_login_buckets: int = 20_000
    ) -> None:
        self._sessions: dict[str, AdminSession] = {}
        self._login: dict[str, tuple[float, int]] = {}
        self._lock = RLock()
        self._max_sessions = max_sessions
        self._max_login_buckets = max_login_buckets

    def put(self, session: AdminSession) -> None:
        with self._lock:
            self._sessions = {
                sid: value
                for sid, value in self._sessions.items()
                if value.expires_at > session.created_at
            }
            if (
                len(self._sessions) >= self._max_sessions
                and session.sid not in self._sessions
            ):
                raise ValueError("admin session capacity reached")
            self._sessions[session.sid] = session

    def get(self, sid: str) -> AdminSession | None:
        with self._lock:
            return self._sessions.get(sid)

    def revoke(self, sid: str) -> bool:
        with self._lock:
            return self._sessions.pop(sid, None) is not None

    def consume_login_attempt(
        self, key: str, *, now: float, window_seconds: int, max_attempts: int
    ) -> int:
        with self._lock:
            self._login = {
                key: bucket for key, bucket in self._login.items() if bucket[0] > now
            }
            existing = self._login.get(key)
            if existing is None:
                if len(self._login) >= self._max_login_buckets:
                    return max(1, window_seconds)
                expires_at, attempts = now + window_seconds, 0
            else:
                expires_at, attempts = existing
            if attempts >= max_attempts:
                return max(1, ceil(expires_at - now))
            self._login[key] = (expires_at, attempts + 1)
            return 0

    def reset_login(self, key: str) -> None:
        with self._lock:
            self._login.pop(key, None)


SESSION_SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_sessions (
    sid TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    credential_fingerprint TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_sessions_expiry ON admin_sessions (expires_at);
CREATE TABLE IF NOT EXISTS admin_login_limits (
    bucket_key TEXT PRIMARY KEY,
    expires_at DOUBLE PRECISION NOT NULL,
    attempts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_login_limits_expiry ON admin_login_limits (expires_at);
"""


class PostgresSessionStore:
    """Shared sessions and throttles; transaction locks enforce quotas across workers."""

    def __init__(
        self, dsn: str, *, max_sessions: int = 10_000, max_login_buckets: int = 20_000
    ) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)
        self._lock = RLock()
        self._max_sessions = max_sessions
        self._max_login_buckets = max_login_buckets

    def init_schema(self) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(SESSION_SCHEMA)

    def put(self, session: AdminSession) -> None:
        with self._lock, self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(648139, 1)")
            cur.execute(
                "DELETE FROM admin_sessions WHERE expires_at <= %s",
                (session.created_at,),
            )
            cur.execute("SELECT COUNT(*) FROM admin_sessions")
            if cur.fetchone()[0] >= self._max_sessions:
                raise ValueError("admin session capacity reached")
            cur.execute(
                """INSERT INTO admin_sessions
                (sid, username, role, credential_fingerprint, csrf_token, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (
                    session.sid,
                    session.username,
                    session.role,
                    session.credential_fingerprint,
                    session.csrf_token,
                    session.created_at,
                    session.expires_at,
                ),
            )

    def get(self, sid: str) -> AdminSession | None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                """SELECT sid, username, role, credential_fingerprint, csrf_token,
                created_at, expires_at FROM admin_sessions WHERE sid = %s""",
                (sid,),
            )
            row = cur.fetchone()
            return AdminSession(*row) if row else None

    def revoke(self, sid: str) -> bool:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("DELETE FROM admin_sessions WHERE sid = %s", (sid,))
            return cur.rowcount > 0

    def consume_login_attempt(
        self, key: str, *, now: float, window_seconds: int, max_attempts: int
    ) -> int:
        with self._lock, self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(648139, 2)")
            cur.execute("DELETE FROM admin_login_limits WHERE expires_at <= %s", (now,))
            cur.execute(
                "SELECT expires_at, attempts FROM admin_login_limits WHERE bucket_key = %s",
                (key,),
            )
            row = cur.fetchone()
            if row is not None:
                expires_at, attempts = row
                if attempts >= max_attempts:
                    return max(1, ceil(expires_at - now))
                cur.execute(
                    "UPDATE admin_login_limits SET attempts = attempts + 1 WHERE bucket_key = %s",
                    (key,),
                )
            else:
                cur.execute("SELECT COUNT(*) FROM admin_login_limits")
                if cur.fetchone()[0] >= self._max_login_buckets:
                    return max(1, window_seconds)
                cur.execute(
                    "INSERT INTO admin_login_limits (bucket_key, expires_at, attempts) VALUES (%s, %s, 1)",
                    (key, now + window_seconds),
                )
            return 0

    def reset_login(self, key: str) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("DELETE FROM admin_login_limits WHERE bucket_key = %s", (key,))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
