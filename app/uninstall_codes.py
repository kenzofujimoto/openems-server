"""Uninstall codes on the server (tamper-protection.md, part 5b).

Each registration's secret is derived from the master key and its client_id (agent/uninstall.py). The
agent fetches it until it confirms storage with a delivery proof; after that the secret is no longer
handed out, so a local administrator who reads the device token cannot fetch it to mint codes. Codes
use a per-client_id counter that only grows. A release lets every machine in a policy group, or the
whole fleet ("*"), uninstall without a code: config/assigned carries a token bound to each machine.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Protocol, runtime_checkable

from agent.uninstall import (
    MIN_MASTER_KEY,
    code,
    delivery_proof,
    derive_secret,
    release_token,
)

from .models import Endpoint
from .service import EmsService

FLEET = "*"

SCHEMA = """
CREATE TABLE IF NOT EXISTS uninstall_state (
    client_id    TEXT PRIMARY KEY,
    counter      BIGINT NOT NULL DEFAULT 0 CHECK (counter >= 0),
    secret_acked BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS uninstall_releases (
    scope       TEXT PRIMARY KEY,
    released_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_by TEXT NOT NULL
);
"""


class UninstallDisabledError(Exception):
    """Raised when no master key is configured (OPENEMS_UNINSTALL_MASTER_KEY)."""


class SecretAlreadyDeliveredError(Exception):
    """Raised when the agent already confirmed it stored the secret."""


@dataclass(frozen=True, slots=True)
class Release:
    scope: str
    released_at: datetime
    released_by: str


@runtime_checkable
class UninstallStore(Protocol):
    def next_counter(self, client_id: str) -> int: ...
    def secret_acked(self, client_id: str) -> bool: ...
    def set_secret_acked(self, client_id: str, acked: bool) -> None: ...
    def releases(self) -> list[Release]: ...
    def set_release(self, scope: str, released: bool, actor: str) -> None: ...


class InMemoryUninstallStore:
    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._acked: set[str] = set()
        self._releases: dict[str, Release] = {}
        self._lock = RLock()

    def next_counter(self, client_id: str) -> int:
        with self._lock:
            self._counters[client_id] = self._counters.get(client_id, 0) + 1
            return self._counters[client_id]

    def secret_acked(self, client_id: str) -> bool:
        with self._lock:
            return client_id in self._acked

    def set_secret_acked(self, client_id: str, acked: bool) -> None:
        with self._lock:
            if acked:
                self._acked.add(client_id)
            else:
                self._acked.discard(client_id)

    def releases(self) -> list[Release]:
        with self._lock:
            return sorted(self._releases.values(), key=lambda release: release.scope)

    def set_release(self, scope: str, released: bool, actor: str) -> None:
        with self._lock:
            if not released:
                self._releases.pop(scope, None)
            elif scope not in self._releases:
                self._releases[scope] = Release(scope=scope, released_at=datetime.now(UTC), released_by=actor)


class PostgresUninstallStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(SCHEMA)

    def next_counter(self, client_id: str) -> int:
        # One statement, so concurrent requests never share a counter.
        with self._conn.cursor() as cur:
            cur.execute("INSERT INTO uninstall_state (client_id, counter) VALUES (%s, 1) ON CONFLICT (client_id) "
                        "DO UPDATE SET counter = uninstall_state.counter + 1 RETURNING counter", (client_id,))
            return int(cur.fetchone()[0])

    def secret_acked(self, client_id: str) -> bool:
        with self._conn.cursor() as cur:
            cur.execute("SELECT secret_acked FROM uninstall_state WHERE client_id = %s", (client_id,))
            row = cur.fetchone()
            return bool(row and row[0])

    def set_secret_acked(self, client_id: str, acked: bool) -> None:
        with self._conn.cursor() as cur:
            cur.execute("INSERT INTO uninstall_state (client_id, secret_acked) VALUES (%s, %s) ON CONFLICT (client_id) "
                        "DO UPDATE SET secret_acked = EXCLUDED.secret_acked", (client_id, acked))

    def releases(self) -> list[Release]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT scope, released_at, released_by FROM uninstall_releases ORDER BY scope")
            return [Release(scope=row[0], released_at=row[1].astimezone(UTC), released_by=row[2])
                    for row in cur.fetchall()]

    def set_release(self, scope: str, released: bool, actor: str) -> None:
        with self._conn.cursor() as cur:
            if released:
                cur.execute("INSERT INTO uninstall_releases (scope, released_by) VALUES (%s, %s) "
                            "ON CONFLICT (scope) DO NOTHING", (scope, actor))
            else:
                cur.execute("DELETE FROM uninstall_releases WHERE scope = %s", (scope,))

    def close(self) -> None:
        self._conn.close()


class UninstallCodes:
    def __init__(self, service: EmsService, store: UninstallStore | None = None,
                 master_key: bytes | None = None) -> None:
        if master_key is not None and len(master_key) < MIN_MASTER_KEY:
            raise ValueError(f"the uninstall master key must have at least {MIN_MASTER_KEY} bytes")
        self._service = service
        self._store: UninstallStore = store or InMemoryUninstallStore()
        self._master_key = master_key

    @property
    def enabled(self) -> bool:
        return self._master_key is not None

    def _require_key(self) -> bytes:
        if self._master_key is None:
            raise UninstallDisabledError()
        return self._master_key

    def _secret(self, client_id: str) -> bytes:
        return derive_secret(self._require_key(), client_id)

    def deliver_secret(self, client_id: str) -> bytes:
        secret = self._secret(client_id)
        self._service.get_endpoint_by_client_id(client_id)
        if self._store.secret_acked(client_id):
            raise SecretAlreadyDeliveredError()
        return secret

    def confirm_delivery(self, client_id: str, proof: str) -> bool:
        secret = self._secret(client_id)
        self._service.get_endpoint_by_client_id(client_id)
        if not hmac.compare_digest(delivery_proof(secret), proof):
            return False
        self._store.set_secret_acked(client_id, True)
        return True

    def reopen_delivery(self, devid: str) -> None:
        self._require_key()
        self._store.set_secret_acked(self._service.get_endpoint(devid).client_id, False)

    def next_code(self, devid: str) -> tuple[int, str]:
        self._require_key()
        client_id = self._service.get_endpoint(devid).client_id
        counter = self._store.next_counter(client_id)
        return counter, code(self._secret(client_id), counter)

    def release_for(self, endpoint: Endpoint) -> str | None:
        """Release token for config/assigned, or None when this machine's removal still needs a code."""
        if not self.enabled:
            return None
        scopes = {release.scope for release in self._store.releases()}
        if FLEET in scopes or self._service.effective_vdom(endpoint) in scopes:
            return release_token(self._secret(endpoint.client_id))
        return None

    def releases(self) -> list[Release]:
        self._require_key()
        return self._store.releases()

    def set_release(self, scope: str, released: bool, actor: str) -> None:
        self._require_key()
        self._store.set_release(scope, released, actor)
