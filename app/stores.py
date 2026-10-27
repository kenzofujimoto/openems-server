"""Storage backends for the endpoint-management server.

`Store` is the port; `InMemoryStore` is the default (tests, first bring-up) and
`PostgresStore` is the production backend. Both satisfy the same contract, which
is exercised by tests/test_store_contract.py.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from threading import RLock
from typing import Protocol, runtime_checkable

from .models import AssignmentRule, Condition, Endpoint, EndpointStatus, Profile


class ProfilePreconditionError(ValueError):
    """A profile changed after an editor read it."""


@runtime_checkable
class Store(Protocol):
    def create(self, endpoint: Endpoint) -> bool: ...
    def upsert(self, endpoint: Endpoint) -> None: ...
    def get_by_client_id(self, client_id: str) -> Endpoint | None: ...
    def get_by_devid(self, devid: str) -> Endpoint | None: ...
    def all(self) -> list[Endpoint]: ...


class InMemoryStore:
    """Non-persistent store. Fine for tests and a first run."""

    def __init__(self) -> None:
        self._by_client: dict[str, Endpoint] = {}
        self._by_devid: dict[str, Endpoint] = {}
        self._lock = RLock()

    def create(self, endpoint: Endpoint) -> bool:
        with self._lock:
            if endpoint.devid in self._by_devid:
                return False
            self.upsert(endpoint)
            return True

    def upsert(self, endpoint: Endpoint) -> None:
        with self._lock:
            self._by_client = {key: row for key, row in self._by_client.items() if row.devid != endpoint.devid}
            stored = deepcopy(replace(endpoint, device_token=""))
            self._by_client[endpoint.client_id] = stored
            self._by_devid[endpoint.devid] = stored

    def get_by_client_id(self, client_id: str) -> Endpoint | None:
        with self._lock:
            return deepcopy(self._by_client.get(client_id))

    def get_by_devid(self, devid: str) -> Endpoint | None:
        with self._lock:
            return deepcopy(self._by_devid.get(devid))

    def all(self) -> list[Endpoint]:
        with self._lock:
            return deepcopy(list(self._by_devid.values()))


SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    devid       TEXT PRIMARY KEY,
    client_id   TEXT UNIQUE NOT NULL,
    hostname    TEXT NOT NULL DEFAULT '',
    os          TEXT NOT NULL DEFAULT '',
    fctver      TEXT NOT NULL DEFAULT '',
    vdom        TEXT NOT NULL DEFAULT 'Default',
    status      TEXT NOT NULL DEFAULT 'registered',
    reg_ip      TEXT NOT NULL DEFAULT '',
    host_tags   JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_endpoints_client_id ON endpoints (client_id);
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS credential_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS config_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS applied_vdom TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS applied_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS last_applied TIMESTAMPTZ;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS location TEXT NOT NULL DEFAULT '';
"""


class PostgresStore:
    """PostgreSQL-backed store using psycopg 3.

    Pass a libpq DSN, e.g. "postgresql://user:pass@localhost:5432/openems".
    Call init_schema() once at startup.
    """

    def __init__(self, dsn: str) -> None:
        import psycopg  # imported lazily so the package stays optional
        from psycopg.types.json import Jsonb

        self._psycopg = psycopg
        self._Jsonb = Jsonb
        self._conn = psycopg.connect(dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(SCHEMA)

    def upsert(self, endpoint: Endpoint) -> None:
        self._write(endpoint, create_only=False)

    def create(self, endpoint: Endpoint) -> bool:
        return self._write(endpoint, create_only=True)

    def _write(self, endpoint: Endpoint, *, create_only: bool) -> bool:
        conflict = "DO NOTHING" if create_only else """DO UPDATE SET
            client_id=EXCLUDED.client_id, hostname=EXCLUDED.hostname,
            os=EXCLUDED.os, fctver=EXCLUDED.fctver, vdom=EXCLUDED.vdom,
            status=EXCLUDED.status, reg_ip=EXCLUDED.reg_ip, host_tags=EXCLUDED.host_tags,
            last_seen=EXCLUDED.last_seen, credential_hash=EXCLUDED.credential_hash,
            config_version=EXCLUDED.config_version, applied_vdom=EXCLUDED.applied_vdom,
            applied_digest=EXCLUDED.applied_digest, last_error=EXCLUDED.last_error,
            last_applied=EXCLUDED.last_applied, location=EXCLUDED.location"""
        with self._conn.cursor() as cur:
            # psycopg, not SQLAlchemy: constant clauses only, every value is a bound parameter.
            cur.execute(  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
                """
                INSERT INTO endpoints
                    (devid, client_id, hostname, os, fctver, vdom, status,
                     reg_ip, host_tags, last_seen, created_at, credential_hash,
                     config_version, applied_vdom, applied_digest, last_error, last_applied, location)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (devid) """ + conflict,  # noqa: S608 - both clauses are constants, values bound
                (
                    endpoint.devid,
                    endpoint.client_id,
                    endpoint.hostname,
                    endpoint.os,
                    endpoint.fctver,
                    endpoint.vdom,
                    endpoint.status.value,
                    endpoint.reg_ip,
                    self._Jsonb(endpoint.host_tags),
                    endpoint.last_seen,
                    endpoint.created_at,
                    endpoint.credential_hash,
                    endpoint.config_version,
                    endpoint.applied_vdom,
                    endpoint.applied_digest,
                    endpoint.last_error,
                    endpoint.last_applied,
                    endpoint.location,
                ),
            )
            return cur.rowcount == 1

    def get_by_client_id(self, client_id: str) -> Endpoint | None:
        return self._one("WHERE client_id = %s", (client_id,))

    def get_by_devid(self, devid: str) -> Endpoint | None:
        return self._one("WHERE devid = %s", (devid,))

    def all(self) -> list[Endpoint]:
        with self._conn.cursor() as cur:
            cur.execute(self._SELECT)
            return [self._row(r) for r in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()

    # --- internals ------------------------------------------------------

    _SELECT = (
        "SELECT devid, client_id, hostname, os, fctver, vdom, status, reg_ip, "
        "host_tags, last_seen, created_at, credential_hash, config_version, "
        "applied_vdom, applied_digest, last_error, last_applied, location FROM endpoints "
    )

    def _one(self, where: str, params: tuple[object, ...]) -> Endpoint | None:
        with self._conn.cursor() as cur:
            # `where` is always a literal clause from this class; values travel in `params`.
            cur.execute(self._SELECT + where, params)  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
            row = cur.fetchone()
            return self._row(row) if row else None

    @staticmethod
    def _row(r: tuple[object, ...]) -> Endpoint:
        return Endpoint(
            devid=r[0],
            client_id=r[1],
            hostname=r[2],
            os=r[3],
            fctver=r[4],
            vdom=r[5],
            status=EndpointStatus(r[6]),
            reg_ip=r[7],
            host_tags=list(r[8]) if r[8] else [],
            last_seen=r[9],
            created_at=r[10],
            credential_hash=r[11],
            config_version=r[12],
            applied_vdom=r[13],
            applied_digest=r[14],
            last_error=r[15],
            last_applied=r[16],
            location=r[17],
        )


# =====================================================================
# Profile storage (config/profile push, SPEC-INTEROP.md §2.4)
# =====================================================================


@runtime_checkable
class ProfileStore(Protocol):
    def get(self, vdom: str) -> Profile | None: ...
    def put(self, profile: Profile) -> None: ...
    def publish(self, vdom: str, body: dict[str, object], expected_digest: str | None = None) -> Profile: ...
    def all(self) -> list[Profile]: ...


class InMemoryProfileStore:
    def __init__(self) -> None:
        self._by_vdom: dict[str, Profile] = {}
        self._lock = RLock()

    def get(self, vdom: str) -> Profile | None:
        with self._lock:
            return deepcopy(self._by_vdom.get(vdom))

    def put(self, profile: Profile) -> None:
        with self._lock:
            self._by_vdom[profile.vdom] = deepcopy(profile)

    def publish(self, vdom: str, body: dict[str, object], expected_digest: str | None = None) -> Profile:
        with self._lock:
            previous = self._by_vdom.get(vdom)
            if expected_digest is not None and (previous is None or previous.digest != expected_digest):
                raise ProfilePreconditionError("profile changed; reload before publishing")
            profile = Profile(vdom=vdom, version=previous.version + 1 if previous else 1,
                              body=deepcopy(body))
            self._by_vdom[vdom] = profile
            return deepcopy(profile)

    def all(self) -> list[Profile]:
        with self._lock:
            return deepcopy(list(self._by_vdom.values()))


PROFILE_SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
    vdom        TEXT PRIMARY KEY,
    version     INTEGER NOT NULL DEFAULT 0,
    body        JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


class PostgresProfileStore:
    """PostgreSQL-backed profile store (psycopg 3)."""

    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        self._Jsonb = Jsonb
        self._conn = psycopg.connect(dsn, autocommit=True)
        self._lock = RLock()

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(PROFILE_SCHEMA)

    def get(self, vdom: str) -> Profile | None:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT vdom, version, body, updated_at FROM profiles WHERE vdom = %s",
                (vdom,),
            )
            row = cur.fetchone()
            return self._row(row) if row else None

    def put(self, profile: Profile) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO profiles (vdom, version, body, updated_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (vdom) DO UPDATE SET
                    version = EXCLUDED.version,
                    body = EXCLUDED.body,
                    updated_at = EXCLUDED.updated_at
                """,
                (profile.vdom, profile.version, self._Jsonb(profile.body), profile.updated_at),
            )

    def publish(self, vdom: str, body: dict[str, object], expected_digest: str | None = None) -> Profile:
        with self._lock, self._conn.transaction(), self._conn.cursor() as cur:
            if expected_digest is not None:
                cur.execute("SELECT vdom, version, body, updated_at FROM profiles WHERE vdom=%s FOR UPDATE", (vdom,))
                previous = cur.fetchone()
                if previous is None or self._row(previous).digest != expected_digest:
                    raise ProfilePreconditionError("profile changed; reload before publishing")
            cur.execute(
                """INSERT INTO profiles (vdom, version, body)
                VALUES (%s, 1, %s)
                ON CONFLICT (vdom) DO UPDATE SET version = profiles.version + 1,
                body = EXCLUDED.body, updated_at = clock_timestamp()
                RETURNING vdom, version, body, updated_at""",
                (vdom, self._Jsonb(body)),
            )
            return self._row(cur.fetchone())

    def all(self) -> list[Profile]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT vdom, version, body, updated_at FROM profiles")
            return [self._row(r) for r in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row(r: tuple[object, ...]) -> Profile:
        return Profile(
            vdom=r[0],
            version=r[1],
            body=dict(r[2]) if r[2] else {},
            updated_at=r[3],
        )


# =====================================================================
# Assignment-rule storage
# =====================================================================


@runtime_checkable
class RuleStore(Protocol):
    def add(self, rule: AssignmentRule) -> None: ...   # upsert by id
    def remove(self, rule_id: str) -> bool: ...
    def all(self) -> list[AssignmentRule]: ...


def _conditions_to_json(rule: AssignmentRule) -> list[dict[str, object]]:
    return [{"field": c.field, "op": c.op, "value": c.value} for c in rule.conditions]


def _conditions_from_json(data: list[dict[str, object]]) -> list[Condition]:
    return [Condition(field=c["field"], op=c["op"], value=c["value"]) for c in data]


class InMemoryRuleStore:
    def __init__(self) -> None:
        self._rules: list[AssignmentRule] = []

    def add(self, rule: AssignmentRule) -> None:
        self._rules = [r for r in self._rules if r.id != rule.id]
        self._rules.append(rule)

    def remove(self, rule_id: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        return len(self._rules) < before

    def all(self) -> list[AssignmentRule]:
        return list(self._rules)


RULE_SCHEMA = """
CREATE TABLE IF NOT EXISTS assignment_rules (
    id          TEXT PRIMARY KEY,
    target_vdom TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 100,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    conditions  JSONB NOT NULL DEFAULT '[]'::jsonb
);
"""


class PostgresRuleStore:
    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        self._Jsonb = Jsonb
        self._conn = psycopg.connect(dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(RULE_SCHEMA)

    def add(self, rule: AssignmentRule) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assignment_rules (id, target_vdom, priority, enabled, conditions)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    target_vdom = EXCLUDED.target_vdom,
                    priority = EXCLUDED.priority,
                    enabled = EXCLUDED.enabled,
                    conditions = EXCLUDED.conditions
                """,
                (rule.id, rule.target_vdom, rule.priority, rule.enabled,
                 self._Jsonb(_conditions_to_json(rule))),
            )

    def remove(self, rule_id: str) -> bool:
        with self._conn.cursor() as cur:
            cur.execute("DELETE FROM assignment_rules WHERE id = %s", (rule_id,))
            return cur.rowcount > 0

    def all(self) -> list[AssignmentRule]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT id, target_vdom, priority, enabled, conditions FROM assignment_rules"
            )
            return [
                AssignmentRule(
                    id=r[0], target_vdom=r[1], priority=r[2], enabled=r[3],
                    conditions=_conditions_from_json(r[4] or []),
                )
                for r in cur.fetchall()
            ]

    def close(self) -> None:
        self._conn.close()


# =====================================================================
# Admin storage (credentials for the management console)
# =====================================================================


@runtime_checkable
class AdminStore(Protocol):
    def get(self, username: str) -> tuple[str, str] | None: ...  # (password_hash, role)
    def put(self, username: str, password_hash: str, role: str) -> None: ...
    def has_any(self) -> bool: ...
    def all(self) -> list[dict[str, str]]: ...
    def manage(self, username: str, password_hash: str | None, role: str | None, *,
               create: bool = False, delete: bool = False, allow_superadmin: bool = False) -> bool: ...


class InMemoryAdminStore:
    def __init__(self) -> None:
        self._admins: dict[str, tuple[str, str]] = {}
        self._lock = RLock()

    def get(self, username: str) -> tuple[str, str] | None:
        return self._admins.get(username)

    def put(self, username: str, password_hash: str, role: str) -> None:
        self._admins[username] = (password_hash, role)

    def has_any(self) -> bool:
        return bool(self._admins)

    def all(self) -> list[dict[str, str]]:
        with self._lock:
            return [{"username": username, "role": record[1]} for username, record in sorted(self._admins.items())]

    def manage(self, username: str, password_hash: str | None, role: str | None, *,
               create: bool = False, delete: bool = False, allow_superadmin: bool = False) -> bool:
        with self._lock:
            previous = self._admins.get(username)
            if create and previous is not None:
                return False
            if not create and previous is None:
                return False
            if previous and previous[1] == "superadmin" and not allow_superadmin:
                raise PermissionError("superadministrator is protected")
            writers = sum(record[1] in {"admin", "superadmin"} for record in self._admins.values())
            if previous and previous[1] in {"admin", "superadmin"} and (delete or role == "viewer") and writers <= 1:
                raise ValueError("the last administrator cannot be removed or demoted")
            if delete:
                del self._admins[username]
            else:
                self._admins[username] = (password_hash or (previous[0] if previous else ""), role or (previous[1] if previous else "admin"))
            return True


ADMIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin'
);
"""


class PostgresAdminStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)
        self._lock = RLock()

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(ADMIN_SCHEMA)

    def get(self, username: str) -> tuple[str, str] | None:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT password_hash, role FROM admins WHERE username = %s", (username,)
            )
            row = cur.fetchone()
            return (row[0], row[1]) if row else None

    def put(self, username: str, password_hash: str, role: str) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO admins (username, password_hash, role)
                VALUES (%s, %s, %s)
                ON CONFLICT (username) DO UPDATE SET
                    password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
                """,
                (username, password_hash, role),
            )

    def has_any(self) -> bool:
        with self._conn.cursor() as cur:
            cur.execute("SELECT 1 FROM admins LIMIT 1")
            return cur.fetchone() is not None

    def all(self) -> list[dict[str, str]]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT username,role FROM admins ORDER BY username")
            return [{"username": row[0], "role": row[1]} for row in cur.fetchall()]

    def manage(self, username: str, password_hash: str | None, role: str | None, *,
               create: bool = False, delete: bool = False, allow_superadmin: bool = False) -> bool:
        with self._lock, self._conn.transaction(), self._conn.cursor() as cur:
            # Serialize changes across processes, including the empty-table/create case.
            cur.execute("LOCK TABLE admins IN SHARE ROW EXCLUSIVE MODE")
            cur.execute("SELECT password_hash,role FROM admins WHERE username=%s", (username,))
            previous = cur.fetchone()
            if (create and previous is not None) or (not create and previous is None):
                return False
            if previous and previous[1] == "superadmin" and not allow_superadmin:
                raise PermissionError("superadministrator is protected")
            if previous and previous[1] in {"admin", "superadmin"} and (delete or role == "viewer"):
                cur.execute("SELECT count(*) FROM admins WHERE role IN ('admin','superadmin')")
                if cur.fetchone()[0] <= 1:
                    raise ValueError("the last administrator cannot be removed or demoted")
            if delete:
                cur.execute("DELETE FROM admins WHERE username=%s", (username,))
            elif create:
                cur.execute("INSERT INTO admins(username,password_hash,role) VALUES(%s,%s,%s)",
                            (username, password_hash, role or "admin"))
            else:
                cur.execute("UPDATE admins SET password_hash=%s,role=%s WHERE username=%s",
                            (password_hash or previous[0], role or previous[1], username))
            return True

    def close(self) -> None:
        self._conn.close()
