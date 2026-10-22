"""Checksummed PostgreSQL upgrades serialized across application workers."""

from __future__ import annotations

import hashlib
from pathlib import Path


def apply_migrations(dsn: str, *, migration_dir: Path | None = None) -> list[str]:
    """Apply pending SQL files atomically; refuse modified or missing history.

    The connection must have schema DDL privileges. SQL files are trusted source
    code shipped with the application, never data supplied by an endpoint.
    All migrations in one invocation share a transaction and advisory lock.
    """
    import psycopg

    root = Path(migration_dir) if migration_dir is not None else Path(__file__).resolve().parent.parent / "migrations"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Migration directory must be an existing regular directory")
    resolved_root = root.resolve()
    migrations: dict[str, tuple[str, str]] = {}
    for path in sorted(root.glob("*.sql")):
        if path.is_symlink() or path.resolve().parent != resolved_root or not path.is_file():
            raise ValueError("Migration symlink or path outside migration directory")
        content = path.read_bytes()
        migrations[path.name] = (hashlib.sha256(content).hexdigest(), content.decode("utf-8"))

    applied: list[str] = []
    with psycopg.connect(dsn) as conn:
        # Transaction-level lock works across processes and is released even if
        # SQL fails. Acquire it before creating history to avoid startup races.
        conn.execute("SELECT pg_advisory_xact_lock(648139, 3)")
        conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            checksum TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")
        history = dict(conn.execute("SELECT name, checksum FROM schema_migrations").fetchall())
        for name, checksum in history.items():
            if name not in migrations:
                raise ValueError(f"Applied migration missing from directory: {name}")
            if migrations[name][0] != checksum:
                raise ValueError(f"Migration checksum mismatch: {name}")
        for name, (checksum, sql) in migrations.items():
            if name not in history:
                conn.execute(sql)
                conn.execute("INSERT INTO schema_migrations (name, checksum) VALUES (%s, %s)",
                             (name, checksum))
                applied.append(name)
    return applied
