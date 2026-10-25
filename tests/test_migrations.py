"""Exercise upgrades and migration failures against disposable PostgreSQL schemas."""

from __future__ import annotations

import importlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest


@pytest.fixture
def database():
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set")
    import psycopg
    from psycopg.conninfo import make_conninfo
    schema = "test_migrations_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(psycopg.sql.SQL("CREATE SCHEMA {}").format(psycopg.sql.Identifier(schema)))
    scoped = make_conninfo(dsn, options=f"-c search_path={schema}")
    try:
        yield scoped
    finally:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(psycopg.sql.SQL("DROP SCHEMA {} CASCADE").format(psycopg.sql.Identifier(schema)))


def runner():
    return importlib.import_module("app.migrations").apply_migrations


def test_upgrades_legacy_schema_and_preserves_endpoint_and_profile(database):
    import psycopg

    from app.stores import PostgresProfileStore, PostgresStore
    with psycopg.connect(database) as conn:
        conn.execute("""CREATE TABLE endpoints (
            devid TEXT PRIMARY KEY, client_id TEXT UNIQUE NOT NULL,
            hostname TEXT NOT NULL DEFAULT '', os TEXT NOT NULL DEFAULT '',
            fctver TEXT NOT NULL DEFAULT '', vdom TEXT NOT NULL DEFAULT 'Default',
            status TEXT NOT NULL DEFAULT 'registered', reg_ip TEXT NOT NULL DEFAULT '',
            host_tags JSONB NOT NULL DEFAULT '[]', last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now());
            INSERT INTO endpoints (devid,client_id,hostname) VALUES ('legacy','old','old-host');
            CREATE TABLE profiles (vdom TEXT PRIMARY KEY, version INTEGER NOT NULL DEFAULT 0,
            body JSONB NOT NULL DEFAULT '{}', updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
            INSERT INTO profiles(vdom,version,body) VALUES ('Default',8,'{"webfilter":{}}')""")
    assert runner()(database) == ["001_initial.sql", "002_block_events.sql", "003_tamper_events.sql", "004_uninstall.sql"]
    endpoints = PostgresStore(database)
    profiles = PostgresProfileStore(database)
    try:
        old = endpoints.get_by_devid("legacy")
        assert old.hostname == "old-host"
        assert old.credential_hash == ""
        assert old.config_version == 0 and old.last_applied is None
        old.credential_hash = "hash-only"
        old.config_version = 8
        old.applied_vdom = "Default"
        old.applied_digest = "d" * 64
        endpoints.upsert(old)
        assert runner()(database) == []
        assert endpoints.get_by_devid("legacy").credential_hash == "hash-only"
        assert profiles.get("Default").version == 8
        assert profiles.get("Default").body == {"webfilter": {}}
        with psycopg.connect(database) as conn:
            tables = {row[0] for row in conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema()")}
        assert {"endpoints", "profiles", "admins", "assignment_rules", "audit_log", "saml_idps", "enrollment_invitations", "admin_sessions", "admin_login_limits", "schema_migrations"} <= tables
    finally:
        endpoints.close()
        profiles.close()


def test_checksum_change_is_rejected_without_changing_state(database, tmp_path):
    import psycopg
    migration = tmp_path / "001_create.sql"
    migration.write_text("CREATE TABLE preserved (value INTEGER); INSERT INTO preserved VALUES (7)", encoding="utf-8")
    assert runner()(database, migration_dir=tmp_path) == [migration.name]
    assert runner()(database, migration_dir=tmp_path) == []
    migration.write_text("DELETE FROM preserved", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        runner()(database, migration_dir=tmp_path)
    with psycopg.connect(database) as conn:
        assert conn.execute("SELECT value FROM preserved").fetchone() == (7,)
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone() == (1,)


def test_failed_batch_rolls_back_schema_and_history(database, tmp_path):
    import psycopg
    (tmp_path / "001_first.sql").write_text("CREATE TABLE rollback_probe (value INTEGER)", encoding="utf-8")
    (tmp_path / "002_bad.sql").write_text("THIS IS INVALID SQL", encoding="utf-8")
    with pytest.raises(psycopg.Error):
        runner()(database, migration_dir=tmp_path)
    with psycopg.connect(database) as conn:
        assert conn.execute("SELECT to_regclass('rollback_probe'), to_regclass('schema_migrations')").fetchone() == (None, None)
    (tmp_path / "002_bad.sql").write_text("INSERT INTO rollback_probe VALUES (3)", encoding="utf-8")
    assert runner()(database, migration_dir=tmp_path) == ["001_first.sql", "002_bad.sql"]


def test_concurrent_runners_apply_once(database):
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: runner()(database), range(4)))
    migrations = len(list((Path(__file__).resolve().parent.parent / "migrations").glob("*.sql")))
    assert sorted(len(result) for result in results) == [0, 0, 0, migrations], "one runner applies every file"


def test_missing_directory_rejected_before_connecting(tmp_path):
    with pytest.raises(ValueError, match="directory"):
        runner()("invalid dsn", migration_dir=tmp_path / "missing")


def test_symlink_migration_cannot_escape_tree(database, tmp_path, monkeypatch):
    external = tmp_path / "external.sql"
    external.write_text("SELECT 1", encoding="utf-8")
    migration_dir = tmp_path / "migrations"
    migration_dir.mkdir()
    migration = migration_dir / "001_escape.sql"
    migration.write_text("SELECT 1", encoding="utf-8")
    # Windows runners may not have symlink privileges; exercise path rejection
    # independently of the OS capability to create a symlink.
    path_type = type(migration)
    original = path_type.is_symlink
    monkeypatch.setattr(path_type, "is_symlink", lambda path: path == migration or original(path))
    with pytest.raises(ValueError, match="outside|symlink"):
        runner()(database, migration_dir=migration_dir)


def test_applied_migration_cannot_disappear(database, tmp_path):
    migration = tmp_path / "001_create.sql"
    migration.write_text("SELECT 1", encoding="utf-8")
    runner()(database, migration_dir=tmp_path)
    migration.unlink()
    with pytest.raises(ValueError, match="missing"):
        runner()(database, migration_dir=tmp_path)
