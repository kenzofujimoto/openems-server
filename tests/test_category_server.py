"""Server side of web categories: building from UT1-style lists and serving them to devices."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from app.categories import CategoryRepository, build_categories
from fastapi.testclient import TestClient

from agent.categories import parse_category_file
from agent.policy import domain_hash
from app.api import create_app
from app.service import EmsService

NOW = datetime(2026, 10, 23, 18, 0, tzinfo=UTC)


def ut1(tmp_path):
    source = tmp_path / "blacklists"
    (source / "games").mkdir(parents=True)
    (source / "games" / "domains").write_text("steampowered.com\n# comment\nsteamcommunity.com\n\n1.2.3.4\n", encoding="utf-8")
    (source / "social_networks").mkdir()
    (source / "social_networks" / "domains").write_text("facebook.com\n", encoding="utf-8")
    return source


def test_builder_writes_verified_files_and_a_manifest_with_attribution(tmp_path):
    output = tmp_path / "categories"
    manifest = build_categories(ut1(tmp_path), output, now=NOW)
    assert manifest["version"] == "2026-10-23T18:00:00Z"
    assert "Université Toulouse Capitole" in manifest["attribution"] and "CC BY-SA 4.0" in manifest["attribution"]
    entries = {entry["id"]: entry for entry in manifest["categories"]}
    assert set(entries) == {"games", "social"}, "categories without any source list are omitted"
    games = entries["games"]
    data = (output / f"games-{games['digest']}.bin").read_bytes()
    assert hashlib.sha256(data).hexdigest() == games["digest"] and games["size"] == len(data)
    assert parse_category_file(data) == sorted({domain_hash("steampowered.com"), domain_hash("steamcommunity.com")})
    assert games["count"] == 2 and games["label"] == "Jogos"
    assert json.loads((output / "manifest.json").read_text(encoding="utf-8")) == manifest


def test_rebuild_replaces_stale_files(tmp_path):
    source, output = ut1(tmp_path), tmp_path / "categories"
    first = build_categories(source, output, now=NOW)
    (source / "games" / "domains").write_text("steampowered.com\n", encoding="utf-8")
    second = build_categories(source, output, now=NOW)
    old = next(entry["digest"] for entry in first["categories"] if entry["id"] == "games")
    new = next(entry["digest"] for entry in second["categories"] if entry["id"] == "games")
    assert old != new and not (output / f"games-{old}.bin").exists() and (output / f"games-{new}.bin").exists()


def test_repository_serves_only_published_files(tmp_path):
    output = tmp_path / "categories"
    manifest = build_categories(ut1(tmp_path), output, now=NOW)
    repository = CategoryRepository(output)
    digest = next(entry["digest"] for entry in manifest["categories"] if entry["id"] == "games")
    assert repository.manifest() == manifest
    assert parse_category_file(repository.file("games", digest))
    assert repository.file("games", "0" * 64) is None
    assert repository.file("../manifest", digest) is None
    assert CategoryRepository(tmp_path / "missing").manifest() == {"version": None, "attribution": "", "categories": []}


def test_routes_require_a_registered_device(tmp_path):
    output = tmp_path / "categories"
    manifest = build_categories(ut1(tmp_path), output, now=NOW)
    client = TestClient(create_app(EmsService(require_invitation=False), category_dir=output))
    enrolled = client.post("/fct/api/public/v1/register/", json={"devid": "pc"}).json()
    auth = {"Authorization": f"Bearer {enrolled['device_token']}"}
    query = {"client_id": enrolled["client_id"]}
    assert client.get("/fct/api/public/v1/categories/", params=query).status_code == 401
    served = client.get("/fct/api/public/v1/categories/", params=query, headers=auth)
    assert served.status_code == 200 and served.json() == manifest
    digest = next(entry["digest"] for entry in manifest["categories"] if entry["id"] == "games")
    blob = client.get("/fct/api/public/v1/categories/file/", params={**query, "id": "games", "digest": digest}, headers=auth)
    assert blob.status_code == 200 and blob.headers["content-type"] == "application/octet-stream"
    assert hashlib.sha256(blob.content).hexdigest() == digest
    for bad in ({"id": "games", "digest": "0" * 64}, {"id": "nope", "digest": digest}, {"id": "games", "digest": "short"}):
        assert client.get("/fct/api/public/v1/categories/file/", params={**query, **bad}, headers=auth).status_code in (404, 422)
