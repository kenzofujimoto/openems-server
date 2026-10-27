"""Publication health distinguishes missing data from a verified empty or stale catalog."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from app.categories import CategoryRepository, build_categories
from tests.test_update_categories import archive
from tools.update_categories import extract_lists
from tools.update_categories import update as update_archive

NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)


def publication(tmp_path, *, now=NOW, domains="games.example\n"):
    source = tmp_path / "source" / "games"
    source.mkdir(parents=True)
    (source / "domains").write_text(domains, encoding="utf-8")
    output = tmp_path / "published"
    build_categories(source.parent, output, now=now)
    return CategoryRepository(output)


def test_missing_catalog_is_not_a_classified_empty_catalog(tmp_path):
    repository = CategoryRepository(tmp_path / "missing")
    health = repository.health(now=NOW)
    assert health["status"] == "missing"
    assert health["published_at"] is None and health["age_seconds"] is None
    assert health["source"]["id"] == "ut1"
    assert repository.manifest() == {"version": None, "attribution": "", "categories": []}


def test_current_publication_has_age_and_catalog_identity(tmp_path):
    repository = publication(tmp_path, now=NOW - timedelta(hours=2))
    health = repository.health(now=NOW)
    assert health["status"] == "current" and health["stale"] is False
    assert health["age_seconds"] == 7200
    assert health["published_at"] == "2026-10-27T10:00:00Z"
    assert health["max_age_hours"] == 48
    assert health["taxonomy_version"].startswith("openems-ut1-")
    assert health["source"]["homepage"] == "https://dsi.ut-capitole.fr/blacklists/"


def test_stale_publication_remains_available(tmp_path):
    repository = publication(tmp_path, now=NOW - timedelta(hours=49))
    before = repository.manifest()
    health = repository.health(now=NOW)
    assert health["status"] == "stale" and health["stale"] is True
    assert repository.manifest() == before


def test_published_empty_list_is_distinct_from_missing(tmp_path):
    repository = publication(tmp_path, domains="# no valid domains\n")
    health = repository.health(now=NOW)
    assert health["status"] == "empty"
    assert health["published_at"] is not None


@pytest.mark.parametrize("content", ["{", "[]", '{"version":"yesterday","categories":[]}',
    '{"version":"2026-10-27T12:00:00Z","categories":"invalid"}'])
def test_invalid_manifest_is_reported_without_exposing_file_content(tmp_path, content):
    (tmp_path / "manifest.json").write_text(content, encoding="utf-8")
    health = CategoryRepository(tmp_path).health(now=NOW)
    assert health["status"] == "invalid"
    assert health["error"] == "invalid_publication"
    assert "yesterday" not in json.dumps(health)


def test_future_publication_does_not_claim_current_data(tmp_path):
    repository = publication(tmp_path, now=NOW + timedelta(hours=2))
    assert repository.health(now=NOW)["status"] == "invalid"


def test_missing_attribution_is_invalid_publication(tmp_path):
    repository = publication(tmp_path)
    manifest = repository.manifest()
    del manifest["attribution"]
    (tmp_path / "published/manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert repository.health(now=NOW)["status"] == "invalid"


def test_invalid_health_parameters_are_refused(tmp_path):
    repository = CategoryRepository(tmp_path)
    with pytest.raises(ValueError):
        repository.health(now=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError):
        repository.health(now=NOW, max_age_hours=0)


def test_official_hyphenated_ut1_list_names_are_extracted(tmp_path):
    bundle = archive(tmp_path, {
        "blacklists/audio-video/domains": b"video.example\n",
        "blacklists/residential-proxies/domains": b"proxy.example\n",
    })
    extracted = extract_lists(bundle, tmp_path / "work")
    assert (extracted / "audio-video/domains").read_text() == "video.example\n"
    assert (extracted / "residential-proxies/domains").read_text() == "proxy.example\n"


@pytest.mark.parametrize("field,value", [("label", None), ("group", None), ("label", ""), ("group", [])])
def test_invalid_display_metadata_does_not_break_the_panel(tmp_path, field, value):
    repository = publication(tmp_path)
    manifest_path = tmp_path / "published/manifest.json"
    manifest = repository.manifest()
    manifest["categories"][0][field] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert repository.health(now=NOW)["status"] == "invalid"


def test_archive_without_supported_lists_preserves_last_publication(tmp_path):
    repository = publication(tmp_path)
    before = repository.manifest()
    before_files = {path.name: path.read_bytes() for path in (tmp_path / "published").glob("*.bin")}
    bundle = archive(tmp_path, {"blacklists/unknown/domains": b"unknown.example\n"})
    with pytest.raises(ValueError, match="supported category"):
        update_archive(bundle, tmp_path / "published", tmp_path / "refresh")
    assert repository.manifest() == before
    assert {path.name: path.read_bytes() for path in (tmp_path / "published").glob("*.bin")} == before_files
