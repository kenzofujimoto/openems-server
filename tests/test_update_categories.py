"""Daily category update: UT1 archive download, safe extraction and the compose job."""

from __future__ import annotations

import io
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from tools.update_categories import (
    extract_lists,
    fetch_archive,
    run_periodically,
    update,
)

ROOT = Path(__file__).resolve().parent.parent


def archive(tmp_path: Path, members: dict[str, bytes], symlink: str | None = None) -> Path:
    path = tmp_path / "blacklists.tar.gz"
    with tarfile.open(path, "w:gz") as bundle:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))
        if symlink:
            link = tarfile.TarInfo(symlink)
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            bundle.addfile(link)
    return path


UT1 = {
    "blacklists/games/domains": b"steampowered.com\nsteamcommunity.com\n",
    "blacklists/games/urls": b"steampowered.com/store\n",
    "blacklists/social_networks/domains": b"facebook.com\n",
    "blacklists/README": b"readme\n",
}


def test_archive_lists_are_extracted_and_published(tmp_path):
    lists = extract_lists(archive(tmp_path, UT1), tmp_path / "work")
    assert sorted(path.relative_to(lists).as_posix() for path in lists.rglob("*") if path.is_file()) == [
        "games/domains", "social_networks/domains"]
    manifest = update(archive(tmp_path, UT1), tmp_path / "published", tmp_path / "work2")
    assert {entry["id"] for entry in manifest["categories"]} == {"games", "social"}
    assert (tmp_path / "published" / "manifest.json").exists()


@pytest.mark.parametrize("name", ["blacklists/../../evil/domains", "/blacklists/games/domains",
                                  "blacklists/ga..mes/domains", "blacklists\\games\\domains"])
def test_paths_outside_the_list_tree_are_refused(tmp_path, name):
    with pytest.raises(ValueError):
        extract_lists(archive(tmp_path, {name: b"x.com\n"}), tmp_path / "work")
    assert not (tmp_path / "evil").exists()


def test_links_and_oversized_archives_are_refused(tmp_path):
    with pytest.raises(ValueError):
        extract_lists(archive(tmp_path, {}, symlink="blacklists/games/domains"), tmp_path / "work")
    with pytest.raises(ValueError):
        extract_lists(archive(tmp_path, UT1), tmp_path / "small", max_bytes=10)


@pytest.mark.parametrize("url", ["http://example.org/blacklists.tar.gz", "file:///etc/passwd", "ftp://x/y", ""])
def test_downloads_require_https(tmp_path, url):
    with pytest.raises(ValueError):
        fetch_archive(url, tmp_path / "download.tar.gz")


def test_periodic_job_survives_failures():
    calls, sleeps = [], []

    def job():
        calls.append(len(calls))
        if len(calls) == 1:
            raise OSError("mirror unreachable")

    run_periodically(job, 3600, sleep=sleeps.append, rounds=3)
    assert calls == [0, 1, 2] and sleeps == [3600, 3600]


def test_cli_refuses_a_plain_http_url(tmp_path):
    result = subprocess.run([sys.executable, str(ROOT / "tools" / "update_categories.py"), "--url",
                             "http://example.org/b.tar.gz", str(tmp_path / "out")],
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0 and "https" in result.stderr


def test_image_and_compose_ship_the_daily_job():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    # app.categories imports agent.categories: the image must ship it or the server cannot start.
    assert ("COPY agent ./agent" in dockerfile
            or "COPY agent/categories.py ./agent/categories.py" in dockerfile)
    assert "COPY tools/update_categories.py ./tools/update_categories.py" in dockerfile
    assert "chown 10001:10001 /var/lib/openems/categories" in dockerfile
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    job = compose.split("\n  categories:\n", 1)[1].split("\n  server:\n", 1)[0]
    assert 'profiles: ["categories"]' in job, "opt-in until the UT1 address and license are confirmed"
    # Compose interpolates every service, profiles included: an empty default keeps "up" working
    # without the job, and the tool itself refuses an empty or non-HTTPS URL.
    assert '"${OPENEMS_UT1_URL:-}"' in job and "--every-hours" in job and "read_only: true" in job
    assert "categories:/var/lib/openems/categories\n" in job
    server = compose.split("\n  server:\n", 1)[1]
    assert "OPENEMS_CATEGORIES_DIR: /var/lib/openems/categories" in server
    assert "categories:/var/lib/openems/categories:ro" in server
