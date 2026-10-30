"""Application catalog refresh: winget index package extraction and the compose job."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from tests.test_app_catalog import winget_index
from tools.update_app_catalog import extract_index, update


def package(tmp_path: Path, members: dict[str, bytes]) -> Path:
    path = tmp_path / "source2.msix"
    with zipfile.ZipFile(path, "w") as bundle:
        for name, data in members.items():
            bundle.writestr(name, data)
    return path


def test_update_extracts_only_the_public_index_and_publishes_the_catalog(tmp_path):
    index = winget_index(tmp_path / "built.db").read_bytes()
    msix = package(tmp_path, {"AppxManifest.xml": b"<x/>", "Public/index.db": index})
    manifest = update(msix, tmp_path / "out", tmp_path / "work")
    assert {app["id"] for app in manifest["apps"]} >= {"Valve.Steam", "AnyDeskSoftwareGmbH.AnyDesk"}
    assert json.loads((tmp_path / "out" / "app-catalog.json").read_text(encoding="utf-8"))["version"] == manifest["version"]


@pytest.mark.parametrize("members,message", [
    ({"AppxManifest.xml": b"<x/>"}, "Public/index.db"),
    ({"Public/index.db": b"x" * 64, "../evil.db": b"x"}, "unsafe"),
])
def test_unexpected_packages_are_refused(tmp_path, members, message):
    with pytest.raises(ValueError, match=message):
        extract_index(package(tmp_path, members), tmp_path / "work")


def test_an_oversized_index_is_refused_before_extraction(tmp_path):
    msix = package(tmp_path, {"Public/index.db": b"x" * 2048})
    with pytest.raises(ValueError, match="larger than"):
        extract_index(msix, tmp_path / "work", max_bytes=1024)
    assert not (tmp_path / "work" / "index.db").exists()


def test_compose_runs_the_daily_catalog_job_in_its_own_profile():
    compose = (Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text(encoding="utf-8")
    assert "tools/update_app_catalog.py" in compose and "app-catalog:/var/lib/openems/app-catalog" in compose
    assert "OPENEMS_APP_CATALOG_DIR: /var/lib/openems/app-catalog" in compose
