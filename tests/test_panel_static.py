"""The React panel is served as a single-page app under /panel/."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api import create_app


@pytest.fixture
def panel_dir(tmp_path):
    dist = tmp_path / "panel_dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log('panel')", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("top-secret", encoding="utf-8")
    return dist


def test_panel_serves_index_assets_and_client_routes(panel_dir):
    with TestClient(create_app(panel_dir=panel_dir)) as client:
        index = client.get("/panel/")
        assert index.status_code == 200 and "id=root" in index.text
        assert index.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in index.headers["content-security-policy"]
        assert client.get("/panel/endpoints").text == index.text
        asset = client.get("/panel/assets/app.js")
        assert asset.status_code == 200 and "panel" in asset.text
        assert client.get("/panel", follow_redirects=False).headers["location"] == "/panel/"


@pytest.mark.parametrize("path", ["/panel/..%2fsecret.txt", "/panel/%2e%2e/secret.txt", "/panel/assets/..%2f..%2fsecret.txt"])
def test_panel_never_serves_files_outside_its_directory(panel_dir, path):
    with TestClient(create_app(panel_dir=panel_dir)) as client:
        assert "top-secret" not in client.get(path).text


def test_missing_build_is_reported_without_server_error(tmp_path):
    with TestClient(create_app(panel_dir=tmp_path / "absent")) as client:
        response = client.get("/panel/")
        assert response.status_code == 404
        assert response.json() == {"detail": "panel is not built"}


def test_root_opens_the_panel_when_built_and_the_console_otherwise(panel_dir, tmp_path):
    with TestClient(create_app(panel_dir=panel_dir)) as client:
        assert client.get("/", follow_redirects=False).headers["location"] == "/panel/"
    with TestClient(create_app(panel_dir=tmp_path / "absent")) as client:
        assert client.get("/", follow_redirects=False).headers["location"] == "/console/"
