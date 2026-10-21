"""Tests for the endpoint-channel traffic recorder."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from app.api import create_app  # noqa: E402
from app.service import EmsService  # noqa: E402


def _lines(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_records_endpoint_channel_body_and_still_serves(tmp_path) -> None:
    cap = tmp_path / "cap.jsonl"
    client = TestClient(create_app(EmsService(), record_path=str(cap)))

    resp = client.post("/fct/api/public/v1/register/", json={"devid": "DEV-1"})
    # the route still worked (body was replayed downstream)
    assert resp.status_code == 200 and resp.json()["client_id"]

    recs = _lines(cap)
    assert len(recs) == 1
    r = recs[0]
    assert r["method"] == "POST"
    assert r["path"] == "/fct/api/public/v1/register/"
    assert json.loads(r["body_text"]) == {"devid": "DEV-1"}


def test_does_not_record_management_api(tmp_path) -> None:
    cap = tmp_path / "cap.jsonl"
    client = TestClient(create_app(EmsService(), record_path=str(cap)))
    client.get("/api/v1/endpoints/count")  # not under /fct/api/
    assert not cap.exists() or _lines(cap) == []


def test_redacts_sensitive_headers(tmp_path) -> None:
    cap = tmp_path / "cap.jsonl"
    client = TestClient(create_app(EmsService(), record_path=str(cap)))
    client.post(
        "/fct/api/public/v1/register/",
        json={"devid": "DEV-1"},
        headers={"Authorization": "Bearer super-secret"},
    )
    r = _lines(cap)[0]
    assert r["headers"]["authorization"] == "<redacted>"
    assert "super-secret" not in json.dumps(r)
